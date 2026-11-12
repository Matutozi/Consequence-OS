package hook

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/matutozi/consequence-os/pkg/verify"
)

// object is a JSON object that keeps its keys in order, so rewriting
// someone's settings file changes only what we add.
type object struct {
	keys []string
	vals map[string]any
}

func newObject() *object { return &object{vals: map[string]any{}} }

func (o *object) get(k string) (any, bool) { v, ok := o.vals[k]; return v, ok }

func (o *object) set(k string, v any) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// parseOrdered reads JSON, keeping object keys in order and numbers as
// written. Duplicate keys are refused rather than guessed at.
func parseOrdered(data []byte) (any, error) {
	if err := verify.CheckUnambiguous(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := readValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value")
	}
	return v, nil
}

func readValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			o := newObject()
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				v, err := readValue(dec)
				if err != nil {
					return nil, err
				}
				o.set(k.(string), v)
			}
			_, err := dec.Token() // }
			return o, err
		case '[':
			list := []any{}
			for dec.More() {
				v, err := readValue(dec)
				if err != nil {
					return nil, err
				}
				list = append(list, v)
			}
			_, err := dec.Token() // ]
			return list, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	default:
		return t, nil // string, json.Number, bool or nil
	}
}

// formatOrdered writes v as JSON indented by two spaces, as Claude Code
// writes its own settings, without escaping < > & in strings.
func formatOrdered(v any) ([]byte, error) {
	var compact bytes.Buffer
	if err := writeOrdered(&compact, v); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, compact.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func writeOrdered(buf *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case *object:
		buf.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeOrdered(buf, k); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := writeOrdered(buf, x.vals[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeOrdered(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	default:
		enc := json.NewEncoder(buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(x); err != nil {
			return err
		}
		buf.Truncate(buf.Len() - 1) // Encode's newline
	}
	return nil
}

// hookEntry is the hooks.PreToolUse entry that runs command on every tool
// call. onFailure "block" makes Claude Code block the call when the hook
// can't run at all, a case ConsequenceOS can't catch itself.
func hookEntry(command string) *object {
	h := newObject()
	h.set("type", "command")
	h.set("command", command)
	h.set("timeout", json.Number("30"))
	h.set("onFailure", "block")
	e := newObject()
	e.set("matcher", "*")
	e.set("hooks", []any{h})
	return e
}

// addHook returns settings with the hook entry added, or added=false when
// a ConsequenceOS Claude Code hook is already there. Everything else in
// the file is kept as it was.
func addHook(settings []byte, command string) (updated []byte, added bool, err error) {
	root := newObject()
	if len(bytes.TrimSpace(settings)) > 0 {
		v, err := parseOrdered(settings)
		if err != nil {
			return nil, false, fmt.Errorf("it isn't valid JSON: %w", err)
		}
		var ok bool
		if root, ok = v.(*object); !ok {
			return nil, false, errors.New("it isn't a JSON object")
		}
	}
	hooks := newObject()
	if v, ok := root.get("hooks"); ok {
		if hooks, ok = v.(*object); !ok {
			return nil, false, errors.New(`its "hooks" isn't an object`)
		}
	}
	var pre []any
	if v, ok := hooks.get("PreToolUse"); ok {
		if pre, ok = v.([]any); !ok {
			return nil, false, errors.New(`its "hooks.PreToolUse" isn't a list`)
		}
	}
	if hasOurHook(pre) {
		return settings, false, nil
	}
	hooks.set("PreToolUse", append(pre, hookEntry(command)))
	root.set("hooks", hooks)
	out, err := formatOrdered(root)
	return out, true, err
}

// hasOurHook reports whether a PreToolUse entry already runs the Claude
// Code hook of consequenced.
func hasOurHook(pre []any) bool {
	for _, entry := range pre {
		e, ok := entry.(*object)
		if !ok {
			continue
		}
		list, _ := e.vals["hooks"].([]any)
		for _, h := range list {
			ho, ok := h.(*object)
			if !ok {
				continue
			}
			cmd, _ := ho.vals["command"].(string)
			if strings.Contains(cmd, "consequenced") && (strings.Contains(cmd, "-hook claude-code") || strings.Contains(cmd, "-hook=claude-code")) {
				return true
			}
		}
	}
	return false
}

// writeFileAtomic writes data to path through a temporary file renamed
// over it, keeping an existing file's mode, so a crash never leaves half a
// settings file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
