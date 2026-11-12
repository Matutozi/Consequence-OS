package store

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matutozi/consequence-os/internal/toolpin"
)

// pinFor builds a pin with every field set, so a store that drops one
// shows up in a comparison.
func pinFor(server, tool string) toolpin.Pin {
	return toolpin.Pin{
		Server: server, Tool: tool, Hash: "sha256:aa", Definition: json.RawMessage(`{"description":"<b>a</b> & b","name":"` + tool + `"}`),
		PinnedAt: at, AcceptedBy: "local:ada",
		Seen: "sha256:bb", SeenDefinition: json.RawMessage(`{"name":"` + tool + `"}`), SeenAt: at.Add(time.Hour),
	}
}

func set(p toolpin.Pin) func(toolpin.Pin, bool) (toolpin.Pin, bool, error) {
	return func(toolpin.Pin, bool) (toolpin.Pin, bool, error) { return p, true, nil }
}

func TestToolPins(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		if _, ok, err := st.ToolPin(ctx, "s1", "a"); ok || err != nil {
			t.Fatalf("a pin before any was saved: ok=%v err=%v", ok, err)
		}
		for _, p := range []toolpin.Pin{pinFor("s2", "a"), pinFor("s1", "b"), pinFor("s1", "a")} {
			if _, err := st.UpdateToolPin(ctx, p.Server, p.Tool, set(p)); err != nil {
				t.Fatal(err)
			}
		}
		got, ok, err := st.ToolPin(ctx, "s1", "a")
		if err != nil || !ok || !reflect.DeepEqual(got, pinFor("s1", "a")) {
			t.Errorf("ToolPin =\n %+v, %v, %v\nwant %+v", got, ok, err, pinFor("s1", "a"))
		}
		// A pin with no change waiting keeps its empty fields empty.
		plain := toolpin.Pin{Server: "s1", Tool: "a", Hash: "sha256:cc", Definition: json.RawMessage(`{}`), PinnedAt: at}
		if _, err := st.UpdateToolPin(ctx, "s1", "a", set(plain)); err != nil {
			t.Fatal(err)
		}
		if got, _, _ := st.ToolPin(ctx, "s1", "a"); !reflect.DeepEqual(got, plain) {
			t.Errorf("after replacing:\n got %+v\nwant %+v", got, plain)
		}

		all, err := st.ListToolPins(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, p := range all {
			keys = append(keys, p.Server+"/"+p.Tool)
		}
		if strings.Join(keys, " ") != "s1/a s1/b s2/a" {
			t.Errorf("ListToolPins(\"\") = %v", keys)
		}
		if one, _ := st.ListToolPins(ctx, "s2"); len(one) != 1 || one[0].Tool != "a" {
			t.Errorf("ListToolPins(s2) = %+v", one)
		}

		// update sees the current pin, and save=false or an error changes nothing.
		boom := errors.New("boom")
		_, err = st.UpdateToolPin(ctx, "s1", "a", func(old toolpin.Pin, ok bool) (toolpin.Pin, bool, error) {
			if !ok || old.Hash != "sha256:cc" {
				t.Errorf("update saw %+v, ok=%v", old, ok)
			}
			return pinFor("s1", "a"), true, boom
		})
		if !errors.Is(err, boom) {
			t.Errorf("err = %v, want boom", err)
		}
		kept, err := st.UpdateToolPin(ctx, "s1", "a", func(old toolpin.Pin, _ bool) (toolpin.Pin, bool, error) {
			return pinFor("s1", "a"), false, nil
		})
		if err != nil || !reflect.DeepEqual(kept, plain) {
			t.Errorf("save=false returned %+v, %v; want the pin as it was", kept, err)
		}
		if got, _, _ := st.ToolPin(ctx, "s1", "a"); !reflect.DeepEqual(got, plain) {
			t.Errorf("an update that didn't save changed the pin: %+v", got)
		}
		if _, err := st.UpdateToolPin(ctx, "s9", "new", func(toolpin.Pin, bool) (toolpin.Pin, bool, error) {
			return toolpin.Pin{}, false, nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := st.ToolPin(ctx, "s9", "new"); ok {
			t.Error("an update that didn't save created a pin")
		}
		if _, err := st.UpdateToolPin(ctx, "s1", "a", set(pinFor("s1", "other"))); err == nil {
			t.Error("an update moved a pin to another tool")
		}
	})
}

// Concurrent updates of one pin, the first one included, run one at a
// time: each sees the last one's result.
func TestConcurrentToolPinUpdates(t *testing.T) {
	forEachStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		const n = 20
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := st.UpdateToolPin(ctx, "s", "counter", func(old toolpin.Pin, ok bool) (toolpin.Pin, bool, error) {
					next := toolpin.Pin{Server: "s", Tool: "counter", Hash: "1", Definition: json.RawMessage(`{}`), PinnedAt: at}
					if ok {
						next.Hash = old.Hash + "1"
					}
					return next, true, nil
				})
				if err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		if p, _, _ := st.ToolPin(ctx, "s", "counter"); len(p.Hash) != n {
			t.Errorf("%d updates counted, want %d: some ran on a stale pin", len(p.Hash), n)
		}
	})
}

func TestFileKeepsPinsThroughRestartAndCompaction(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st := openFile(t, dir)
	for _, p := range []toolpin.Pin{pinFor("s", "a"), pinFor("s", "b")} {
		if _, err := st.UpdateToolPin(ctx, p.Server, p.Tool, set(p)); err != nil {
			t.Fatal(err)
		}
	}
	accepted := toolpin.Pin{Server: "s", Tool: "a", Hash: "sha256:bb", Definition: json.RawMessage(`{"name":"a"}`), PinnedAt: at.Add(2 * time.Hour), AcceptedBy: "local:ada"}
	if _, err := st.UpdateToolPin(ctx, "s", "a", set(accepted)); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(journalOf(t, dir), `"op":"tool_pin"`); n != 3 {
		t.Errorf("%d tool_pin lines, want 3", n)
	}
	st.Close()

	st = openFile(t, dir)
	if got, _, _ := st.ToolPin(ctx, "s", "a"); !reflect.DeepEqual(got, accepted) {
		t.Errorf("after a restart:\n got %+v\nwant %+v", got, accepted)
	}
	st.mu.Lock()
	st.base = 0
	st.compact()
	st.mu.Unlock()
	if n := strings.Count(journalOf(t, dir), `"op":"tool_pin"`); n != 2 {
		t.Errorf("%d tool_pin lines after compaction, want one per pin", n)
	}
	st.Close()

	st = openFile(t, dir)
	if got, _, _ := st.ToolPin(ctx, "s", "a"); !reflect.DeepEqual(got, accepted) {
		t.Errorf("after compaction:\n got %+v\nwant %+v", got, accepted)
	}
	if got, _, _ := st.ToolPin(ctx, "s", "b"); !reflect.DeepEqual(got, pinFor("s", "b")) {
		t.Errorf("after compaction:\n got %+v\nwant %+v", got, pinFor("s", "b"))
	}
}
