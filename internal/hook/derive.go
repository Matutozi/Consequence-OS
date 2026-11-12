package hook

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The arguments the hook adds to a call before the policy sees it. Each
// replaces anything the agent sent under the same name, in any letter case.
const (
	// ArgProgram is a shell command's first word, after any VAR=value
	// assignments: "git" for "GIT_PAGER=cat git log".
	ArgProgram = "program"
	// ArgCompound is true when a shell command could run more than one
	// program, or redirect: it holds ; & | ` $( < > ( ) or a line break.
	ArgCompound = "compound"
	// ArgInProject is true when a file tool's path, with symlinks
	// resolved, is inside the project directory.
	ArgInProject = "in_project"
	// ArgViaSymlink is true when any part of a file tool's path that
	// exists is a symlink. The link could be swapped between the check
	// and the write, so the starter policy asks for writes through one.
	ArgViaSymlink = "via_symlink"
)

// derived lists every name the hook sets, for removing the agent's copies.
var derived = []string{ArgProgram, ArgCompound, ArgInProject, ArgViaSymlink}

// shellTools take a command in "command".
var shellTools = map[string]bool{"Bash": true, "PowerShell": true}

// pathTools maps each file tool to the argument holding its path. A tool
// whose path is optional (Glob, Grep) works in the current directory
// without one.
var pathTools = map[string]struct {
	arg      string
	optional bool
}{
	"Read":         {arg: "file_path"},
	"Write":        {arg: "file_path"},
	"Edit":         {arg: "file_path"},
	"MultiEdit":    {arg: "file_path"},
	"NotebookEdit": {arg: "notebook_path"},
	"NotebookRead": {arg: "notebook_path"},
	"Glob":         {arg: "path", optional: true},
	"Grep":         {arg: "path", optional: true},
	"LS":           {arg: "path", optional: true},
}

// derive adds the derived arguments for one call to args, in place. cwd is
// where Claude Code is working; project is the project directory.
func derive(tool string, args map[string]any, cwd, project string) {
	for k := range args {
		for _, name := range derived {
			if strings.EqualFold(k, name) {
				delete(args, k)
			}
		}
	}
	if shellTools[tool] {
		cmd, _ := args["command"].(string)
		args[ArgProgram], args[ArgCompound] = shellFacts(cmd)
	}
	if t, ok := pathTools[tool]; ok {
		p, isText := args[t.arg].(string)
		switch {
		case isText && p != "":
		case t.optional && args[t.arg] == nil:
			p = cwd
		default:
			// No usable path: say nothing is known, so an allow rule
			// that needs in_project doesn't match and the call asks.
			args[ArgInProject], args[ArgViaSymlink] = false, true
			return
		}
		resolved, viaSymlink := resolvePath(p, cwd)
		if args[t.arg] != nil {
			args[t.arg] = resolved
		}
		args[ArgInProject] = within(resolved, resolveDir(project))
		args[ArgViaSymlink] = viaSymlink
	}
}

var assignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// shellFacts finds a command's program and whether it is compound. It
// reads text, not shell grammar: anything it isn't sure of counts as
// compound, so an allow rule that requires compound: false doesn't match.
func shellFacts(cmd string) (program string, compound bool) {
	compound = strings.ContainsAny(cmd, ";&|`<>()\n\r\x00")
	for _, word := range strings.Fields(cmd) {
		if !assignment.MatchString(word) {
			return word, compound
		}
	}
	return "", compound
}

// resolvePath makes p absolute against cwd, cleans it, and resolves
// symlinks in the part of it that exists, so "notes/../.env" and a link to
// .env both come out as the real .env. A path that doesn't exist yet (a new
// file) keeps its missing tail as written. viaSymlink says whether any
// existing part was a symlink; when that can't be told, it says yes.
func resolvePath(p, cwd string) (resolved string, viaSymlink bool) {
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	p = filepath.Clean(p)
	existing, rest := p, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return p, true // nothing exists, not even the root
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	real, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return p, true
	}
	return filepath.Join(real, rest), hasSymlink(existing)
}

// hasSymlink reports whether p, or any directory on the way to it, is a
// symlink. p must exist.
func hasSymlink(p string) bool {
	for {
		info, err := os.Lstat(p)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return true
		}
		parent := filepath.Dir(p)
		if parent == p {
			return false
		}
		p = parent
	}
}

// resolveDir resolves symlinks in a directory, so a project under a linked
// directory still compares equal to the paths inside it.
func resolveDir(dir string) string {
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		return real
	}
	return filepath.Clean(dir)
}

// within reports whether p is dir or inside it.
func within(p, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
