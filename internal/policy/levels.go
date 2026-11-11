package policy

import (
	"fmt"
	"strings"
)

// Level says how hard a tool's effects are to undo. Levels come only from our
// config; a tool's own annotations are never trusted.
type Level string

const (
	LevelRead         Level = "read"
	LevelReversible   Level = "reversible"
	LevelIrreversible Level = "irreversible"
)

// Valid reports whether l is one of the known levels.
func (l Level) Valid() bool {
	switch l {
	case LevelRead, LevelReversible, LevelIrreversible:
		return true
	}
	return false
}

// Resource reads and prompt fetches go past the policy under these names:
// "resource:" plus the URI, and "prompt:" plus the prompt's name. MCP tool
// names can't contain ":", so they can't collide with a real tool.
const (
	ResourcePrefix = "resource:"
	PromptPrefix   = "prompt:"
)

// IsRead reports whether name is a resource read or a prompt fetch rather
// than a tool call.
func IsRead(name string) bool {
	return strings.HasPrefix(name, ResourcePrefix) || strings.HasPrefix(name, PromptPrefix)
}

// Levels maps exact tool names to their consequence level.
type Levels map[string]Level

// For returns the level of a tool. Unknown tools are treated as
// irreversible. Unlisted resources and prompts are reads: they change
// nothing, so by default they're allowed, but still audited.
func (l Levels) For(tool string) Level {
	if level, ok := l[tool]; ok {
		return level
	}
	if IsRead(tool) {
		return LevelRead
	}
	return LevelIrreversible
}

// Validate checks that every configured level is known.
func (l Levels) Validate() error {
	for tool, level := range l {
		if !level.Valid() {
			return fmt.Errorf("tool %q: unknown level %q (want read, reversible or irreversible)", tool, level)
		}
	}
	return nil
}
