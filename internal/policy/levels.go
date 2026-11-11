package policy

import (
	"fmt"

	"github.com/matutozi/consequence-os/internal/consequence"
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
// "resource:" plus the URI, and "prompt:" plus the prompt's name. They're
// defined in package consequence, which also treats them as reads.
const (
	ResourcePrefix = consequence.ResourcePrefix
	PromptPrefix   = consequence.PromptPrefix
)

// IsRead reports whether name is a resource read or a prompt fetch rather
// than a tool call.
func IsRead(name string) bool { return consequence.IsRead(name) }

// Reversibility says how the consequence package names a level.
func (l Level) Reversibility() consequence.Reversibility {
	switch l {
	case LevelRead:
		return consequence.Read
	case LevelReversible:
		return consequence.Reversible
	}
	return consequence.None
}

// LevelOf is the level for a reversibility. Compensable counts as
// irreversible: the effect itself can't be undone.
func LevelOf(r consequence.Reversibility) Level {
	switch r {
	case consequence.Read:
		return LevelRead
	case consequence.Reversible:
		return LevelReversible
	}
	return LevelIrreversible
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
