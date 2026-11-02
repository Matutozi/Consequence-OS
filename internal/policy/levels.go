package policy

import "fmt"

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

// Levels maps exact tool names to their consequence level.
type Levels map[string]Level

// For returns the level of a tool. Unknown tools are treated as irreversible.
func (l Levels) For(tool string) Level {
	if level, ok := l[tool]; ok {
		return level
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
