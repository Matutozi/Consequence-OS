package main

import (
	"fmt"
	"sync/atomic"
)

// tool is one fake tool the mock server exposes.
type tool struct {
	Name        string
	Title       string
	Description string
	InputSchema map[string]any
	// Call returns the text to send back and whether it is a tool execution error.
	Call func(args map[string]any) (text string, isError bool)
}

// listing is the shape of a tool inside a tools/list result.
func (t tool) listing() map[string]any {
	return map[string]any{
		"name":        t.Name,
		"title":       t.Title,
		"description": t.Description,
		"inputSchema": t.InputSchema,
	}
}

var refundCounter atomic.Int64 // atomic because requests run on separate goroutines

var notes = map[string]string{
	"welcome":       "Welcome to the mock notes store.",
	"refund-policy": "Refunds over $50 need a manager's approval.",
}

// defaultTools returns the tools in a fixed order; the spec says listings
// SHOULD be deterministic, which a Go map would not be.
func defaultTools() []tool {
	return []tool{
		{
			Name:        "notes.read",
			Title:       "Read note",
			Description: "Read a note by its ID.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"note_id": map[string]any{"type": "string", "description": "ID of the note, e.g. welcome"},
				},
				"required": []string{"note_id"},
			},
			Call: readNote,
		},
		{
			Name:        "payments.refund",
			Title:       "Refund payment",
			Description: "Refund part or all of a charge. Fake: no money moves.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"charge_id": map[string]any{"type": "string"},
					"amount":    map[string]any{"type": "number", "exclusiveMinimum": 0},
					"currency":  map[string]any{"type": "string", "default": "USD"},
					"reason":    map[string]any{"type": "string"},
				},
				"required": []string{"charge_id", "amount"},
			},
			Call: refund,
		},
	}
}

func readNote(args map[string]any) (string, bool) {
	id, _ := args["note_id"].(string) // the ", _" form returns "" instead of panicking on a bad type
	text, ok := notes[id]
	if !ok {
		return fmt.Sprintf("No note with ID %q.", id), true
	}
	return text, false
}

func refund(args map[string]any) (string, bool) {
	chargeID, _ := args["charge_id"].(string)
	amount, _ := args["amount"].(float64) // JSON numbers decode to float64
	currency, _ := args["currency"].(string)
	if currency == "" {
		currency = "USD"
	}
	if chargeID == "" {
		return "charge_id is required.", true
	}
	if amount <= 0 {
		return "amount must be a positive number.", true
	}
	id := refundCounter.Add(1)
	return fmt.Sprintf("Refunded %.2f %s on charge %s (refund re_mock_%04d).", amount, currency, chargeID, id), false
}
