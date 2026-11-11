package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

// The notes are also served as resources, note://<id>, so resource rules
// in the proxy have something to read.
const noteScheme = "note://"

// codeResourceNotFound is the MCP error for an unknown resource URI.
const codeResourceNotFound = -32002

func listResources() reply {
	ids := make([]string, 0, len(notes))
	for id := range notes {
		ids = append(ids, id)
	}
	sort.Strings(ids) // deterministic, like the tool listing
	list := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		list = append(list, map[string]any{"uri": noteScheme + id, "name": id, "mimeType": "text/plain"})
	}
	return ok(map[string]any{"resources": list})
}

func readResource(params json.RawMessage) reply {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.URI == "" {
		return fail(http.StatusBadRequest, codeInvalidParams, "resources/read needs params.uri")
	}
	id, isNote := strings.CutPrefix(p.URI, noteScheme)
	text, found := notes[id]
	if !isNote || !found {
		rep := fail(http.StatusOK, codeResourceNotFound, "Resource not found")
		rep.err.Data = map[string]any{"uri": p.URI}
		return rep
	}
	return ok(map[string]any{"contents": []map[string]any{{"uri": p.URI, "mimeType": "text/plain", "text": text}}})
}
