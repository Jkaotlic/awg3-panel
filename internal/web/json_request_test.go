//go:build !readonly

package web_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestPatchRequiresOneJSONObject(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	for _, body := range []string{
		`{"name":"client","unknown":true}`,
		`{"overrides":{"unknown":true}}`,
		`{"name":"client"} {}`,
		"null",
		`{"name":"client"}` + strings.Repeat(" ", 16384),
	} {
		rec := doAuthed(t, h, http.MethodPatch, "/api/ifaces/awg3/peers/client", strings.NewReader(body))
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("expected request rejection, got %d", rec.Code)
		}
	}
}
