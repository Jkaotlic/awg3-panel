//go:build !readonly

package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

var errJSONObject = errors.New("ожидается ровно один объект JSON без неизвестных полей")

func decodeJSONObject(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		if err != nil {
			return err
		}
		return errJSONObject
	}
	if raw[0] != '{' {
		return errJSONObject
	}
	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	return strict.Decode(dst)
}

func writeJSONRequestError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, errors.New("тело запроса слишком большое"))
		return
	}
	writeError(w, http.StatusBadRequest, errJSONObject)
}
