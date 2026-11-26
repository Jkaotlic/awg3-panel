//go:build readonly

package web

import "net/http"

type junkTuneHTTP struct{}

func (s *Server) junkTuneBinding() (string, string) { return "", "" }
func (s *Server) registerJunkTune(*http.ServeMux)   {}
func (s *Server) stopJunkTune() <-chan struct{}     { return nil }
