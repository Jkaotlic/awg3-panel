package keenetictune

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	restResponseLimit = 8 << 20
	mcpResponseLimit  = 256 << 10
	protocolVersion   = "2025-06-18"
)

type httpStatusError struct {
	code int
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("AWG Manager вернул HTTP %d", e.code)
}

func (r *Router) request(ctx context.Context, method, path string, query url.Values, token string, body []byte) (*http.Response, error) {
	target := r.base
	target.Path, target.RawQuery = path, query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("не удалось подготовить запрос AWG Manager")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if path == "/mcp" {
		req.Header.Set("Accept", "application/json, text/event-stream")
		if r.protocol != "" {
			req.Header.Set("MCP-Protocol-Version", r.protocol)
		}
		if r.session != "" {
			req.Header.Set("Mcp-Session-Id", r.session)
		}
	}
	res, err := r.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("не удалось связаться с AWG Manager")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		res.Body.Close()
		return nil, httpStatusError{code: res.StatusCode}
	}
	return res, nil
}

func (r *Router) rest(ctx context.Context, path string, query url.Values, out any) error {
	return r.restRequest(ctx, http.MethodGet, path, query, nil, out)
}

func (r *Router) restRequest(ctx context.Context, method, path string, query url.Values, payload []byte, out any) error {
	res, err := r.request(ctx, method, path, query, r.config.RESTToken, payload)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	var envelope struct {
		Success bool            `json:"success"`
		Data    json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, restResponseLimit)).Decode(&envelope); err != nil ||
		!envelope.Success || len(envelope.Data) == 0 || json.Unmarshal(envelope.Data, out) != nil {
		return errors.New("некорректный ответ REST AWG Manager")
	}
	return nil
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

func (r *Router) rpc(ctx context.Context, method string, params any, out any) error {
	if out != nil {
		r.sequence++
	}
	req := struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		ID      uint64 `json:"id,omitempty"`
		Params  any    `json:"params,omitempty"`
	}{JSONRPC: "2.0", Method: method, Params: params}
	if out != nil {
		req.ID = r.sequence
	}
	body, err := json.Marshal(req)
	if err != nil {
		return errors.New("не удалось подготовить вызов MCP AWG Manager")
	}
	res, err := r.request(ctx, http.MethodPost, "/mcp", nil, r.config.MCPToken, body)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if out == nil {
		if res.StatusCode != http.StatusAccepted && res.StatusCode != http.StatusNoContent {
			return errors.New("AWG Manager не подтвердил инициализацию MCP")
		}
		return nil
	}
	msg, err := readRPCResponse(res, req.ID)
	if err != nil {
		return err
	}
	if len(msg.Result) == 0 || len(msg.Error) != 0 || json.Unmarshal(msg.Result, out) != nil {
		return errors.New("AWG Manager отклонил вызов MCP")
	}
	if method == "initialize" {
		r.session = res.Header.Get("Mcp-Session-Id")
		if r.session != "" && !validToken(r.session) {
			r.session = ""
			return errors.New("AWG Manager вернул неверный идентификатор сеанса MCP")
		}
	}
	return nil
}

func readRPCResponse(res *http.Response, id uint64) (rpcResponse, error) {
	var response rpcResponse
	body := io.LimitReader(res.Body, mcpResponseLimit)
	if !strings.HasPrefix(strings.ToLower(res.Header.Get("Content-Type")), "text/event-stream") {
		if json.NewDecoder(body).Decode(&response) == nil && response.JSONRPC == "2.0" && response.ID == id {
			return response, nil
		}
		return rpcResponse{}, errors.New("некорректный ответ MCP AWG Manager")
	}
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 4096), mcpResponseLimit)
	var event strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			event.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			event.WriteByte('\n')
		case line == "" && event.Len() != 0:
			response = rpcResponse{}
			if json.Unmarshal([]byte(event.String()), &response) == nil &&
				response.JSONRPC == "2.0" && response.ID == id {
				return response, nil
			}
			event.Reset()
		}
	}
	if event.Len() != 0 {
		response = rpcResponse{}
		if json.Unmarshal([]byte(event.String()), &response) == nil &&
			response.JSONRPC == "2.0" && response.ID == id {
			return response, nil
		}
	}
	return rpcResponse{}, errors.New("AWG Manager не вернул результат MCP")
}

func (r *Router) ensureMCP(ctx context.Context) error {
	if r.protocol != "" {
		return nil
	}
	var result struct {
		Version string `json:"protocolVersion"`
	}
	if err := r.rpc(ctx, "initialize", map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]string{"name": "awg3panel", "version": "1"},
	}, &result); err != nil {
		return err
	}
	if result.Version != protocolVersion {
		r.session = ""
		return errors.New("AWG Manager не согласовал версию MCP")
	}
	r.protocol = result.Version
	if err := r.rpc(ctx, "notifications/initialized", nil, nil); err != nil {
		r.protocol, r.session = "", ""
		return err
	}
	return nil
}

func (r *Router) call(ctx context.Context, tool string, arguments any, out any) error {
	reused := r.protocol != ""
	if err := r.ensureMCP(ctx); err != nil {
		return err
	}
	var result struct {
		IsError           bool            `json:"isError"`
		StructuredContent json.RawMessage `json:"structuredContent"`
	}
	params := map[string]any{"name": tool, "arguments": arguments}
	err := r.rpc(ctx, "tools/call", params, &result)
	if err != nil && ctx.Err() == nil {
		r.protocol, r.session = "", ""
		var statusErr httpStatusError
		if reused && errors.As(err, &statusErr) &&
			(statusErr.code == http.StatusNotFound || statusErr.code == http.StatusBadRequest) {
			if initErr := r.ensureMCP(ctx); initErr != nil {
				return initErr
			}
			result = struct {
				IsError           bool            `json:"isError"`
				StructuredContent json.RawMessage `json:"structuredContent"`
			}{}
			err = r.rpc(ctx, "tools/call", params, &result)
			if err != nil && ctx.Err() == nil {
				r.protocol, r.session = "", ""
			}
		}
	}
	if err != nil {
		return err
	}
	if result.IsError {
		return errors.New("AWG Manager не выполнил операцию MCP")
	}
	if out != nil && (len(result.StructuredContent) == 0 || json.Unmarshal(result.StructuredContent, out) != nil) {
		return errors.New("AWG Manager не вернул данные операции MCP")
	}
	return nil
}

func (r *Router) control(ctx context.Context, action string) error {
	var result struct {
		TunnelID string `json:"tunnelId"`
		Action   string `json:"action"`
	}
	if err := r.call(ctx, "control_tunnel", map[string]string{
		"tunnelId": r.config.TunnelID, "action": action,
	}, &result); err != nil {
		return err
	}
	if result.TunnelID != r.config.TunnelID || result.Action != action {
		return errors.New("AWG Manager не подтвердил целевой туннель и операцию")
	}
	return nil
}
