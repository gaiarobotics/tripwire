package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// anthropicRequest is the Messages API body.
//
// Note what is absent: no `thinking` and no `temperature`. Thinking is left at
// the model's default (current models reject a fixed token budget outright),
// and sampling parameters are rejected by current Claude models — the prompt
// does the steering.
type anthropicRequest struct {
	Model        string             `json:"model"`
	MaxTokens    int                `json:"max_tokens"`
	System       string             `json:"system,omitempty"`
	Messages     []anthropicMessage `json:"messages"`
	OutputConfig *outputConfig      `json:"output_config,omitempty"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// outputConfig carries the effort hint. It is omitted unless configured,
// because not every Claude model accepts effort.
type outputConfig struct {
	Effort string `json:"effort,omitempty"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason  string `json:"stop_reason"`
	StopDetails *struct {
		Category    string `json:"category"`
		Explanation string `json:"explanation"`
	} `json:"stop_details"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) generateAnthropic(ctx context.Context, system, user string) ([]byte, error) {
	reqBody := anthropicRequest{
		Model:     c.opts.Model,
		MaxTokens: c.opts.MaxTokens,
		System:    system,
		Messages:  []anthropicMessage{{Role: "user", Content: user}},
	}
	if e := strings.TrimSpace(c.opts.Effort); e != "" {
		reqBody.OutputConfig = &outputConfig{Effort: e}
	}

	raw, err := c.post(ctx, c.endpoint(anthropicDefaultURL), reqBody, func(h http.Header) {
		h.Set("x-api-key", c.opts.APIKey)
		h.Set("anthropic-version", anthropicVersion)
	})
	if err != nil {
		return nil, err
	}

	var resp anthropicResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("anthropic %s: %s", resp.Error.Type, resp.Error.Message)
	}
	// A refusal is a successful HTTP 200 with an empty or partial content array,
	// so it has to be checked before reading content.
	if resp.StopReason == "refusal" {
		category := "unspecified"
		if resp.StopDetails != nil && resp.StopDetails.Category != "" {
			category = resp.StopDetails.Category
		}
		return nil, fmt.Errorf("model declined the request (category %s)", category)
	}
	if resp.StopReason == "max_tokens" {
		return nil, fmt.Errorf("response hit max_tokens (%d); raise llm.max_tokens", c.opts.MaxTokens)
	}

	var text strings.Builder
	for _, block := range resp.Content {
		if block.Type == "text" {
			text.WriteString(block.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" {
		return nil, fmt.Errorf("anthropic response contained no text (stop_reason %q)", resp.StopReason)
	}
	return []byte(text.String()), nil
}

// post sends a JSON body and returns the raw response, turning a non-2xx into an
// error that quotes the body — API errors are the thing an operator debugging
// `tripwire regenerate` most needs to see.
func (c *Client) post(ctx context.Context, url string, body any, setHeaders func(http.Header)) ([]byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	setHeaders(req.Header)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned %d: %s", url, resp.StatusCode, snippet(raw))
	}
	return raw, nil
}

func snippet(raw []byte) string {
	const max = 400
	s := strings.TrimSpace(string(raw))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
