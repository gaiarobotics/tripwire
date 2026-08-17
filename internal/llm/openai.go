package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// openAIRequest is the /chat/completions body, kept to the fields every
// OpenAI-compatible server accepts.
type openAIRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens,omitempty"`
	Messages  []openAIMessage `json:"messages"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
			Refusal string `json:"refusal"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *Client) generateOpenAI(ctx context.Context, system, user string) ([]byte, error) {
	reqBody := openAIRequest{
		Model:     c.opts.Model,
		MaxTokens: c.opts.MaxTokens,
		Messages: []openAIMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	}

	raw, err := c.post(ctx, c.endpoint(openAIDefaultURL), reqBody, func(h http.Header) {
		if key := strings.TrimSpace(c.opts.APIKey); key != "" {
			h.Set("Authorization", "Bearer "+key)
		}
	})
	if err != nil {
		return nil, err
	}

	var resp openAIResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("%s: %s", resp.Error.Type, resp.Error.Message)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("response contained no choices")
	}
	choice := resp.Choices[0]
	if r := strings.TrimSpace(choice.Message.Refusal); r != "" {
		return nil, fmt.Errorf("model declined the request: %s", r)
	}
	if choice.FinishReason == "length" {
		return nil, fmt.Errorf("response hit the token limit (%d); raise llm.max_tokens", c.opts.MaxTokens)
	}
	if strings.TrimSpace(choice.Message.Content) == "" {
		return nil, fmt.Errorf("response contained no content (finish_reason %q)", choice.FinishReason)
	}
	return []byte(choice.Message.Content), nil
}
