// Package github publishes gatekeeper results to a pull request as a Check Run
// and a comment, using the token GitHub Actions provides. When no token is
// configured the client degrades to a no-op so the CLI still works locally.
package github

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ikoojo/agent-pr-gatekeeper/internal/model"
)

// Client talks to the GitHub REST API.
type Client struct {
	token   string
	repo    string // owner/repo
	apiBase string
	http    *http.Client
}

// FromEnv builds a Client from the standard GitHub Actions environment. It
// returns (nil, nil) when no token is present so callers can treat publishing
// as optional.
func FromEnv() (*Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	repo := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repo == "" {
		return nil, nil
	}
	base := os.Getenv("GITHUB_API_URL")
	if base == "" {
		base = "https://api.github.com"
	}
	return &Client{
		token:   token,
		repo:    repo,
		apiBase: base,
		http:    &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Publish posts a Check Run for the head SHA and, when prNumber > 0, a PR
// comment with the same Markdown body.
func (c *Client) Publish(headSHA string, prNumber int, verdict model.Verdict, markdown string) error {
	if headSHA != "" {
		if err := c.createCheckRun(headSHA, verdict, markdown); err != nil {
			return fmt.Errorf("create check run: %w", err)
		}
	}
	if prNumber > 0 {
		if err := c.createComment(prNumber, markdown); err != nil {
			return fmt.Errorf("create comment: %w", err)
		}
	}
	return nil
}

func (c *Client) createCheckRun(headSHA string, verdict model.Verdict, markdown string) error {
	body := map[string]any{
		"name":       "agent-pr-gatekeeper",
		"head_sha":   headSHA,
		"status":     "completed",
		"conclusion": conclusion(verdict.Decision),
		"output": map[string]any{
			"title":   checkTitle(verdict),
			"summary": markdown,
		},
	}
	return c.post(fmt.Sprintf("/repos/%s/check-runs", c.repo), body)
}

func (c *Client) createComment(prNumber int, markdown string) error {
	body := map[string]any{"body": markdown}
	return c.post(fmt.Sprintf("/repos/%s/issues/%d/comments", c.repo, prNumber), body)
}

func (c *Client) post(path string, body any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.apiBase+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("github api %s: %s", resp.Status, string(msg))
	}
	return nil
}

// conclusion maps a decision to a GitHub Check Run conclusion.
func conclusion(d model.Decision) string {
	switch d {
	case model.DecisionBlock:
		return "failure"
	case model.DecisionWarn:
		return "neutral"
	default:
		return "success"
	}
}

func checkTitle(v model.Verdict) string {
	return fmt.Sprintf("%s (%d finding(s), profile %s)",
		string(v.Decision), len(v.Findings), v.Profile)
}

// PRNumberFromEnv extracts the pull request number from the GitHub event
// payload path in GITHUB_EVENT_PATH. It returns 0 when unavailable.
func PRNumberFromEnv() int {
	path := os.Getenv("GITHUB_EVENT_PATH")
	if path == "" {
		return 0
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var event struct {
		Number      int `json:"number"`
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(raw, &event); err != nil {
		return 0
	}
	if event.PullRequest.Number > 0 {
		return event.PullRequest.Number
	}
	return event.Number
}

// EnvInt reads an integer environment variable, returning fallback when unset
// or invalid.
func EnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
