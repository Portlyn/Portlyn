package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"portlyn/internal/domain"
)

type WebhookStore interface {
	ActiveByEvent(ctx context.Context, action string) ([]domain.AuditWebhook, error)
	Update(ctx context.Context, item *domain.AuditWebhook) error
}

type WebhookDispatcher struct {
	store   WebhookStore
	client  *http.Client
	timeout time.Duration
}

func NewWebhookDispatcher(store WebhookStore) *WebhookDispatcher {
	return &WebhookDispatcher{
		store:   store,
		client:  &http.Client{Timeout: 5 * time.Second},
		timeout: 5 * time.Second,
	}
}

type webhookPayload struct {
	Event        string         `json:"event"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   *uint          `json:"resource_id,omitempty"`
	UserID       *uint          `json:"user_id,omitempty"`
	Timestamp    time.Time      `json:"timestamp"`
	Details      map[string]any `json:"details,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	StatusCode   int            `json:"status_code,omitempty"`
	Host         string         `json:"host,omitempty"`
	Path         string         `json:"path,omitempty"`
	Method       string         `json:"method,omitempty"`
	RemoteAddr   string         `json:"remote_addr,omitempty"`
}

func (d *WebhookDispatcher) Dispatch(ctx context.Context, entry domain.AuditLog, details map[string]any) {
	if d == nil || d.store == nil {
		return
	}
	hooks, err := d.store.ActiveByEvent(ctx, entry.Action)
	if err != nil || len(hooks) == 0 {
		return
	}
	payload := webhookPayload{
		Event:        entry.Action,
		Action:       entry.Action,
		ResourceType: entry.ResourceType,
		ResourceID:   entry.ResourceID,
		UserID:       entry.UserID,
		Timestamp:    entry.Timestamp,
		Details:      details,
		RequestID:    entry.RequestID,
		StatusCode:   entry.StatusCode,
		Host:         entry.Host,
		Path:         entry.Path,
		Method:       entry.Method,
		RemoteAddr:   entry.RemoteAddr,
	}
	for _, hook := range hooks {
		go d.fire(hook, payload)
	}
}

func (d *WebhookDispatcher) fire(hook domain.AuditWebhook, payload webhookPayload) {
	body, err := renderWebhookBody(hook.Format, payload)
	if err != nil {
		d.recordResult(hook, 0, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		d.recordResult(hook, 0, err.Error())
		return
	}
	req.Header.Set("Content-Type", contentTypeFor(hook.Format))
	req.Header.Set("User-Agent", "portlyn-webhook/1")
	if strings.TrimSpace(hook.SecretHashed) != "" {
		sig := signBody(hook.SecretHashed, body)
		req.Header.Set("X-Portlyn-Signature", sig)
	}
	resp, err := d.client.Do(req)
	if err != nil {
		d.recordResult(hook, 0, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		d.recordResult(hook, resp.StatusCode, fmt.Sprintf("upstream %d", resp.StatusCode))
		return
	}
	d.recordResult(hook, resp.StatusCode, "")
}

func (d *WebhookDispatcher) recordResult(hook domain.AuditWebhook, status int, errMessage string) {
	now := time.Now().UTC()
	hook.LastFiredAt = &now
	hook.LastStatus = status
	hook.LastError = errMessage
	_ = d.store.Update(context.Background(), &hook)
}

func renderWebhookBody(format string, payload webhookPayload) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "slack":
		text := fmt.Sprintf("*%s* — %s", payload.Event, payload.ResourceType)
		if payload.UserID != nil {
			text += fmt.Sprintf(" (user #%d)", *payload.UserID)
		}
		return json.Marshal(map[string]any{"text": text, "attachments": []map[string]any{{
			"fallback":  text,
			"color":     "warning",
			"timestamp": payload.Timestamp.Unix(),
			"fields": []map[string]any{
				{"title": "Action", "value": payload.Action, "short": true},
				{"title": "Resource", "value": payload.ResourceType, "short": true},
				{"title": "Host", "value": payload.Host, "short": true},
				{"title": "Status", "value": fmt.Sprintf("%d", payload.StatusCode), "short": true},
			},
		}}})
	case "discord":
		title := payload.Event
		desc := fmt.Sprintf("**Resource:** %s\n**Host:** %s\n**Status:** %d", payload.ResourceType, payload.Host, payload.StatusCode)
		return json.Marshal(map[string]any{
			"username": "portlyn",
			"embeds": []map[string]any{{
				"title":       title,
				"description": desc,
				"timestamp":   payload.Timestamp.UTC().Format(time.RFC3339),
			}},
		})
	case "ntfy":
		text := fmt.Sprintf("%s on %s (%s)", payload.Event, payload.Host, payload.ResourceType)
		return []byte(text), nil
	default:
		return json.Marshal(payload)
	}
}

func contentTypeFor(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "ntfy":
		return "text/plain"
	default:
		return "application/json"
	}
}

func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
