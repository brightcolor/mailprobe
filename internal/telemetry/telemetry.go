package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

type Counters struct {
	startedAt time.Time

	httpRequestsTotal    atomic.Uint64
	mailboxesCreated     atomic.Uint64
	mailsReceived        atomic.Uint64
	reportsGenerated     atomic.Uint64
	analyzerErrors       atomic.Uint64
	inboundErrors        atomic.Uint64
	webRateLimitBlocked  atomic.Uint64
	smtpRateLimitBlocked atomic.Uint64
}

func New() *Counters {
	return &Counters{startedAt: time.Now().UTC()}
}

func (c *Counters) IncHTTPRequests()     { c.httpRequestsTotal.Add(1) }
func (c *Counters) IncMailboxesCreated() { c.mailboxesCreated.Add(1) }
func (c *Counters) IncMailsReceived()    { c.mailsReceived.Add(1) }
func (c *Counters) IncReportsGenerated() { c.reportsGenerated.Add(1) }
func (c *Counters) IncAnalyzerErrors()   { c.analyzerErrors.Add(1) }
func (c *Counters) IncInboundErrors()    { c.inboundErrors.Add(1) }
func (c *Counters) IncWebRateLimited()   { c.webRateLimitBlocked.Add(1) }
func (c *Counters) IncSMTPRateLimited()  { c.smtpRateLimitBlocked.Add(1) }

func (c *Counters) RenderPrometheus() string {
	uptimeSeconds := time.Since(c.startedAt).Seconds()
	var b strings.Builder
	b.WriteString("# HELP mailprobe_uptime_seconds Process uptime in seconds\n")
	b.WriteString("# TYPE mailprobe_uptime_seconds gauge\n")
	b.WriteString(fmt.Sprintf("mailprobe_uptime_seconds %.0f\n", uptimeSeconds))

	b.WriteString("# HELP mailprobe_http_requests_total Total HTTP requests\n")
	b.WriteString("# TYPE mailprobe_http_requests_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_http_requests_total %d\n", c.httpRequestsTotal.Load()))

	b.WriteString("# HELP mailprobe_mailboxes_created_total Total created mailboxes\n")
	b.WriteString("# TYPE mailprobe_mailboxes_created_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_mailboxes_created_total %d\n", c.mailboxesCreated.Load()))

	b.WriteString("# HELP mailprobe_mails_received_total Total inbound mails received\n")
	b.WriteString("# TYPE mailprobe_mails_received_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_mails_received_total %d\n", c.mailsReceived.Load()))

	b.WriteString("# HELP mailprobe_reports_generated_total Total analysis reports generated\n")
	b.WriteString("# TYPE mailprobe_reports_generated_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_reports_generated_total %d\n", c.reportsGenerated.Load()))

	b.WriteString("# HELP mailprobe_analyzer_errors_total Total analyzer/report persistence errors\n")
	b.WriteString("# TYPE mailprobe_analyzer_errors_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_analyzer_errors_total %d\n", c.analyzerErrors.Load()))

	b.WriteString("# HELP mailprobe_inbound_errors_total Total inbound processing errors\n")
	b.WriteString("# TYPE mailprobe_inbound_errors_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_inbound_errors_total %d\n", c.inboundErrors.Load()))

	b.WriteString("# HELP mailprobe_web_ratelimit_blocked_total Total web requests blocked by rate limiting\n")
	b.WriteString("# TYPE mailprobe_web_ratelimit_blocked_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_web_ratelimit_blocked_total %d\n", c.webRateLimitBlocked.Load()))

	b.WriteString("# HELP mailprobe_smtp_ratelimit_blocked_total Total SMTP sessions blocked by rate limiting\n")
	b.WriteString("# TYPE mailprobe_smtp_ratelimit_blocked_total counter\n")
	b.WriteString(fmt.Sprintf("mailprobe_smtp_ratelimit_blocked_total %d\n", c.smtpRateLimitBlocked.Load()))

	return b.String()
}

type Alerter struct {
	webhookURL string
	client     *http.Client
}

func NewAlerter(webhookURL string) *Alerter {
	return &Alerter{
		webhookURL: strings.TrimSpace(webhookURL),
		client: &http.Client{
			Timeout: 4 * time.Second,
		},
	}
}

func (a *Alerter) Enabled() bool {
	return a != nil && a.webhookURL != ""
}

func (a *Alerter) Send(ctx context.Context, severity, event, message string, fields map[string]any) error {
	if !a.Enabled() {
		return nil
	}
	payload := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"severity":  strings.ToLower(strings.TrimSpace(severity)),
		"event":     strings.TrimSpace(event),
		"message":   strings.TrimSpace(message),
		"fields":    fields,
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webhookURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alert webhook status %d", resp.StatusCode)
	}
	return nil
}
