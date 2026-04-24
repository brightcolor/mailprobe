package telemetry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderPrometheusIncludesCounters(t *testing.T) {
	c := New()
	c.IncHTTPRequests()
	c.IncMailboxesCreated()
	c.IncMailsReceived()
	c.IncReportsGenerated()
	c.IncAnalyzerErrors()
	c.IncInboundErrors()
	c.IncWebRateLimited()
	c.IncSMTPRateLimited()

	out := c.RenderPrometheus()
	want := []string{
		"mailprobe_http_requests_total 1",
		"mailprobe_mailboxes_created_total 1",
		"mailprobe_mails_received_total 1",
		"mailprobe_reports_generated_total 1",
		"mailprobe_analyzer_errors_total 1",
		"mailprobe_inbound_errors_total 1",
		"mailprobe_web_ratelimit_blocked_total 1",
		"mailprobe_smtp_ratelimit_blocked_total 1",
	}
	for _, needle := range want {
		if !strings.Contains(out, needle) {
			t.Fatalf("expected %q in metrics output", needle)
		}
	}
}

func TestAlerterSendPostsJSON(t *testing.T) {
	var gotMethod string
	var gotContentType string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		gotBody = string(body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	a := NewAlerter(srv.URL)
	err := a.Send(context.Background(), "warn", "test_event", "sample", map[string]any{"id": 7})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST method, got %q", gotMethod)
	}
	if gotContentType != "application/json" {
		t.Fatalf("expected application/json content type, got %q", gotContentType)
	}
	if !strings.Contains(gotBody, "\"event\":\"test_event\"") {
		t.Fatalf("expected event in payload, got %q", gotBody)
	}
}
