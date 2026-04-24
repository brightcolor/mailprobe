package main

import (
	"context"
	"strings"
	"testing"

	"github.com/brightcolor/mailprobe/internal/config"
	"github.com/brightcolor/mailprobe/internal/smtp"
)

func TestEnrichWithReceiverAuthHeadersAddsAuthBlocks(t *testing.T) {
	cfg := config.Config{SMTPDomain: "mx-test.example.org"}
	rm := smtp.ReceivedMail{
		RemoteIP: "",
		HELO:     "",
		MailFrom: "",
		RcptTo:   "abc123@mx-test.example.org",
	}
	raw := "Subject: Demo\r\n\r\nHello"

	out := enrichWithReceiverAuthHeaders(context.Background(), cfg, rm, raw)

	want := []string{
		"Authentication-Results:",
		"Received-SPF:",
		"X-MailProbe-SPF-Detail:",
		"X-MailProbe-DKIM-Detail:",
		"X-MailProbe-DMARC-Detail:",
		"\r\nSubject: Demo\r\n",
	}
	for _, needle := range want {
		if !strings.Contains(out, needle) {
			t.Fatalf("expected %q in output, got: %q", needle, out)
		}
	}
}
