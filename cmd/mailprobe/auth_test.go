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

func TestHeaderFieldUnfoldsAndDecodesSubject(t *testing.T) {
	headers := strings.Join([]string{
		"From: sender@example.org",
		"Subject: =?UTF-8?Q?Hallo?=",
		" =?UTF-8?Q?_Welt?=",
		"To: probe@example.test",
	}, "\r\n")

	got := headerField(headers, "Subject")
	if got != "Hallo Welt" {
		t.Fatalf("expected decoded folded subject, got %q", got)
	}
}

func TestMatchesConfiguredDomainAllowsDynamicDomainWhenUnset(t *testing.T) {
	cfg := config.Config{}
	if !matchesConfiguredDomain(cfg, "abc@request-derived.example") {
		t.Fatal("expected unset SMTP_DOMAIN to allow lookup-based recipient validation")
	}
}

func TestMatchesConfiguredDomainRestrictsConfiguredDomain(t *testing.T) {
	cfg := config.Config{SMTPDomain: "example.test"}
	if !matchesConfiguredDomain(cfg, "abc@example.test") {
		t.Fatal("expected configured domain to match")
	}
	if matchesConfiguredDomain(cfg, "abc@other.test") {
		t.Fatal("expected different recipient domain to be rejected")
	}
}
