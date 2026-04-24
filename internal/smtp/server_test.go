package smtp

import (
	"bufio"
	"strings"
	"testing"
)

func TestExtractSMTPPath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"<Alice@Example.org>", "alice@example.org"},
		{"bob@example.org", "bob@example.org"},
		{"<carol@example.org> SIZE=123", "carol@example.org"},
		{"", ""},
	}

	for _, tc := range cases {
		got := extractSMTPPath(tc.in)
		if got != tc.want {
			t.Fatalf("extractSMTPPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReadData(t *testing.T) {
	input := "Subject: t\r\n\r\nhello\r\n.\r\n"
	r := bufio.NewReader(strings.NewReader(input))
	data, err := readData(r, 1024)
	if err != nil {
		t.Fatalf("readData returned error: %v", err)
	}
	if !strings.Contains(string(data), "hello") {
		t.Fatalf("unexpected data: %q", string(data))
	}
}

func TestReadDataTooLarge(t *testing.T) {
	input := "x\r\n.\r\n"
	r := bufio.NewReader(strings.NewReader(input))
	_, err := readData(r, 1)
	if err == nil {
		t.Fatal("expected size limit error, got nil")
	}
}
