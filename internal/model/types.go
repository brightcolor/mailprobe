package model

import "time"

type Mailbox struct {
	ID         int64
	Token      string
	Address    string
	CreatedIP  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

type Message struct {
	ID          int64
	MailboxID   int64
	SMTPFrom    string
	RCPTTo      string
	RemoteIP    string
	HELO        string
	ReceivedAt  time.Time
	RawSource   string
	HeaderBlock string
	Subject     string
	SizeBytes   int64
}

type CheckResult struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	ScoreDelta float64 `json:"score_delta"`
	Summary    string  `json:"summary"`
	Suggestion string  `json:"suggestion"`
}

type AnalysisReport struct {
	ID          int64         `json:"id"`
	MessageID   int64         `json:"message_id"`
	CreatedAt   time.Time     `json:"created_at"`
	Score       float64       `json:"score"`
	ScoreLabel  string        `json:"score_label"`
	Checks      []CheckResult `json:"checks"`
	Warnings    []string      `json:"warnings"`
	Suggestions []string      `json:"suggestions"`
	RawHeaders  map[string][]string `json:"raw_headers"`
	Links       []string      `json:"links"`
	SpamSignals []string      `json:"spam_signals"`
}

type MessageWithReport struct {
	Message Message
	Report  *AnalysisReport
}
