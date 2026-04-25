package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppName              string
	HTTPListenAddr       string
	SMTPListenAddr       string
	PublicBaseURL        string
	SMTPDomain           string
	DBPath               string
	DataDir              string
	MailboxTTL           time.Duration
	RetentionTTL         time.Duration
	CleanupInterval      time.Duration
	MaxMessageBytes      int64
	MaxActivePerIP       int
	MaxActiveGlobal      int
	WebRateLimitPerMin   int
	WebBurstPer10Sec     int
	SMTPRateLimitPerHour int
	SMTPBurstPerMin      int
	EnableRBLChecks      bool
	RBLProviders         []string
	EnableSpamAssassin   bool
	SpamAssassinHostPort string
	EnableRspamd         bool
	RspamdURL            string
	RspamdPassword       string
	AlertWebhookURL      string
	TrustedProxyCIDRs    []string
}

func Load() (Config, error) {
	cfg := Config{
		AppName:              getEnv("APP_NAME", "MailProbe"),
		HTTPListenAddr:       getEnv("HTTP_LISTEN_ADDR", ":8080"),
		SMTPListenAddr:       getEnv("SMTP_LISTEN_ADDR", ":2525"),
		PublicBaseURL:        strings.TrimRight(getEnv("PUBLIC_BASE_URL", "http://localhost:8080"), "/"),
		SMTPDomain:           strings.ToLower(getEnv("SMTP_DOMAIN", "mailprobe.local")),
		DBPath:               getEnv("DB_PATH", "/data/mailprobe.db"),
		DataDir:              getEnv("DATA_DIR", "/data"),
		MailboxTTL:           getEnvDuration("MAILBOX_TTL", 24*time.Hour),
		RetentionTTL:         getEnvDuration("DATA_RETENTION_TTL", 7*24*time.Hour),
		CleanupInterval:      getEnvDuration("CLEANUP_INTERVAL", 30*time.Minute),
		MaxMessageBytes:      getEnvInt64("MAX_MESSAGE_BYTES", 2*1024*1024),
		MaxActivePerIP:       getEnvInt("MAX_ACTIVE_MAILBOXES_PER_IP", 20),
		MaxActiveGlobal:      getEnvInt("MAX_ACTIVE_MAILBOXES_GLOBAL", 2000),
		WebRateLimitPerMin:   getEnvInt("WEB_RATE_LIMIT_PER_MIN", 60),
		WebBurstPer10Sec:     getEnvInt("WEB_BURST_PER_10_SEC", 20),
		SMTPRateLimitPerHour: getEnvInt("SMTP_RATE_LIMIT_PER_HOUR", 200),
		SMTPBurstPerMin:      getEnvInt("SMTP_BURST_PER_MIN", 40),
		EnableRBLChecks:      getEnvBool("ENABLE_RBL_CHECKS", false),
		RBLProviders:         splitCSV(getEnv("RBL_PROVIDERS", "zen.spamhaus.org,bl.spamcop.net,b.barracudacentral.org,psbl.surriel.com,dnsbl.dronebl.org,bl.blocklist.de")),
		EnableSpamAssassin:   getEnvBool("ENABLE_SPAMASSASSIN", false),
		SpamAssassinHostPort: getEnv("SPAMASSASSIN_HOSTPORT", "spamd:783"),
		EnableRspamd:         getEnvBool("ENABLE_RSPAMD", false),
		RspamdURL:            getEnv("RSPAMD_URL", "http://rspamd:11334/checkv2"),
		RspamdPassword:       getEnv("RSPAMD_PASSWORD", ""),
		AlertWebhookURL:      getEnv("ALERT_WEBHOOK_URL", ""),
		TrustedProxyCIDRs:    splitCSV(getEnv("TRUSTED_PROXY_CIDRS", "")),
	}

	if cfg.SMTPDomain == "" {
		return cfg, fmt.Errorf("SMTP_DOMAIN must not be empty")
	}
	if cfg.MaxMessageBytes < 512*1024 {
		return cfg, fmt.Errorf("MAX_MESSAGE_BYTES too low, must be >= 524288")
	}
	if cfg.MaxActivePerIP <= 0 || cfg.MaxActiveGlobal <= 0 || cfg.WebRateLimitPerMin <= 0 || cfg.WebBurstPer10Sec <= 0 || cfg.SMTPRateLimitPerHour <= 0 || cfg.SMTPBurstPerMin <= 0 {
		return cfg, fmt.Errorf("rate and mailbox limits must be > 0")
	}
	if cfg.MailboxTTL <= 0 || cfg.RetentionTTL <= 0 || cfg.CleanupInterval <= 0 {
		return cfg, fmt.Errorf("TTL and cleanup intervals must be > 0")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func getEnvInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvInt64(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
