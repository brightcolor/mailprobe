package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brightcolor/mailprobe/internal/analyzer"
	"github.com/brightcolor/mailprobe/internal/cleanup"
	"github.com/brightcolor/mailprobe/internal/config"
	"github.com/brightcolor/mailprobe/internal/db"
	"github.com/brightcolor/mailprobe/internal/model"
	"github.com/brightcolor/mailprobe/internal/ratelimit"
	"github.com/brightcolor/mailprobe/internal/smtp"
	"github.com/brightcolor/mailprobe/internal/store"
	"github.com/brightcolor/mailprobe/internal/telemetry"
	"github.com/brightcolor/mailprobe/internal/web"
)

func main() {
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slogLogger := slog.New(slogHandler)
	logger := slog.NewLogLogger(slogHandler, slog.LevelInfo)
	cfg, err := config.Load()
	if err != nil {
		slogLogger.Error("config error", "error", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		slogLogger.Error("data dir error", "error", err)
		os.Exit(1)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		slogLogger.Error("db open error", "error", err)
		os.Exit(1)
	}
	defer database.Close()

	st := store.New(database)
	metrics := telemetry.New()
	alerter := telemetry.NewAlerter(cfg.AlertWebhookURL)
	engine := analyzer.New(analyzer.Options{
		EnableRBLChecks:      cfg.EnableRBLChecks,
		RBLProviders:         cfg.RBLProviders,
		EnableSpamAssassin:   cfg.EnableSpamAssassin,
		SpamAssassinHostPort: cfg.SpamAssassinHostPort,
		EnableRspamd:         cfg.EnableRspamd,
		RspamdURL:            cfg.RspamdURL,
		RspamdPassword:       cfg.RspamdPassword,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cleanup.Start(ctx, logger, st, cfg.CleanupInterval, cfg.RetentionTTL)

	webServer, err := web.New(cfg, st, logger, metrics)
	if err != nil {
		slogLogger.Error("web init error", "error", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{
		Addr:              cfg.HTTPListenAddr,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	smtpLimiter := ratelimit.New(time.Hour, cfg.SMTPRateLimitPerHour)
	smtpBurstLimiter := ratelimit.New(time.Minute, cfg.SMTPBurstPerMin)
	smtpSrv := &smtp.Server{
		Addr:            cfg.SMTPListenAddr,
		Domain:          cfg.SMTPDomain,
		MaxMessageBytes: cfg.MaxMessageBytes,
		RateLimiter:     smtpLimiter,
		BurstLimiter:    smtpBurstLimiter,
		OnRateLimited: func(remoteIP string) {
			metrics.IncSMTPRateLimited()
			logger.Printf("smtp rate limited remote_ip=%s", remoteIP)
		},
		Logger: logger,
		AllowRecipient: func(ctx context.Context, rcpt string) bool {
			return isAllowedRecipient(ctx, st, cfg, rcpt)
		},
		HandleMail: func(ctx context.Context, rm smtp.ReceivedMail) error {
			if err := processInbound(ctx, st, engine, cfg, logger, metrics, alerter, rm); err != nil {
				metrics.IncInboundErrors()
				_ = alerter.Send(ctx, "error", "inbound_processing_failed", "Inbound processing failed", map[string]any{
					"remote_ip": rm.RemoteIP,
					"mail_from": rm.MailFrom,
					"rcpt_to":   rm.RcptTo,
					"error":     err.Error(),
				})
				return err
			}
			return nil
		},
	}

	errCh := make(chan error, 2)
	go func() {
		slogLogger.Info("http listening", "addr", cfg.HTTPListenAddr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	go func() {
		if err := smtpSrv.Start(ctx); err != nil && ctx.Err() == nil {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		slogLogger.Info("shutdown signal received")
	case err := <-errCh:
		slogLogger.Error("fatal service error", "error", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
	smtpSrv.Wait()
	slogLogger.Info("shutdown complete")
}

func processInbound(ctx context.Context, st *store.Store, engine *analyzer.Engine, cfg config.Config, logger *log.Logger, metrics *telemetry.Counters, alerter *telemetry.Alerter, rm smtp.ReceivedMail) error {
	rcpt := strings.ToLower(strings.TrimSpace(rm.RcptTo))
	if !strings.HasSuffix(rcpt, "@"+strings.ToLower(cfg.SMTPDomain)) {
		return nil
	}
	mb, err := st.GetMailboxByAddress(ctx, rcpt)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if time.Now().UTC().After(mb.ExpiresAt) {
		return nil
	}

	raw := string(rm.Data)
	raw = enrichWithReceiverAuthHeaders(ctx, cfg, rm, raw)
	headers := headerBlock(raw)
	subject := headerField(headers, "Subject")

	msg, err := st.SaveMessage(ctx, model.Message{
		MailboxID:   mb.ID,
		SMTPFrom:    rm.MailFrom,
		RCPTTo:      rcpt,
		RemoteIP:    rm.RemoteIP,
		HELO:        rm.HELO,
		ReceivedAt:  time.Now().UTC(),
		RawSource:   raw,
		HeaderBlock: headers,
		Subject:     subject,
		SizeBytes:   int64(len(rm.Data)),
	})
	if err != nil {
		return err
	}
	metrics.IncMailsReceived()

	report := engine.Analyze(ctx, analyzer.Input{Message: msg, SMTPDomain: cfg.SMTPDomain})
	if _, err := st.SaveReport(ctx, report); err != nil {
		metrics.IncAnalyzerErrors()
		logger.Printf("analyze/store report error msg=%d: %v", msg.ID, err)
		_ = alerter.Send(ctx, "warn", "report_store_failed", "Analyzer report persistence failed", map[string]any{
			"message_id": msg.ID,
			"mailbox_id": mb.ID,
			"error":      err.Error(),
		})
	} else {
		metrics.IncReportsGenerated()
	}
	_ = st.TouchMailbox(ctx, mb.ID)
	logger.Printf("smtp: received message mailbox=%s msg=%d size=%d", mb.Token, msg.ID, len(rm.Data))
	return nil
}

func isAllowedRecipient(ctx context.Context, st *store.Store, cfg config.Config, rcpt string) bool {
	rcpt = strings.ToLower(strings.TrimSpace(rcpt))
	if !strings.HasSuffix(rcpt, "@"+strings.ToLower(cfg.SMTPDomain)) {
		return false
	}
	mb, err := st.GetMailboxByAddress(ctx, rcpt)
	if err != nil {
		return false
	}
	return time.Now().UTC().Before(mb.ExpiresAt)
}

func headerBlock(raw string) string {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(norm, "\n\n", 2)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func headerField(headerBlock, key string) string {
	lines := strings.Split(headerBlock, "\n")
	prefix := strings.ToLower(key) + ":"
	for i, l := range lines {
		line := strings.TrimRight(l, "\r")
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), prefix) {
			value := strings.TrimSpace(line[len(prefix):])
			for _, next := range lines[i+1:] {
				next = strings.TrimRight(next, "\r")
				if !strings.HasPrefix(next, " ") && !strings.HasPrefix(next, "\t") {
					break
				}
				value += " " + strings.TrimSpace(next)
			}
			decoded, err := new(mime.WordDecoder).DecodeHeader(value)
			if err == nil {
				return strings.TrimSpace(decoded)
			}
			return strings.TrimSpace(value)
		}
	}
	return ""
}
