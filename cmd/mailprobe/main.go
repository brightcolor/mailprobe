package main

import (
	"context"
	"errors"
	"log"
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
	"github.com/brightcolor/mailprobe/internal/web"
)

func main() {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.LUTC)
	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("config error: %v", err)
	}

	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		logger.Fatalf("data dir: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		logger.Fatalf("db open: %v", err)
	}
	defer database.Close()

	st := store.New(database)
	engine := analyzer.New(analyzer.Options{
		EnableRBLChecks:     cfg.EnableRBLChecks,
		RBLProviders:        cfg.RBLProviders,
		EnableSpamAssassin:  cfg.EnableSpamAssassin,
		SpamAssassinHostPort: cfg.SpamAssassinHostPort,
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cleanup.Start(ctx, logger, st, cfg.CleanupInterval, cfg.RetentionTTL)

	webServer, err := web.New(cfg, st, logger)
	if err != nil {
		logger.Fatalf("web init: %v", err)
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
	smtpSrv := &smtp.Server{
		Addr:            cfg.SMTPListenAddr,
		Domain:          cfg.SMTPDomain,
		MaxMessageBytes: cfg.MaxMessageBytes,
		RateLimiter:     smtpLimiter,
		Logger:          logger,
		AllowRecipient: func(ctx context.Context, rcpt string) bool {
			return isAllowedRecipient(ctx, st, cfg, rcpt)
		},
		HandleMail: func(ctx context.Context, rm smtp.ReceivedMail) error {
			return processInbound(ctx, st, engine, cfg, logger, rm)
		},
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Printf("http: listening on %s", cfg.HTTPListenAddr)
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
		logger.Printf("shutdown signal received")
	case err := <-errCh:
		logger.Printf("fatal service error: %v", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	cancel()
	smtpSrv.Wait()
	logger.Printf("shutdown complete")
}

func processInbound(ctx context.Context, st *store.Store, engine *analyzer.Engine, cfg config.Config, logger *log.Logger, rm smtp.ReceivedMail) error {
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

	report := engine.Analyze(ctx, analyzer.Input{Message: msg, SMTPDomain: cfg.SMTPDomain})
	if _, err := st.SaveReport(ctx, report); err != nil {
		logger.Printf("analyze/store report error msg=%d: %v", msg.ID, err)
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
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), prefix) {
			return strings.TrimSpace(l[len(prefix):])
		}
	}
	return ""
}
