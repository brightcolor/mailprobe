package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/brightcolor/mailprobe/internal/config"
	"github.com/brightcolor/mailprobe/internal/model"
	"github.com/brightcolor/mailprobe/internal/ratelimit"
	"github.com/brightcolor/mailprobe/internal/store"
)

type Server struct {
	cfg      config.Config
	store    *store.Store
	logger   *log.Logger
	tmpl     *template.Template
	limiter  *ratelimit.Limiter
	staticFS http.Handler
}

type HomeData struct {
	AppName string
	Domain  string
}

type MailboxData struct {
	AppName   string
	Mailbox   model.Mailbox
	Messages  []model.MessageWithReport
	Now       time.Time
	PublicURL string
}

type ReportData struct {
	AppName  string
	Message  model.Message
	Mailbox  model.Mailbox
	Report   model.AnalysisReport
	Statuses map[string]int
}

func New(cfg config.Config, st *store.Store, logger *log.Logger) (*Server, error) {
	if logger == nil {
		logger = log.Default()
	}
	t, err := template.ParseGlob(filepath.Join("internal", "web", "templates", "*.html"))
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		store:    st,
		logger:   logger,
		tmpl:     t,
		limiter:  ratelimit.New(time.Minute, cfg.WebRateLimitPerMin),
		staticFS: http.StripPrefix("/static/", http.FileServer(http.Dir(filepath.Join("internal", "web", "static")))),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", s.staticFS)
	mux.HandleFunc("/", s.home)
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/readyz", s.ready)
	mux.HandleFunc("/api/mailboxes", s.createMailbox)
	mux.HandleFunc("/api/mailboxes/", s.mailboxAPI)
	mux.HandleFunc("/mailbox/", s.mailboxPage)
	mux.HandleFunc("/report/", s.reportPage)
	mux.HandleFunc("/raw/", s.rawPage)
	return s.withLogging(s.withRateLimit(mux))
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/healthz") || strings.HasPrefix(r.URL.Path, "/readyz") || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		ip := s.clientIP(r)
		if !s.limiter.Allow("web:" + ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Printf("http: %s %s from=%s dur=%s", r.Method, r.URL.Path, s.clientIP(r), time.Since(start).Round(time.Millisecond))
	})
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) ready(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data := HomeData{AppName: s.cfg.AppName, Domain: s.cfg.SMTPDomain}
	s.render(w, "home", data)
}

func (s *Server) createMailbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.clientIP(r)
	ctx := r.Context()
	active, err := s.store.CountActiveMailboxesByIP(ctx, ip)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	if active >= s.cfg.MaxActivePerIP {
		http.Error(w, "too many active mailboxes for this IP", http.StatusTooManyRequests)
		return
	}

	token, addr, err := s.generateMailboxAddress(ctx)
	if err != nil {
		http.Error(w, "could not create mailbox", http.StatusInternalServerError)
		return
	}
	mb, err := s.store.CreateMailbox(ctx, token, addr, ip, s.cfg.MailboxTTL)
	if err != nil {
		http.Error(w, "could not create mailbox", http.StatusInternalServerError)
		return
	}

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		jsonResp(w, http.StatusCreated, map[string]any{
			"token":      mb.Token,
			"address":    mb.Address,
			"expires_at": mb.ExpiresAt,
			"mailbox_url": fmt.Sprintf("%s/mailbox/%s", s.cfg.PublicBaseURL, mb.Token),
		})
		return
	}

	http.Redirect(w, r, "/mailbox/"+mb.Token, http.StatusSeeOther)
}

func (s *Server) mailboxPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, "/mailbox/")
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	mb, err := s.store.GetMailboxByToken(ctx, token)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		http.Error(w, "mailbox not found", status)
		return
	}
	_ = s.store.TouchMailbox(ctx, mb.ID)

	msgs, err := s.store.ListMessagesWithReports(ctx, mb.ID, 30)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	s.render(w, "mailbox", MailboxData{
		AppName:   s.cfg.AppName,
		Mailbox:   mb,
		Messages:  msgs,
		Now:       time.Now().UTC(),
		PublicURL: s.cfg.PublicBaseURL,
	})
}

func (s *Server) reportPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idRaw := strings.TrimPrefix(r.URL.Path, "/report/")
	id, err := strconv.ParseInt(idRaw, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	report, err := s.store.GetReport(ctx, id)
	if err != nil {
		http.Error(w, "report not found", http.StatusNotFound)
		return
	}
	msg, err := s.store.GetMessage(ctx, report.MessageID)
	if err != nil {
		http.Error(w, "message not found", http.StatusNotFound)
		return
	}
	mb, err := s.mailboxByID(ctx, msg.MailboxID)
	if err != nil {
		http.Error(w, "mailbox not found", http.StatusNotFound)
		return
	}
	statuses := map[string]int{"pass": 0, "warn": 0, "fail": 0, "info": 0}
	sortChecks(report.Checks)
	for _, c := range report.Checks {
		statuses[c.Status]++
	}
	s.render(w, "report", ReportData{AppName: s.cfg.AppName, Message: msg, Mailbox: mb, Report: report, Statuses: statuses})
}

func (s *Server) rawPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/raw/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	msg, err := s.store.GetMessage(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	switch parts[1] {
	case "headers":
		_, _ = w.Write([]byte(msg.HeaderBlock))
	case "source":
		_, _ = w.Write([]byte(msg.RawSource))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) mailboxAPI(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/mailboxes/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	token, action := parts[0], parts[1]
	ctx := r.Context()
	switch {
	case action == "status" && r.Method == http.MethodGet:
		mb, err := s.store.GetMailboxByToken(ctx, token)
		if err != nil {
			jsonResp(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
		msgs, err := s.store.ListMessagesWithReports(ctx, mb.ID, 1)
		if err != nil {
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
		resp := map[string]any{"mailbox": mb.Address, "expires_at": mb.ExpiresAt, "message_count": 0}
		if len(msgs) > 0 {
			resp["message_count"] = 1
			resp["latest_message_id"] = msgs[0].Message.ID
			resp["latest_received_at"] = msgs[0].Message.ReceivedAt
			if msgs[0].Report != nil {
				resp["latest_report_id"] = msgs[0].Report.ID
				resp["latest_score"] = msgs[0].Report.Score
			}
		}
		jsonResp(w, http.StatusOK, resp)
	case action == "delete" && r.Method == http.MethodPost:
		err := s.store.DeleteMailboxByToken(ctx, token)
		if err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, store.ErrNotFound) {
				status = http.StatusNotFound
			}
			jsonResp(w, status, map[string]string{"error": "mailbox not found"})
			return
		}
		jsonResp(w, http.StatusOK, map[string]string{"status": "deleted"})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) mailboxByID(ctx context.Context, id int64) (model.Mailbox, error) {
	return s.store.GetMailboxByID(ctx, id)
}

func (s *Server) generateMailboxAddress(ctx context.Context) (token, address string, err error) {
	for i := 0; i < 8; i++ {
		tok, e := randomToken(6)
		if e != nil {
			return "", "", e
		}
		addr := tok + "@" + s.cfg.SMTPDomain
		_, e = s.store.GetMailboxByAddress(ctx, addr)
		if errors.Is(e, store.ErrNotFound) {
			return tok, addr, nil
		}
		if e != nil {
			return "", "", e
		}
	}
	return "", "", fmt.Errorf("could not generate unique mailbox")
}

func randomToken(bytesLen int) (string, error) {
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) clientIP(r *http.Request) string {
	if xf := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); xf != "" {
		if ip := net.ParseIP(strings.TrimSpace(xf)); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		s.logger.Printf("template render error: %v", err)
	}
}

func jsonResp(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func sortChecks(checks []model.CheckResult) {
	rank := map[string]int{"fail": 0, "warn": 1, "pass": 2, "info": 3}
	sort.SliceStable(checks, func(i, j int) bool {
		ri := rank[checks[i].Status]
		rj := rank[checks[j].Status]
		if ri == rj {
			return checks[i].Name < checks[j].Name
		}
		return ri < rj
	})
}
