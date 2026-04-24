package smtp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/brightcolor/mailprobe/internal/ratelimit"
)

type ReceivedMail struct {
	RemoteIP string
	HELO     string
	MailFrom string
	RcptTo   string
	Data     []byte
}

type Handler func(ctx context.Context, m ReceivedMail) error
type RecipientValidator func(ctx context.Context, rcpt string) bool

type Server struct {
	Addr            string
	Domain          string
	MaxMessageBytes int64
	RateLimiter     *ratelimit.Limiter
	Logger          *log.Logger
	HandleMail      Handler
	AllowRecipient  RecipientValidator

	ln net.Listener
	wg sync.WaitGroup
}

func (s *Server) Start(ctx context.Context) error {
	if s.Logger == nil {
		s.Logger = log.Default()
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.Logger.Printf("smtp: listening on %s", s.Addr)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.Logger.Printf("smtp: accept error: %v", err)
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(ctx, c)
		}(conn)
	}
}

func (s *Server) Wait() {
	s.wg.Wait()
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	remoteIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if remoteIP == "" {
		remoteIP = conn.RemoteAddr().String()
	}
	if s.RateLimiter != nil && !s.RateLimiter.Allow(remoteIP) {
		writeLine(conn, "451 4.7.1 rate limit exceeded")
		return
	}

	_ = conn.SetDeadline(time.Now().Add(3 * time.Minute))
	writeLine(conn, "220 "+s.Domain+" MailProbe SMTP")

	r := bufio.NewReader(conn)
	var helo, mailFrom string
	var rcptTo []string

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				s.Logger.Printf("smtp: read error from %s: %v", remoteIP, err)
			}
			return
		}
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO ") || strings.HasPrefix(upper, "HELO "):
			helo = strings.TrimSpace(line[5:])
			writeLine(conn, "250-"+s.Domain)
			writeLine(conn, "250 SIZE "+fmt.Sprintf("%d", s.MaxMessageBytes))
		case strings.HasPrefix(upper, "MAIL FROM:"):
			mailFrom = extractSMTPPath(line[len("MAIL FROM:"):])
			rcptTo = rcptTo[:0]
			writeLine(conn, "250 2.1.0 OK")
		case strings.HasPrefix(upper, "RCPT TO:"):
			rcpt := extractSMTPPath(line[len("RCPT TO:"):])
			if rcpt == "" {
				writeLine(conn, "501 5.1.3 bad recipient")
				continue
			}
			if s.AllowRecipient != nil && !s.AllowRecipient(ctx, rcpt) {
				writeLine(conn, "550 5.1.1 recipient rejected")
				continue
			}
			rcptTo = append(rcptTo, strings.ToLower(rcpt))
			writeLine(conn, "250 2.1.5 OK")
		case upper == "DATA":
			if mailFrom == "" || len(rcptTo) == 0 {
				writeLine(conn, "503 5.5.1 bad sequence")
				continue
			}
			writeLine(conn, "354 End data with <CR><LF>.<CR><LF>")
			data, derr := readData(r, s.MaxMessageBytes)
			if derr != nil {
				writeLine(conn, "552 5.3.4 message too large or malformed")
				continue
			}
			for _, rcpt := range rcptTo {
				if s.HandleMail == nil {
					continue
				}
				err = s.HandleMail(ctx, ReceivedMail{RemoteIP: remoteIP, HELO: helo, MailFrom: mailFrom, RcptTo: rcpt, Data: data})
				if err != nil {
					s.Logger.Printf("smtp: handler error: %v", err)
				}
			}
			writeLine(conn, "250 2.0.0 queued")
		case upper == "RSET":
			mailFrom = ""
			rcptTo = nil
			writeLine(conn, "250 2.0.0 reset")
		case upper == "NOOP":
			writeLine(conn, "250 2.0.0 OK")
		case upper == "QUIT":
			writeLine(conn, "221 2.0.0 bye")
			return
		default:
			writeLine(conn, "500 5.5.2 command not recognized")
		}
	}
}

func writeLine(w io.Writer, line string) {
	_, _ = io.WriteString(w, line+"\r\n")
}

func extractSMTPPath(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "<") {
		if end := strings.Index(s, ">"); end > 0 {
			s = s[1:end]
		} else {
			s = strings.TrimPrefix(s, "<")
		}
	}
	if i := strings.Index(s, " "); i > 0 {
		s = s[:i]
	}
	return strings.ToLower(strings.TrimSpace(s))
}

func readData(r *bufio.Reader, maxBytes int64) ([]byte, error) {
	var out strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if int64(out.Len()+len(line)) > maxBytes {
			return nil, fmt.Errorf("message exceeds max bytes")
		}
		out.WriteString(line)
	}
	return []byte(out.String()), nil
}
