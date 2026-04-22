package analyzer

import (
	"bytes"
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/html"

	"github.com/brightcolor/mailprobe/internal/model"
)

type Options struct {
	EnableRBLChecks      bool
	RBLProviders         []string
	EnableSpamAssassin   bool
	SpamAssassinHostPort string
	EnableRspamd         bool
	RspamdURL            string
	RspamdPassword       string
}

type Input struct {
	Message    model.Message
	SMTPDomain string
}

type Engine struct {
	opts Options
}

func New(opts Options) *Engine {
	return &Engine{opts: opts}
}

func (e *Engine) Analyze(ctx context.Context, in Input) model.AnalysisReport {
	report := model.AnalysisReport{
		MessageID:  in.Message.ID,
		CreatedAt:  time.Now().UTC(),
		Score:      10.0,
		RawHeaders: map[string][]string{},
	}

	parsed, parseErr := mail.ReadMessage(strings.NewReader(in.Message.RawSource))
	if parseErr != nil {
		report.Checks = append(report.Checks, fail("mime_parse", "MIME/Message Parsing", -2.0, "Rohmail konnte nicht korrekt geparst werden.", "Sende eine RFC-konforme MIME-Mail und prüfe den Mailer."))
		report.Warnings = append(report.Warnings, parseErr.Error())
		report.Score = clampScore(report.Score)
		assignLabel(&report)
		return report
	}

	headers := parsed.Header
	for k, v := range headers {
		report.RawHeaders[k] = append([]string(nil), v...)
	}

	bodyBytes, bodyErr := readLimited(parsed.Body, 4*1024*1024)
	if bodyErr != nil {
		report.Checks = append(report.Checks, warn("body_read", "Body Readability", -0.5, "Body konnte nicht vollständig gelesen werden.", "Nachrichtengröße und Encoding prüfen."))
	}

	fromDomain, _ := headerFromDomain(headers.Get("From"))
	envelopeDomain := domainPart(in.Message.SMTPFrom)
	returnPathDomain := domainPart(headers.Get("Return-Path"))
	authResults := strings.ToLower(strings.Join(headers.Values("Authentication-Results"), " ; "))

	spfResult := parseAuthResult(authResults, "spf")
	dkimResult := parseAuthResult(authResults, "dkim")
	dmarcResult := parseAuthResult(authResults, "dmarc")

	// SPF
	hasSPFRecord := false
	if envelopeDomain != "" {
		recs, _ := net.DefaultResolver.LookupTXT(ctx, envelopeDomain)
		for _, rec := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
				hasSPFRecord = true
				break
			}
		}
	}
	switch spfResult {
	case "pass":
		report.Checks = append(report.Checks, pass("spf", "SPF", 0.4, "SPF laut Authentication-Results bestanden.", ""))
	case "fail", "softfail":
		report.Checks = append(report.Checks, fail("spf", "SPF", -1.4, fmt.Sprintf("SPF meldet %s.", spfResult), "Envelope-From-Domain und SPF-Record korrigieren."))
	default:
		if hasSPFRecord {
			report.Checks = append(report.Checks, info("spf", "SPF", 0.0, "SPF-Record vorhanden, kein eindeutiges SPF-Ergebnis im Header.", ""))
		} else {
			report.Checks = append(report.Checks, warn("spf", "SPF", -0.8, "Kein SPF-Record erkannt oder Ergebnis fehlt.", "TXT-Record mit v=spf1 auf der Envelope-From-Domain setzen."))
		}
	}

	// DKIM
	hasDKIMSig := headers.Get("DKIM-Signature") != ""
	switch dkimResult {
	case "pass":
		report.Checks = append(report.Checks, pass("dkim", "DKIM", 0.4, "DKIM laut Authentication-Results bestanden.", ""))
	case "fail", "temperror", "permerror":
		report.Checks = append(report.Checks, fail("dkim", "DKIM", -1.4, fmt.Sprintf("DKIM meldet %s.", dkimResult), "Selector, Canonicalization und Signatur prüfen."))
	default:
		if hasDKIMSig {
			report.Checks = append(report.Checks, warn("dkim", "DKIM", -0.5, "DKIM-Signatur vorhanden, aber kein valides Ergebnis erkennbar.", "Verifizierbarkeit der DKIM-Signatur sicherstellen."))
		} else {
			report.Checks = append(report.Checks, fail("dkim", "DKIM", -1.0, "Keine DKIM-Signatur gefunden.", "Ausgehenden MTA so konfigurieren, dass DKIM signiert wird."))
		}
	}

	// DMARC
	hasDMARC := false
	dmarcPolicy := ""
	if fromDomain != "" {
		dmarcTXT, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+fromDomain)
		for _, rec := range dmarcTXT {
			lr := strings.ToLower(rec)
			if strings.HasPrefix(lr, "v=dmarc1") {
				hasDMARC = true
				dmarcPolicy = extractTagValue(lr, "p")
				break
			}
		}
	}
	alignedSPF := envelopeDomain != "" && fromDomain != "" && (envelopeDomain == fromDomain || strings.HasSuffix(envelopeDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+envelopeDomain))
	dkimDomain := domainFromDKIM(headers.Get("DKIM-Signature"))
	alignedDKIM := dkimDomain != "" && fromDomain != "" && (dkimDomain == fromDomain || strings.HasSuffix(dkimDomain, "."+fromDomain))

	if dmarcResult == "pass" {
		report.Checks = append(report.Checks, pass("dmarc", "DMARC", 0.4, "DMARC laut Authentication-Results bestanden.", ""))
	} else if hasDMARC {
		if alignedSPF || alignedDKIM {
			report.Checks = append(report.Checks, warn("dmarc", "DMARC", -0.3, fmt.Sprintf("DMARC-Record vorhanden (p=%s), Alignment teilweise plausibel, aber kein eindeutiges pass im Header.", emptyFallback(dmarcPolicy, "none")), "DMARC-Alignment und Reporting prüfen."))
		} else {
			report.Checks = append(report.Checks, fail("dmarc", "DMARC", -1.0, fmt.Sprintf("DMARC-Record vorhanden (p=%s), aber kein SPF/DKIM-Alignment.", emptyFallback(dmarcPolicy, "none")), "From-Domain-Alignment mit SPF oder DKIM sicherstellen."))
		}
	} else {
		report.Checks = append(report.Checks, fail("dmarc", "DMARC", -1.2, "Kein DMARC-Record für die From-Domain gefunden.", "_dmarc.<domain> TXT mit v=DMARC1 veröffentlichen."))
	}

	// PTR
	ptrCheck := ptrPlausibility(ctx, in.Message.RemoteIP)
	report.Checks = append(report.Checks, ptrCheck)

	// HELO/EHLO
	helo := strings.TrimSpace(in.Message.HELO)
	if helo == "" {
		report.Checks = append(report.Checks, fail("helo", "HELO/EHLO", -0.8, "HELO/EHLO fehlt.", "MTA sollte einen validen FQDN als EHLO senden."))
	} else if net.ParseIP(helo) != nil {
		report.Checks = append(report.Checks, warn("helo", "HELO/EHLO", -0.4, "HELO/EHLO ist eine IP-Literal-Angabe.", "FQDN statt IP in EHLO verwenden."))
	} else if strings.Count(helo, ".") < 1 {
		report.Checks = append(report.Checks, warn("helo", "HELO/EHLO", -0.3, "HELO/EHLO wirkt nicht wie ein FQDN.", "FQDN mit PTR-bezogener Hostkennung verwenden."))
	} else {
		report.Checks = append(report.Checks, pass("helo", "HELO/EHLO", 0.1, "HELO/EHLO sieht plausibel aus.", ""))
	}

	// Envelope/Header alignment
	if fromDomain == "" || envelopeDomain == "" {
		report.Checks = append(report.Checks, warn("from_alignment", "Envelope-From / Header-From", -0.4, "From oder Envelope-From konnte nicht sicher ermittelt werden.", "Absenderfelder konsistent setzen."))
	} else if fromDomain == envelopeDomain || strings.HasSuffix(envelopeDomain, "."+fromDomain) {
		report.Checks = append(report.Checks, pass("from_alignment", "Envelope-From / Header-From", 0.2, "Envelope-From und Header-From sind konsistent.", ""))
	} else {
		report.Checks = append(report.Checks, warn("from_alignment", "Envelope-From / Header-From", -0.7, "Envelope-From und Header-From sind nicht aligned.", "Bounce-Domain und sichtbare From-Domain besser angleichen."))
	}

	// Return-Path
	if headers.Get("Return-Path") == "" {
		report.Checks = append(report.Checks, warn("return_path", "Return-Path", -0.5, "Kein Return-Path Header sichtbar.", "Envelope-From und Return-Path klar setzen."))
	} else if returnPathDomain != "" {
		report.Checks = append(report.Checks, pass("return_path", "Return-Path", 0.1, "Return-Path ist vorhanden.", ""))
	}

	receivedLines := headers.Values("Received")
	if len(receivedLines) == 0 {
		report.Checks = append(report.Checks, fail("received_chain", "Received-Header-Kette", -1.2, "Keine Received-Header vorhanden.", "Transportpfad muss Received-Header enthalten."))
	} else {
		report.Checks = append(report.Checks, info("received_chain", "Received-Header-Kette", 0.0, fmt.Sprintf("%d Received-Header erkannt.", len(receivedLines)), ""))
	}

	if headers.Get("ARC-Seal") != "" || headers.Get("ARC-Message-Signature") != "" {
		report.Checks = append(report.Checks, info("arc", "ARC", 0.0, "ARC-Header vorhanden.", ""))
	} else {
		report.Checks = append(report.Checks, info("arc", "ARC", 0.0, "Keine ARC-Header vorhanden.", "Nur relevant bei Weiterleitungs-Szenarien."))
	}

	mimeFindings, parsedBody := inspectBody(headers, bodyBytes)
	report.Checks = append(report.Checks, mimeFindings...)

	links := extractLinks(parsedBody.AllText)
	report.Links = dedupeSorted(links)
	urlFindings, spamSignals := evaluateURLs(report.Links)
	report.Checks = append(report.Checks, urlFindings...)
	report.SpamSignals = append(report.SpamSignals, spamSignals...)

	htmlFindings := htmlHeuristics(parsedBody.HTML)
	report.Checks = append(report.Checks, htmlFindings...)

	subjectChecks, subjectSignals := subjectHeuristics(headers.Get("Subject"))
	report.Checks = append(report.Checks, subjectChecks...)
	report.SpamSignals = append(report.SpamSignals, subjectSignals...)

	headChecks, headWarnings := headerHeuristics(headers)
	report.Checks = append(report.Checks, headChecks...)
	report.Warnings = append(report.Warnings, headWarnings...)

	unicodeCheck, unicodeSignal := unicodeObfuscationCheck(parsedBody.AllText)
	report.Checks = append(report.Checks, unicodeCheck)
	if unicodeSignal != "" {
		report.SpamSignals = append(report.SpamSignals, unicodeSignal)
	}

	newsletterChecks := newsletterHeuristics(headers, parsedBody)
	report.Checks = append(report.Checks, newsletterChecks...)

	if e.opts.EnableRBLChecks {
		rblChecks := rblHeuristics(ctx, in.Message.RemoteIP, e.opts.RBLProviders)
		report.Checks = append(report.Checks, rblChecks...)
	}
	if e.opts.EnableSpamAssassin && strings.TrimSpace(e.opts.SpamAssassinHostPort) != "" {
		report.Checks = append(report.Checks, spamAssassinHeuristic(ctx, e.opts.SpamAssassinHostPort, in.Message.RawSource))
	}
	if e.opts.EnableRspamd && strings.TrimSpace(e.opts.RspamdURL) != "" {
		report.Checks = append(report.Checks, rspamdHeuristic(ctx, e.opts.RspamdURL, e.opts.RspamdPassword, in.Message.RawSource))
	}

	for _, c := range report.Checks {
		report.Score += c.ScoreDelta
		if c.Status == "fail" || c.Status == "warn" {
			if c.Suggestion != "" {
				report.Suggestions = append(report.Suggestions, c.Suggestion)
			}
		}
	}

	report.Score = clampScore(report.Score)
	report.Suggestions = dedupeSorted(report.Suggestions)
	report.Warnings = dedupeSorted(report.Warnings)
	report.SpamSignals = dedupeSorted(report.SpamSignals)
	assignLabel(&report)
	return report
}

func pass(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "pass", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}
func warn(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "warn", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}
func fail(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "fail", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}
func info(id, name string, delta float64, summary, suggestion string) model.CheckResult {
	return model.CheckResult{ID: id, Name: name, Status: "info", ScoreDelta: delta, Summary: summary, Suggestion: suggestion}
}

func clampScore(s float64) float64 {
	if s < 0 {
		return 0
	}
	if s > 10 {
		return 10
	}
	return float64(int(s*10+0.5)) / 10
}

func assignLabel(r *model.AnalysisReport) {
	switch {
	case r.Score >= 9:
		r.ScoreLabel = "Excellent"
	case r.Score >= 7.5:
		r.ScoreLabel = "Good"
	case r.Score >= 5.5:
		r.ScoreLabel = "Needs Work"
	default:
		r.ScoreLabel = "High Risk"
	}
}

func parseAuthResult(s, key string) string {
	re := regexp.MustCompile(key + `=([a-zA-Z]+)`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(m[1])
}

func headerFromDomain(raw string) (domain, addr string) {
	if raw == "" {
		return "", ""
	}
	parsed, err := mail.ParseAddress(raw)
	if err != nil {
		return domainPart(raw), ""
	}
	return domainPart(parsed.Address), parsed.Address
}

func domainPart(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "<>"))
	if v == "" {
		return ""
	}
	at := strings.LastIndex(v, "@")
	if at < 0 || at+1 >= len(v) {
		return ""
	}
	return strings.ToLower(v[at+1:])
}

func ptrPlausibility(ctx context.Context, ip string) model.CheckResult {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return warn("ptr", "PTR/rDNS", -0.4, "Remote-IP ist ungültig, PTR nicht prüfbar.", "SMTP-Quelle prüfen.")
	}
	ptr, err := net.DefaultResolver.LookupAddr(ctx, parsed.String())
	if err != nil || len(ptr) == 0 {
		return fail("ptr", "PTR/rDNS", -1.0, "Kein PTR/rDNS für die sendende IP gefunden.", "PTR-Record für ausgehende Mail-IP setzen.")
	}
	host := strings.TrimSuffix(strings.ToLower(ptr[0]), ".")
	fwd, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(fwd) == 0 {
		return warn("ptr", "PTR/rDNS", -0.5, "PTR vorhanden, aber Forward-Lookup liefert keine Adresse.", "Forward-confirmed reverse DNS einrichten.")
	}
	for _, candidate := range fwd {
		if candidate == parsed.String() {
			return pass("ptr", "PTR/rDNS", 0.2, "PTR und Forward DNS sind konsistent.", "")
		}
	}
	return warn("ptr", "PTR/rDNS", -0.4, "PTR vorhanden, aber nicht forward-consistent zur sendenden IP.", "PTR/FQDN und A/AAAA sauber angleichen.")
}

type parsedBody struct {
	Text        string
	HTML        string
	AllText     string
	PartCount   int
	HasTextPart bool
	HasHTMLPart bool
	Attachments int
	Images      int
	Charset     string
}

func inspectBody(headers mail.Header, body []byte) ([]model.CheckResult, parsedBody) {
	out := make([]model.CheckResult, 0)
	pb := parsedBody{AllText: string(body)}

	ct := headers.Get("Content-Type")
	mediatype, params, err := mime.ParseMediaType(ct)
	if err != nil {
		out = append(out, warn("mime_ct", "MIME Content-Type", -0.4, "Content-Type wirkt fehlerhaft.", "Content-Type Header korrigieren."))
		return out, pb
	}
	pb.Charset = strings.ToLower(params["charset"])

	if strings.HasPrefix(mediatype, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			out = append(out, fail("mime_boundary", "Multipart-Aufbau", -1.0, "Multipart ohne Boundary.", "MIME-Boundary korrekt setzen."))
			return out, pb
		}
		mr := multipart.NewReader(strings.NewReader(string(body)), boundary)
		for {
			part, perr := mr.NextPart()
			if perr != nil {
				break
			}
			pb.PartCount++
			pbytes, _ := readLimited(part, 2*1024*1024)
			ptype, pparams, _ := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if ptype == "text/plain" {
				pb.HasTextPart = true
				pb.Text += decodeBody(part.Header, pbytes)
			}
			if ptype == "text/html" {
				pb.HasHTMLPart = true
				h := decodeBody(part.Header, pbytes)
				pb.HTML += h
				pb.Images += strings.Count(strings.ToLower(h), "<img")
			}
			if filename := pparams["name"]; filename != "" || part.FileName() != "" {
				pb.Attachments++
			}
			_ = part.Close()
		}
	} else {
		if mediatype == "text/plain" {
			pb.HasTextPart = true
			pb.Text = decodeBody(textproto.MIMEHeader(headers), body)
		}
		if mediatype == "text/html" {
			pb.HasHTMLPart = true
			pb.HTML = decodeBody(textproto.MIMEHeader(headers), body)
			pb.Images = strings.Count(strings.ToLower(pb.HTML), "<img")
		}
		pb.PartCount = 1
	}

	if pb.Text == "" && pb.HTML != "" {
		out = append(out, warn("plain_text", "Plaintext-Part", -0.8, "Kein text/plain Part gefunden.", "Einen sauberen Plaintext-Part ergänzen."))
	} else if pb.Text != "" {
		out = append(out, pass("plain_text", "Plaintext-Part", 0.1, "Plaintext-Part vorhanden.", ""))
	}

	if pb.HasTextPart && pb.HasHTMLPart {
		out = append(out, pass("multipart_alt", "Multipart Struktur", 0.2, "Text und HTML sind vorhanden.", ""))
	} else if pb.HasHTMLPart || pb.HasTextPart {
		out = append(out, info("multipart_alt", "Multipart Struktur", 0.0, "Nur ein Body-Format vorhanden.", "Multipart/alternative verbessert Kompatibilität."))
	}

	if pb.Attachments > 0 {
		out = append(out, info("attachments", "Anhänge", 0.0, fmt.Sprintf("%d Anhang/Anhänge erkannt.", pb.Attachments), "Anhänge klein und vertrauenswürdig halten."))
	}

	if pb.Images >= 4 && len(stripHTML(pb.HTML)) < 240 {
		out = append(out, warn("image_text_ratio", "Bild/Text-Verhältnis", -0.7, "Viele Bilder bei wenig Text erkannt.", "Mehr echten Text ergänzen."))
	} else {
		out = append(out, info("image_text_ratio", "Bild/Text-Verhältnis", 0.0, "Bild/Text-Verhältnis ohne grobe Auffälligkeit.", ""))
	}

	all := strings.TrimSpace(pb.Text + "\n" + stripHTML(pb.HTML))
	if all != "" {
		pb.AllText = all
	}

	if pb.Charset != "" && pb.Charset != "utf-8" && pb.Charset != "us-ascii" {
		out = append(out, warn("charset", "Charset", -0.3, fmt.Sprintf("Ungewöhnlicher Charset erkannt: %s.", pb.Charset), "Nach Möglichkeit UTF-8 verwenden."))
	} else {
		out = append(out, pass("charset", "Charset", 0.1, "Charset wirkt unauffällig.", ""))
	}

	return out, pb
}

func decodeBody(headers textproto.MIMEHeader, body []byte) string {
	enc := strings.ToLower(strings.TrimSpace(headers.Get("Content-Transfer-Encoding")))
	switch enc {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(removeCRLF(string(body)))
		if err == nil {
			return string(decoded)
		}
	}
	return string(body)
}

func removeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.ReplaceAll(s, "\n", "")
}

func stripHTML(in string) string {
	if strings.TrimSpace(in) == "" {
		return ""
	}
	node, err := html.Parse(strings.NewReader(in))
	if err != nil {
		return in
	}
	var b strings.Builder
	var walker func(*html.Node)
	walker = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteString(" ")
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walker(c)
		}
	}
	walker(node)
	return strings.TrimSpace(b.String())
}

func extractLinks(in string) []string {
	re := regexp.MustCompile(`https?://[^\s"'>)]+`)
	return re.FindAllString(in, -1)
}

func evaluateURLs(links []string) ([]model.CheckResult, []string) {
	if len(links) == 0 {
		return []model.CheckResult{info("links", "Link-Analyse", 0.0, "Keine Links erkannt.", "")}, nil
	}
	checks := []model.CheckResult{info("links", "Link-Analyse", 0.0, fmt.Sprintf("%d Links erkannt.", len(links)), "")}
	spamSignals := make([]string, 0)
	shorteners := map[string]bool{"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "is.gd": true, "ow.ly": true}
	tracking := 0
	shortCount := 0
	for _, raw := range links {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.ToLower(strings.TrimPrefix(u.Hostname(), "www."))
		if shorteners[host] {
			shortCount++
		}
		for q := range u.Query() {
			lq := strings.ToLower(q)
			if strings.HasPrefix(lq, "utm_") || strings.Contains(lq, "track") || strings.Contains(lq, "mc_eid") {
				tracking++
				break
			}
		}
	}
	if shortCount > 0 {
		checks = append(checks, warn("shortener", "URL-Shortener", -0.6, fmt.Sprintf("%d verkürzte URL(s) erkannt.", shortCount), "Direkte, vertrauenswürdige Domains verwenden."))
		spamSignals = append(spamSignals, "URL-Shortener erkannt")
	}
	if tracking > 0 {
		checks = append(checks, info("tracking_links", "Tracking-Links", 0.0, fmt.Sprintf("%d Link(s) mit Tracking-Merkmalen.", tracking), "Tracking-Parameter minimieren erhöht Vertrauen."))
	}
	return checks, spamSignals
}

func htmlHeuristics(htmlBody string) []model.CheckResult {
	if strings.TrimSpace(htmlBody) == "" {
		return []model.CheckResult{info("html", "HTML-Analyse", 0.0, "Kein HTML-Body vorhanden.", "")}
	}
	checks := make([]model.CheckResult, 0, 3)
	lower := strings.ToLower(htmlBody)
	hiddenCount := strings.Count(lower, "display:none") + strings.Count(lower, "font-size:0") + strings.Count(lower, "visibility:hidden")
	if hiddenCount > 3 {
		checks = append(checks, warn("hidden_html", "Versteckte HTML-Elemente", -0.6, "Mehrere versteckte HTML-Elemente erkannt.", "Versteckte Inhalte reduzieren."))
	} else {
		checks = append(checks, pass("hidden_html", "Versteckte HTML-Elemente", 0.1, "Keine auffällige Menge versteckter Elemente.", ""))
	}
	if _, err := html.Parse(strings.NewReader(htmlBody)); err != nil {
		checks = append(checks, warn("html_validity", "HTML-Grundvalidierung", -0.4, "HTML wirkt strukturell fehlerhaft.", "HTML-Template validieren."))
	} else {
		checks = append(checks, pass("html_validity", "HTML-Grundvalidierung", 0.1, "HTML ist parsebar.", ""))
	}
	return checks
}

func subjectHeuristics(subject string) ([]model.CheckResult, []string) {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return []model.CheckResult{warn("subject", "Betreff", -0.7, "Betreff fehlt.", "Klaren, präzisen Betreff setzen.")}, nil
	}
	checks := []model.CheckResult{pass("subject", "Betreff", 0.1, "Betreff vorhanden.", "")}
	signals := make([]string, 0)
	ex := strings.Count(subject, "!")
	if ex >= 3 {
		checks = append(checks, warn("subject_exclaim", "Betreff-Zeichenstil", -0.4, "Viele Ausrufezeichen im Betreff.", "Weniger reißerische Zeichensetzung verwenden."))
		signals = append(signals, "Betreff mit vielen Ausrufezeichen")
	}
	letters := 0
	upper := 0
	for _, r := range subject {
		if unicode.IsLetter(r) {
			letters++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	if letters > 8 && float64(upper)/float64(letters) > 0.7 {
		checks = append(checks, warn("subject_caps", "Betreff-Großschreibung", -0.5, "Betreff ist überwiegend in Großbuchstaben.", "Gemischte Schreibweise nutzen."))
		signals = append(signals, "All-caps Betreff")
	}
	return checks, signals
}

func headerHeuristics(headers mail.Header) ([]model.CheckResult, []string) {
	checks := make([]model.CheckResult, 0)
	warnings := make([]string, 0)
	dateRaw := headers.Get("Date")
	if dateRaw == "" {
		checks = append(checks, warn("date", "Date-Header", -0.6, "Date-Header fehlt.", "Date-Header korrekt setzen."))
	} else if t, err := mail.ParseDate(dateRaw); err != nil {
		checks = append(checks, warn("date", "Date-Header", -0.5, "Date-Header ist nicht parsebar.", "RFC-kompatibles Datumsformat nutzen."))
	} else {
		delta := time.Since(t)
		if delta < -2*time.Hour || delta > 14*24*time.Hour {
			checks = append(checks, warn("date_skew", "Datumsplausibilität", -0.4, "Date-Header wirkt zeitlich inkonsistent.", "Serverzeit/NTP prüfen."))
			warnings = append(warnings, "Date-Header zeitlich auffällig")
		} else {
			checks = append(checks, pass("date", "Date-Header", 0.1, "Date-Header plausibel.", ""))
		}
	}
	if headers.Get("Message-Id") == "" && headers.Get("Message-ID") == "" {
		checks = append(checks, fail("message_id", "Message-ID", -0.8, "Message-ID fehlt.", "Jede Mail mit stabiler Message-ID versenden."))
	} else {
		checks = append(checks, pass("message_id", "Message-ID", 0.1, "Message-ID vorhanden.", ""))
	}
	return checks, warnings
}

func unicodeObfuscationCheck(text string) (model.CheckResult, string) {
	if text == "" {
		return info("unicode", "Unicode/Obfuscation", 0.0, "Kein Text für Unicode-Heuristik.", ""), ""
	}
	zwCount := strings.Count(text, "\u200b") + strings.Count(text, "\u200c") + strings.Count(text, "\u2060")
	nonASCII := 0
	for _, r := range text {
		if r > unicode.MaxASCII {
			nonASCII++
		}
	}
	if zwCount > 2 {
		return warn("unicode", "Unicode/Obfuscation", -0.6, "Mehrere Zero-Width Zeichen erkannt.", "Versteckte Unicode-Zeichen entfernen."), "Zero-width obfuscation erkannt"
	}
	if nonASCII > 0 && float64(nonASCII)/float64(len([]rune(text))) > 0.6 {
		return info("unicode", "Unicode/Obfuscation", 0.0, "Hoher Unicode-Anteil erkannt (evtl. sprachbedingt).", ""), ""
	}
	return pass("unicode", "Unicode/Obfuscation", 0.1, "Keine offensichtliche Unicode-Obfuscation erkannt.", ""), ""
}

func newsletterHeuristics(headers mail.Header, body parsedBody) []model.CheckResult {
	checks := make([]model.CheckResult, 0)
	all := strings.ToLower(body.AllText)
	newsletterHint := strings.Contains(all, "unsubscribe") || strings.Contains(strings.ToLower(headers.Get("Precedence")), "bulk") || strings.TrimSpace(headers.Get("List-Id")) != ""
	if newsletterHint {
		if headers.Get("List-Unsubscribe") == "" {
			checks = append(checks, warn("list_unsub", "List-Unsubscribe", -0.7, "Newsletter-Hinweise vorhanden, aber List-Unsubscribe fehlt.", "List-Unsubscribe Header ergänzen."))
		} else {
			checks = append(checks, pass("list_unsub", "List-Unsubscribe", 0.2, "List-Unsubscribe Header vorhanden.", ""))
		}
	}

	htmlLower := strings.ToLower(body.HTML)
	if strings.Contains(htmlLower, "preheader") || strings.Contains(htmlLower, "display:none") {
		checks = append(checks, info("preheader", "Preheader-Heuristik", 0.0, "Möglicher Preheader erkannt.", ""))
	} else if body.HasHTMLPart {
		checks = append(checks, warn("preheader", "Preheader-Heuristik", -0.2, "Kein klarer Preheader erkennbar.", "Optional kurzen Preheader ergänzen."))
	}
	return checks
}

func rblHeuristics(ctx context.Context, remoteIP string, providers []string) []model.CheckResult {
	if len(providers) == 0 {
		return []model.CheckResult{info("rbl", "DNSBL/RBL", 0.0, "RBL-Prüfung aktiv, aber keine Provider konfiguriert.", "")}
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil || ip.To4() == nil {
		return []model.CheckResult{info("rbl", "DNSBL/RBL", 0.0, "RBL nur für IPv4 geprüft.", "")}
	}
	octets := strings.Split(ip.String(), ".")
	queryIP := fmt.Sprintf("%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0])
	listed := 0
	for _, p := range providers {
		name := queryIP + "." + strings.TrimSpace(p)
		ips, _ := net.DefaultResolver.LookupHost(ctx, name)
		if len(ips) > 0 {
			listed++
		}
	}
	if listed > 0 {
		return []model.CheckResult{warn("rbl", "DNSBL/RBL", -0.8, fmt.Sprintf("Absender-IP auf %d RBL(s) gelistet.", listed), "IP-Reputation prüfen und Delisting durchführen.")}
	}
	return []model.CheckResult{pass("rbl", "DNSBL/RBL", 0.1, "Keine RBL-Listings in konfigurierten Listen erkannt.", "")}
}

func spamAssassinHeuristic(ctx context.Context, hostport, raw string) model.CheckResult {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin nicht erreichbar.", "Optionalen spamd-Dienst prüfen oder Option deaktivieren.")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf("SYMBOLS SPAMC/1.5\r\nContent-length: %d\r\n\r\n%s", len(raw), raw)
	if _, err := conn.Write([]byte(req)); err != nil {
		return info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Anfrage fehlgeschlagen.", "spamd-Verbindung prüfen.")
	}

	resp, err := readLimited(conn, 64*1024)
	if err != nil {
		return info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Antwort nicht lesbar.", "spamd Antwortformat prüfen.")
	}
	lower := strings.ToLower(string(resp))
	spamLine := ""
	for _, line := range strings.Split(string(resp), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "spam:") {
			spamLine = strings.TrimSpace(line)
			break
		}
	}
	if strings.Contains(lower, "spam: true") {
		return warn("spamassassin", "SpamAssassin", -1.0, emptyFallback(spamLine, "SpamAssassin stuft Nachricht als Spam ein."), "SpamAssassin-Regeln/Symbole prüfen und Mailinhalt überarbeiten.")
	}
	if spamLine != "" {
		return pass("spamassassin", "SpamAssassin", 0.2, spamLine, "")
	}
	return info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Antwort ohne klassisches Spam-Headerformat erhalten.", "")
}

type rspamdCheckResult struct {
	Score         float64               `json:"score"`
	RequiredScore float64               `json:"required_score"`
	Action        string                `json:"action"`
	Symbols       map[string]any        `json:"symbols"`
}

func rspamdHeuristic(ctx context.Context, endpointURL, password, raw string) model.CheckResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpointURL, bytes.NewBufferString(raw))
	if err != nil {
		return info("rspamd", "Rspamd", 0.0, "Rspamd request build failed.", "Check RSPAMD_URL configuration.")
	}
	req.Header.Set("Content-Type", "message/rfc822")
	if strings.TrimSpace(password) != "" {
		req.Header.Set("Password", password)
	}

	client := &http.Client{Timeout: 6 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return info("rspamd", "Rspamd", 0.0, "Rspamd not reachable.", "Check Rspamd service availability or disable ENABLE_RSPAMD.")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return info("rspamd", "Rspamd", 0.0, "Rspamd denied access (auth).", "Set correct RSPAMD_PASSWORD or adjust controller auth.")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return info("rspamd", "Rspamd", 0.0, fmt.Sprintf("Rspamd HTTP status %d.", resp.StatusCode), "Check Rspamd controller endpoint.")
	}

	var parsed rspamdCheckResult
	if err := json.Unmarshal(body, &parsed); err != nil {
		return info("rspamd", "Rspamd", 0.0, "Rspamd response parse failed.", "Verify Rspamd endpoint returns JSON (checkv2).")
	}

	action := strings.ToLower(strings.TrimSpace(parsed.Action))
	summary := fmt.Sprintf("Rspamd action=%s score=%.2f required=%.2f symbols=%d", emptyFallback(action, "unknown"), parsed.Score, parsed.RequiredScore, len(parsed.Symbols))
	switch action {
	case "reject", "soft reject":
		return fail("rspamd", "Rspamd", -1.2, summary, "Review triggered symbols and sender/content reputation.")
	case "add header", "rewrite subject", "greylist":
		return warn("rspamd", "Rspamd", -0.6, summary, "Tune message content and auth alignment to reduce spam signals.")
	case "no action":
		return pass("rspamd", "Rspamd", 0.2, summary, "")
	default:
		if parsed.RequiredScore > 0 && parsed.Score >= parsed.RequiredScore {
			return warn("rspamd", "Rspamd", -0.6, summary, "Score is above or equal to required threshold.")
		}
		return info("rspamd", "Rspamd", 0.0, summary, "")
	}
}

func domainFromDKIM(sig string) string {
	sig = strings.ToLower(sig)
	return extractTagValue(sig, "d")
}

func extractTagValue(v, key string) string {
	for _, token := range strings.Split(v, ";") {
		token = strings.TrimSpace(token)
		if strings.HasPrefix(token, key+"=") {
			return strings.TrimSpace(strings.TrimPrefix(token, key+"="))
		}
	}
	return ""
}

func emptyFallback(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func readLimited(r interface{ Read([]byte) (int, error) }, limit int64) ([]byte, error) {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 1024), int(limit))
	var b strings.Builder
	for s.Scan() {
		line := s.Text()
		if int64(b.Len()+len(line)+1) > limit {
			break
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
