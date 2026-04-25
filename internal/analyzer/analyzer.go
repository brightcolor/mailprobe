package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
		parseCheck := fail("mime_parse", "MIME/Message Parsing", -2.0, "Rohmail konnte nicht korrekt geparst werden.", "Sende eine RFC-konforme MIME-Mail und pruefe den Mailer.")
		parseCheck.Category = "Header und Rohdaten"
		parseCheck.Severity = "high"
		parseCheck.TechnicalDetails = map[string]string{
			"remote_ip":   emptyFallback(in.Message.RemoteIP, "unknown"),
			"helo_ehlo":   emptyFallback(in.Message.HELO, "unknown"),
			"raw_bytes":   strconv.Itoa(len(in.Message.RawSource)),
			"parse_error": parseErr.Error(),
		}
		parseCheck.Explanation = "Eine RFC-konforme Message-Struktur ist Voraussetzung fuer alle weiteren Authentifizierungs-, Header- und Inhaltspruefungen. Kaputte Rohmails werden von Providern schlechter bewertet oder direkt abgelehnt."
		parseCheck.Recommendation = "Versandsoftware oder MTA so konfigurieren, dass Header und Body strikt RFC-konform erzeugt werden: gueltige Header-Zeilen, leere Zeile vor Body, korrekte CRLF-Zeilenenden und saubere MIME-Boundaries."
		report.Checks = append(report.Checks, parseCheck)
		report.Warnings = append(report.Warnings, parseErr.Error())
		report.Score += parseCheck.ScoreDelta
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
	authHeaderValues := headerValues(headers, "Authentication-Results")
	authResults := strings.ToLower(strings.Join(authHeaderValues, " ; "))

	spfResult := parseAuthResult(authResults, "spf")
	dkimResult := parseAuthResult(authResults, "dkim")
	dmarcResult := parseAuthResult(authResults, "dmarc")

	// SPF
	spfRecords := make([]string, 0)
	if envelopeDomain != "" {
		recs, _ := net.DefaultResolver.LookupTXT(ctx, envelopeDomain)
		for _, rec := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
				spfRecords = append(spfRecords, strings.TrimSpace(rec))
			}
		}
	}
	switch spfResult {
	case "pass":
		report.Checks = append(report.Checks, pass("spf", "SPF", 0.4, "SPF laut Authentication-Results bestanden.", ""))
	case "fail", "softfail":
		report.Checks = append(report.Checks, fail("spf", "SPF", -1.4, fmt.Sprintf("SPF meldet %s.", spfResult), "Envelope-From-Domain und SPF-Record korrigieren."))
	default:
		if len(spfRecords) > 0 {
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
	dmarcRecords := make([]string, 0)
	dmarcPolicy := ""
	if fromDomain != "" {
		dmarcTXT, _ := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+fromDomain)
		for _, rec := range dmarcTXT {
			lr := strings.ToLower(rec)
			if strings.HasPrefix(lr, "v=dmarc1") {
				dmarcRecords = append(dmarcRecords, strings.TrimSpace(rec))
				dmarcPolicy = extractTagValue(lr, "p")
			}
		}
	}
	alignedSPF := envelopeDomain != "" && fromDomain != "" && (envelopeDomain == fromDomain || strings.HasSuffix(envelopeDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+envelopeDomain))
	dkimDomain := domainFromDKIM(headers.Get("DKIM-Signature"))
	alignedDKIM := dkimDomain != "" && fromDomain != "" && (dkimDomain == fromDomain || strings.HasSuffix(dkimDomain, "."+fromDomain))

	if dmarcResult == "pass" {
		report.Checks = append(report.Checks, pass("dmarc", "DMARC", 0.4, "DMARC laut Authentication-Results bestanden.", ""))
	} else if len(dmarcRecords) > 0 {
		if alignedSPF || alignedDKIM {
			report.Checks = append(report.Checks, warn("dmarc", "DMARC", -0.3, fmt.Sprintf("DMARC-Record vorhanden (p=%s), Alignment teilweise plausibel, aber kein eindeutiges pass im Header.", emptyFallback(dmarcPolicy, "none")), "DMARC-Alignment und Reporting prüfen."))
		} else {
			report.Checks = append(report.Checks, fail("dmarc", "DMARC", -1.0, fmt.Sprintf("DMARC-Record vorhanden (p=%s), aber kein SPF/DKIM-Alignment.", emptyFallback(dmarcPolicy, "none")), "From-Domain-Alignment mit SPF oder DKIM sicherstellen."))
		}
	} else {
		report.Checks = append(report.Checks, fail("dmarc", "DMARC", -1.2, "Kein DMARC-Record für die From-Domain gefunden.", "_dmarc.<domain> TXT mit v=DMARC1 veröffentlichen."))
	}

	primaryDomain := firstNonEmpty(fromDomain, envelopeDomain)
	report.Checks = append(report.Checks, mxRecordCheck(ctx, primaryDomain))
	report.Checks = append(report.Checks, addressRecordCheck(ctx, primaryDomain))
	report.Checks = append(report.Checks, spfAlignmentCheck(fromDomain, envelopeDomain, spfResult, alignedSPF))
	report.Checks = append(report.Checks, dkimAlignmentCheck(fromDomain, dkimDomain, dkimResult, alignedDKIM))
	report.Checks = append(report.Checks, dmarcAlignmentCheck(fromDomain, spfResult, dkimResult, alignedSPF, alignedDKIM))

	// PTR
	ptrCheck := ptrPlausibility(ctx, in.Message.RemoteIP, in.Message.HELO)
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

	if replyTo := strings.TrimSpace(headers.Get("Reply-To")); replyTo == "" {
		report.Checks = append(report.Checks, info("reply_to", "Reply-To", 0.0, "Kein Reply-To-Header gesetzt.", "Wenn Antworten an eine andere Adresse gehen sollen, Reply-To bewusst setzen."))
	} else {
		report.Checks = append(report.Checks, pass("reply_to", "Reply-To", 0.0, "Reply-To-Header ist vorhanden.", ""))
	}

	receivedLines := headerValues(headers, "Received")
	if len(receivedLines) == 0 {
		report.Checks = append(report.Checks, fail("received_chain", "Received-Header-Kette", -1.2, "Keine Received-Header vorhanden.", "Transportpfad muss Received-Header enthalten."))
	} else {
		report.Checks = append(report.Checks, info("received_chain", "Received-Header-Kette", 0.0, fmt.Sprintf("%d Received-Header erkannt.", len(receivedLines)), ""))
	}
	report.Checks = append(report.Checks, tlsTransportCheck(receivedLines))

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

	enrichCtx := checkContext{
		Message:        in.Message,
		SMTPDomain:     in.SMTPDomain,
		Headers:        headers,
		FromDomain:     fromDomain,
		EnvelopeDomain: envelopeDomain,
		ReturnPath:     headers.Get("Return-Path"),
		ReturnDomain:   returnPathDomain,
		AuthHeaders:    authHeaderValues,
		SPFResult:      spfResult,
		SPFRecords:     spfRecords,
		DKIMResult:     dkimResult,
		DKIMDomain:     dkimDomain,
		DMARCResult:    dmarcResult,
		DMARCRecords:   dmarcRecords,
		DMARCPolicy:    dmarcPolicy,
		AlignedSPF:     alignedSPF,
		AlignedDKIM:    alignedDKIM,
		ReceivedLines:  receivedLines,
		ParsedBody:     parsedBody,
		Links:          report.Links,
	}
	for i := range report.Checks {
		report.Checks[i] = enrichCheckResult(report.Checks[i], enrichCtx)
	}

	for _, c := range report.Checks {
		report.Score += c.ScoreDelta
		if c.Status == "fail" || c.Status == "warn" {
			if c.Recommendation != "" {
				report.Suggestions = append(report.Suggestions, c.Recommendation)
			} else if c.Suggestion != "" {
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

type checkContext struct {
	Message        model.Message
	SMTPDomain     string
	Headers        mail.Header
	FromDomain     string
	EnvelopeDomain string
	ReturnPath     string
	ReturnDomain   string
	AuthHeaders    []string
	SPFResult      string
	SPFRecords     []string
	DKIMResult     string
	DKIMDomain     string
	DMARCResult    string
	DMARCRecords   []string
	DMARCPolicy    string
	AlignedSPF     bool
	AlignedDKIM    bool
	ReceivedLines  []string
	ParsedBody     parsedBody
	Links          []string
}

func mxRecordCheck(ctx context.Context, domain string) model.CheckResult {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return info("mx_records", "MX-Records", 0.0, "Keine Domain fuer den MX-Check ermittelbar.", "Header-From oder Envelope-From sauber setzen.")
	}
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return warn("mx_records", "MX-Records", -0.3, fmt.Sprintf("Fuer %s wurde kein MX-Record gefunden.", domain), fmt.Sprintf("Falls %s E-Mails empfangen soll, in der DNS-Zone einen MX-Record setzen, z. B. %s. MX 10 mail.%s.", domain, domain, domain))
	}
	values := make([]string, 0, len(mxs))
	for _, mx := range mxs {
		values = append(values, fmt.Sprintf("%s MX %d %s", domain, mx.Pref, strings.TrimSuffix(mx.Host, ".")))
	}
	return withDetails(pass("mx_records", "MX-Records", 0.1, fmt.Sprintf("Fuer %s sind %d MX-Record(s) vorhanden.", domain, len(mxs)), ""), map[string]string{
		"domain":     domain,
		"mx_records": strings.Join(values, "\n"),
	})
}

func addressRecordCheck(ctx context.Context, domain string) model.CheckResult {
	domain = strings.TrimSpace(strings.TrimSuffix(domain, "."))
	if domain == "" {
		return info("address_records", "A/AAAA-Records", 0.0, "Keine Domain fuer A/AAAA-Check ermittelbar.", "Header-From oder Envelope-From sauber setzen.")
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
	if err != nil || len(ips) == 0 {
		return warn("address_records", "A/AAAA-Records", -0.3, fmt.Sprintf("%s loest nicht auf A/AAAA auf.", domain), fmt.Sprintf("In der DNS-Zone A/AAAA-Records fuer %s setzen, wenn diese Domain direkt als Hostname verwendet wird.", domain))
	}
	values := make([]string, 0, len(ips))
	for _, ip := range ips {
		values = append(values, ip.IP.String())
	}
	return withDetails(pass("address_records", "A/AAAA-Records", 0.1, fmt.Sprintf("%s loest auf %d Adresse(n) auf.", domain, len(ips)), ""), map[string]string{
		"domain":         domain,
		"a_aaaa_records": strings.Join(values, "\n"),
	})
}

func spfAlignmentCheck(fromDomain, envelopeDomain, spfResult string, aligned bool) model.CheckResult {
	if fromDomain == "" || envelopeDomain == "" {
		return warn("spf_alignment", "SPF Alignment", -0.4, "SPF-Alignment konnte nicht vollstaendig bewertet werden.", "Header-From und Envelope-From mit klaren Domains setzen.")
	}
	if spfResult == "pass" && aligned {
		return pass("spf_alignment", "SPF Alignment", 0.2, "SPF besteht und ist mit der sichtbaren From-Domain aligned.", "")
	}
	if spfResult == "pass" {
		return warn("spf_alignment", "SPF Alignment", -0.4, "SPF besteht, ist aber nicht mit der sichtbaren From-Domain aligned.", "Envelope-From/Bounce-Domain auf eine Subdomain der sichtbaren From-Domain umstellen oder DKIM Alignment sicherstellen.")
	}
	return warn("spf_alignment", "SPF Alignment", -0.5, "SPF liefert kein pass; dadurch kann SPF nicht fuer DMARC-Alignment zaehlen.", "SPF fuer die Envelope-From-Domain korrigieren.")
}

func dkimAlignmentCheck(fromDomain, dkimDomain, dkimResult string, aligned bool) model.CheckResult {
	if dkimResult != "pass" {
		return warn("dkim_alignment", "DKIM Alignment", -0.5, "DKIM liefert kein pass; DKIM kann nicht fuer DMARC-Alignment zaehlen.", "DKIM-Signatur fuer die sichtbare From-Domain oder eine passende Subdomain aktivieren.")
	}
	if aligned {
		return pass("dkim_alignment", "DKIM Alignment", 0.2, "DKIM besteht und ist mit der sichtbaren From-Domain aligned.", "")
	}
	return warn("dkim_alignment", "DKIM Alignment", -0.4, "DKIM besteht, aber die Signaturdomain passt nicht zur sichtbaren From-Domain.", "DKIM d= auf die From-Domain oder eine erlaubte Subdomain setzen.")
}

func dmarcAlignmentCheck(fromDomain, spfResult, dkimResult string, alignedSPF, alignedDKIM bool) model.CheckResult {
	if fromDomain == "" {
		return warn("dmarc_alignment", "DMARC Alignment", -0.5, "DMARC-Alignment konnte ohne From-Domain nicht bewertet werden.", "Einen gueltigen From-Header mit Domain setzen.")
	}
	if (spfResult == "pass" && alignedSPF) || (dkimResult == "pass" && alignedDKIM) {
		return pass("dmarc_alignment", "DMARC Alignment", 0.2, "Mindestens SPF oder DKIM ist aligned und kann DMARC tragen.", "")
	}
	return fail("dmarc_alignment", "DMARC Alignment", -0.9, "Weder SPF noch DKIM sind aligned; DMARC kann dadurch scheitern.", "SPF oder DKIM so konfigurieren, dass die authentifizierte Domain zur Header-From-Domain passt.")
}

func tlsTransportCheck(received []string) model.CheckResult {
	raw := strings.ToLower(strings.Join(received, "\n"))
	if strings.Contains(raw, "tls") || strings.Contains(raw, "esmtps") || strings.Contains(raw, "cipher") {
		return pass("tls_transport", "TLS Transport", 0.1, "Received-Header enthalten Hinweise auf verschluesselten Transport.", "")
	}
	return info("tls_transport", "TLS Transport", 0.0, "Aus den Received-Headern ist kein TLS-Transport eindeutig erkennbar.", "TLS fuer SMTP aktivieren und sicherstellen, dass vorgelagerte MTAs TLS-Informationen in Received-Headern dokumentieren.")
}

func withDetails(c model.CheckResult, details map[string]string) model.CheckResult {
	c.TechnicalDetails = details
	return c
}

func enrichCheckResult(c model.CheckResult, ctx checkContext) model.CheckResult {
	c.Category = checkCategory(c.ID)
	c.Severity = checkSeverity(c.Status)
	base := baseDetails(ctx)
	if c.TechnicalDetails == nil {
		c.TechnicalDetails = base
	} else {
		for key, value := range base {
			if _, ok := c.TechnicalDetails[key]; !ok {
				c.TechnicalDetails[key] = value
			}
		}
	}
	addHeaderDetail(c.TechnicalDetails, "from", ctx.Headers.Get("From"))
	addHeaderDetail(c.TechnicalDetails, "subject", ctx.Headers.Get("Subject"))
	addCheckSpecificDetails(c.TechnicalDetails, c.ID, ctx)
	switch c.ID {
	case "spf":
		c.Name = "SPF fuer " + emptyFallback(ctx.EnvelopeDomain, "Envelope-From")
		c.TechnicalDetails["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		c.TechnicalDetails["spf_records"] = joinOrNone(ctx.SPFRecords)
		c.Explanation = "SPF legt fest, welche Server im Namen der Envelope-From-Domain senden duerfen. Gmail, Outlook und Yahoo bewerten fehlende oder fehlschlagende SPF-Ergebnisse deutlich negativ, besonders wenn DMARC aktiv ist."
		c.Recommendation = spfRecommendation(ctx)
	case "dkim":
		c.TechnicalDetails["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		c.TechnicalDetails["dkim_domain"] = emptyFallback(ctx.DKIMDomain, "none")
		c.TechnicalDetails["dkim_signature"] = emptyFallback(ctx.Headers.Get("DKIM-Signature"), "none")
		c.Explanation = "DKIM signiert die Nachricht kryptografisch. Provider wie Gmail, Outlook, Yahoo und Apple Mail nutzen DKIM stark, um Manipulationen und spoofing zu erkennen."
		c.Recommendation = dkimRecommendation(ctx)
	case "dmarc":
		c.TechnicalDetails["dmarc_result"] = emptyFallback(ctx.DMARCResult, "none")
		c.TechnicalDetails["dmarc_records"] = joinOrNone(ctx.DMARCRecords)
		c.TechnicalDetails["policy"] = emptyFallback(ctx.DMARCPolicy, "none")
		c.Explanation = "DMARC verbindet SPF/DKIM mit der sichtbaren From-Domain. Moderne Provider erwarten fuer serioese Versanddomains mindestens eine DMARC-Policy."
		c.Recommendation = dmarcRecommendation(ctx)
	case "ptr":
		c.TechnicalDetails["expected"] = fmt.Sprintf("IP %s -> PTR %s -> A/AAAA %s", emptyFallback(ctx.Message.RemoteIP, "unknown"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.RemoteIP, "sender-ip"))
		c.Explanation = "Reverse DNS zeigt, welcher Hostname zu einer sendenden IP gehoert. Viele Provider lehnen Server ohne plausiblen PTR ab oder werten sie ab."
		c.Recommendation = fmt.Sprintf("Beim Server- oder IP-Provider den PTR der IP %s auf den Mailserver-Hostnamen setzen. Empfohlen: PTR/rDNS %s und HELO/EHLO %s. Zusaetzlich muss dieser Hostname per A/AAAA wieder auf die sendende IP zeigen.", emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.Message.HELO, "mail.example.tld"), emptyFallback(ctx.Message.HELO, "mail.example.tld"))
	case "helo":
		c.Explanation = "HELO/EHLO ist der Name, mit dem sich der sendende Mailserver beim Empfaenger meldet. Er sollte ein stabiler FQDN sein und zum PTR passen."
		c.Recommendation = fmt.Sprintf("Im Mailserver den SMTP-Hostname auf einen FQDN setzen, z. B. Postfix `myhostname = %s`. Der gleiche Name sollte im PTR/rDNS der IP stehen.", emptyFallback(ctx.Message.HELO, "mail.example.tld"))
	case "mx_records":
		c.Explanation = "MX-Records definieren, welcher Mailserver E-Mails fuer eine Domain annimmt. Fuer reine Versanddomains ist das nicht immer zwingend, verbessert aber die technische Plausibilitaet."
		if c.Recommendation == "" {
			c.Recommendation = fmt.Sprintf("Falls %s E-Mails empfangen soll, in der DNS-Zone einen gueltigen MX-Record pflegen.", emptyFallback(ctx.FromDomain, ctx.EnvelopeDomain))
		}
	case "address_records":
		c.Explanation = "A/AAAA-Records zeigen, auf welche IPs eine Domain zeigt. HELO-, MX- und DKIM/DMARC-nahe Hostnamen sollten sauber aufloesen."
		if c.Recommendation == "" {
			c.Recommendation = "DNS-Zone pruefen und fuer verwendete Hostnamen passende A/AAAA-Records setzen."
		}
	case "spamassassin":
		c.Explanation = "SpamAssassin bewertet viele Inhalts-, Header- und Reputationssignale. Es ist kein globaler Standard, aber ein guter Hinweis auf klassische Spam-Muster."
		if c.Recommendation == "" {
			c.Recommendation = "Die ausgegebenen SpamAssassin-Regeln priorisieren und zuerst Authentifizierung, Betreff, Links und HTML-Struktur bereinigen."
		}
	case "rbl":
		c.Explanation = "RBLs listen IPs mit Spam-, Abuse- oder Botnet-Historie. Gmail, Outlook und andere Provider nutzen eigene Systeme, reagieren aber ebenfalls empfindlich auf IP-Reputation."
		if c.Recommendation == "" {
			c.Recommendation = fmt.Sprintf("Falls gelistet: Ursache abstellen, Versand stoppen, Logs pruefen und anschliessend Delisting beim jeweiligen RBL-Anbieter fuer IP %s beantragen.", emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"))
		}
	default:
		c.Explanation = defaultExplanation(c.ID)
		if c.Recommendation == "" {
			c.Recommendation = defaultRecommendation(c, ctx)
		}
	}
	if c.Recommendation == "" {
		c.Recommendation = c.Suggestion
	}
	return c
}

func baseDetails(ctx checkContext) map[string]string {
	return map[string]string{
		"from_domain":     emptyFallback(ctx.FromDomain, "none"),
		"envelope_domain": emptyFallback(ctx.EnvelopeDomain, "none"),
		"remote_ip":       emptyFallback(ctx.Message.RemoteIP, "unknown"),
		"helo_ehlo":       emptyFallback(ctx.Message.HELO, "unknown"),
		"return_path":     emptyFallback(ctx.ReturnPath, "none"),
		"auth_results":    joinOrNone(ctx.AuthHeaders),
	}
}

func addHeaderDetail(details map[string]string, key, value string) {
	if strings.TrimSpace(value) != "" {
		details["header_"+key] = strings.TrimSpace(value)
	}
}

func addCheckSpecificDetails(details map[string]string, id string, ctx checkContext) {
	body := ctx.ParsedBody
	switch id {
	case "from_alignment":
		details["header_from_domain"] = emptyFallback(ctx.FromDomain, "none")
		details["envelope_from_domain"] = emptyFallback(ctx.EnvelopeDomain, "none")
	case "return_path":
		details["return_path_domain"] = emptyFallback(ctx.ReturnDomain, "none")
	case "reply_to":
		details["reply_to"] = emptyFallback(ctx.Headers.Get("Reply-To"), "none")
	case "spf_alignment":
		details["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		details["spf_aligned"] = strconv.FormatBool(ctx.AlignedSPF)
	case "dkim_alignment":
		details["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		details["dkim_domain"] = emptyFallback(ctx.DKIMDomain, "none")
		details["dkim_aligned"] = strconv.FormatBool(ctx.AlignedDKIM)
	case "dmarc_alignment":
		details["spf_result"] = emptyFallback(ctx.SPFResult, "none")
		details["dkim_result"] = emptyFallback(ctx.DKIMResult, "none")
		details["spf_aligned"] = strconv.FormatBool(ctx.AlignedSPF)
		details["dkim_aligned"] = strconv.FormatBool(ctx.AlignedDKIM)
	case "received_chain", "tls_transport":
		details["received_count"] = strconv.Itoa(len(ctx.ReceivedLines))
		details["received_headers"] = joinOrNone(ctx.ReceivedLines)
	case "arc":
		details["arc_seal"] = emptyFallback(ctx.Headers.Get("ARC-Seal"), "none")
		details["arc_message_signature"] = emptyFallback(ctx.Headers.Get("ARC-Message-Signature"), "none")
	case "mime_ct", "mime_boundary", "multipart_alt", "plain_text", "attachments", "image_text_ratio", "charset":
		addBodyDetails(details, ctx)
	case "links", "shortener", "tracking_links":
		details["link_count"] = strconv.Itoa(len(ctx.Links))
		details["links"] = joinOrNone(ctx.Links)
	case "html", "hidden_html", "html_validity":
		addBodyDetails(details, ctx)
		details["html_chars"] = strconv.Itoa(len([]rune(body.HTML)))
	case "subject", "subject_exclaim", "subject_caps":
		subject := ctx.Headers.Get("Subject")
		details["subject"] = emptyFallback(subject, "none")
		details["subject_chars"] = strconv.Itoa(len([]rune(subject)))
		details["exclamation_count"] = strconv.Itoa(strings.Count(subject, "!"))
	case "date", "date_skew":
		details["date_header"] = emptyFallback(ctx.Headers.Get("Date"), "none")
	case "message_id":
		details["message_id"] = firstNonEmpty(ctx.Headers.Get("Message-ID"), ctx.Headers.Get("Message-Id"), "none")
	case "list_unsub":
		details["list_unsubscribe"] = emptyFallback(ctx.Headers.Get("List-Unsubscribe"), "none")
		details["list_id"] = emptyFallback(ctx.Headers.Get("List-ID"), "none")
		details["precedence"] = emptyFallback(ctx.Headers.Get("Precedence"), "none")
	case "preheader":
		addBodyDetails(details, ctx)
	case "unicode":
		details["text_chars"] = strconv.Itoa(len([]rune(body.AllText)))
	}
}

func addBodyDetails(details map[string]string, ctx checkContext) {
	body := ctx.ParsedBody
	details["content_type"] = emptyFallback(ctx.Headers.Get("Content-Type"), "none")
	details["content_transfer_encoding"] = emptyFallback(ctx.Headers.Get("Content-Transfer-Encoding"), "none")
	details["part_count"] = strconv.Itoa(body.PartCount)
	details["has_text_part"] = strconv.FormatBool(body.HasTextPart)
	details["has_html_part"] = strconv.FormatBool(body.HasHTMLPart)
	details["text_chars"] = strconv.Itoa(len([]rune(body.Text)))
	details["html_chars"] = strconv.Itoa(len([]rune(body.HTML)))
	details["attachment_count"] = strconv.Itoa(body.Attachments)
	details["image_count"] = strconv.Itoa(body.Images)
	details["charset"] = emptyFallback(body.Charset, "none")
}

func checkCategory(id string) string {
	switch id {
	case "spf", "dkim", "dmarc", "spf_alignment", "dkim_alignment", "dmarc_alignment", "from_alignment", "return_path", "reply_to":
		return "Authentifizierung"
	case "ptr", "helo", "mx_records", "address_records", "tls_transport", "received_chain", "rbl":
		return "DNS und Infrastruktur"
	case "spamassassin", "rspamd":
		return "Spamfilter"
	case "mime_ct", "mime_boundary", "plain_text", "multipart_alt", "attachments", "image_text_ratio", "charset", "links", "shortener", "tracking_links", "html", "hidden_html", "html_validity", "subject", "subject_exclaim", "subject_caps", "unicode", "list_unsub", "preheader":
		return "Format und Inhalt"
	default:
		return "Header und Rohdaten"
	}
}

func checkSeverity(status string) string {
	switch status {
	case "fail":
		return "high"
	case "warn":
		return "medium"
	case "pass":
		return "low"
	default:
		return "info"
	}
}

func defaultExplanation(id string) string {
	switch id {
	case "from_alignment", "spf_alignment", "dkim_alignment", "dmarc_alignment":
		return "Alignment prueft, ob technische Authentifizierung und sichtbare From-Domain zusammenpassen. Gmail, Outlook, Yahoo und Apple Mail gewichten das stark, weil damit Spoofing und Phishing erkannt werden."
	case "return_path":
		return "Return-Path ist die Bounce-Adresse, die der empfangende Server aus dem SMTP Envelope ableitet. Sie sollte technisch zur Versanddomain passen und fuer SPF/DMARC nachvollziehbar sein."
	case "mime_ct", "mime_boundary", "multipart_alt":
		return "MIME beschreibt den Aufbau der Nachricht. Fehlerhafte MIME-Strukturen fuehren dazu, dass Clients Inhalte falsch darstellen oder Spamfilter die Mail abwerten."
	case "plain_text":
		return "Ein Plaintext-Part verbessert Kompatibilitaet und wirkt fuer Spamfilter natuerlicher als reine HTML-Mails."
	case "attachments":
		return "Anhaenge erhoehen Risiko und Groesse der Mail. Einige Provider pruefen Dateityp, Signaturen und Reputation besonders streng."
	case "image_text_ratio":
		return "Mails mit vielen Bildern und wenig Text wirken oft wie Werbe- oder Phishing-Mails und werden haeufig schlechter bewertet."
	case "links", "shortener", "tracking_links":
		return "Links werden von Mailprovidern intensiv geprueft. Kurzlinks, Weiterleitungen und aggressive Tracking-Parameter koennen Vertrauen reduzieren."
	case "html", "hidden_html", "html_validity":
		return "HTML wird von Mailclients restriktiv gerendert und von Spamfiltern auf versteckte Inhalte, Phishing-Muster und kaputte Struktur geprueft."
	case "subject", "subject_exclaim", "subject_caps":
		return "Der Betreff ist ein starkes Nutzer- und Spamfilter-Signal. Reisserische Zeichen, reine Grossschreibung oder fehlender Kontext verschlechtern die Einstufung."
	case "message_id":
		return "Eine stabile Message-ID ist ein RFC-Basismerkmal und hilft bei Threading, Duplikaterkennung und Reputation."
	case "date", "date_skew":
		return "Der Date-Header sollte plausibel zur Versandzeit passen. Starke Abweichungen wirken wie fehlerhafte Serverzeit oder manipulierte Nachrichten."
	case "tls_transport":
		return "TLS schuetzt den Transport zwischen Mailservern. Viele Provider erwarten heute STARTTLS-Unterstuetzung."
	case "reply_to":
		return "Reply-To steuert, wohin Antworten gehen. Abweichungen zur From-Adresse koennen legitim sein, sollten aber bewusst gesetzt sein."
	case "list_unsub", "preheader":
		return "Newsletter-Provider und grosse Mailboxanbieter erwarten klare Abmelde- und Vorschau-Signale. Gmail und Yahoo bewerten List-Unsubscribe fuer Bulk-Mail besonders stark."
	case "unicode":
		return "Unicode ist normal fuer viele Sprachen, aber Zero-Width-Zeichen oder obfuskierte Zeichenmischungen werden haeufig fuer Spam und Phishing genutzt."
	case "received_chain":
		return "Received-Header dokumentieren den Transportweg. Fehlende oder unplausible Header erschweren die technische Bewertung durch empfangende Systeme."
	default:
		return "Dieser Check bewertet ein technisches Signal, das Mailprovider fuer Zustellbarkeit, Missbrauchserkennung oder Nutzervertrauen heranziehen."
	}
}

func defaultRecommendation(c model.CheckResult, ctx checkContext) string {
	if c.Suggestion != "" {
		return c.Suggestion
	}
	switch c.ID {
	case "from_alignment":
		return fmt.Sprintf("Envelope-From/Bounce-Domain und sichtbare From-Domain angleichen. Aktuell: Header-From `%s`, Envelope-From-Domain `%s`. Empfehlenswert ist z. B. Bounce-Adresse `bounce@%s` oder eine Subdomain wie `bounce.%s`, die per SPF autorisiert ist.", emptyFallback(ctx.Headers.Get("From"), "none"), emptyFallback(ctx.EnvelopeDomain, "none"), emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.FromDomain, "example.org"))
	case "return_path":
		return fmt.Sprintf("Im Versand-MTA oder ESP eine gueltige Envelope-From/Bounce-Adresse setzen. Beispiel fuer die DNS-/MTA-Konfiguration: `bounce@%s` mit SPF-Record fuer die sendende IP %s.", emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.Message.RemoteIP, "203.0.113.10"))
	case "reply_to":
		return "Wenn Antworten an eine andere Adresse gehen sollen, Reply-To bewusst setzen, z. B. `Reply-To: support@example.org`. Wenn nicht, Reply-To weglassen oder zur sichtbaren From-Domain passend halten."
	case "spf_alignment":
		return fmt.Sprintf("SPF fuer die Envelope-From-Domain `%s` so konfigurieren, dass die sendende IP %s erlaubt ist, und die Bounce-Domain als gleiche Domain oder Subdomain von `%s` verwenden.", emptyFallback(ctx.EnvelopeDomain, "none"), emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), emptyFallback(ctx.FromDomain, "example.org"))
	case "dkim_alignment":
		return fmt.Sprintf("DKIM mit einer Domain signieren, die zur sichtbaren From-Domain passt. Beispiel: `d=%s` oder eine erlaubte Subdomain; DNS-Record unter `selector._domainkey.%s` setzen.", emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.FromDomain, "example.org"))
	case "dmarc_alignment":
		return fmt.Sprintf("Mindestens SPF oder DKIM muss aligned bestehen. Praktisch: DKIM-Signatur mit `d=%s` aktivieren und SPF fuer `%s` korrigieren; DMARC-Record unter `_dmarc.%s` pflegen.", emptyFallback(ctx.FromDomain, "example.org"), emptyFallback(ctx.EnvelopeDomain, "example.org"), emptyFallback(ctx.FromDomain, "example.org"))
	case "received_chain":
		return "Der empfangende SMTP-Server sollte mindestens einen Received-Header schreiben. Wenn vorgeschaltete Relays Header entfernen, deren Konfiguration pruefen und RFC-konforme Received-Zeilen erhalten."
	case "message_id":
		return "Mailserver oder Versandsoftware so konfigurieren, dass jede Nachricht eine eindeutige Message-ID erzeugt, z. B. `<unique-id@" + emptyFallback(ctx.FromDomain, "example.org") + ">`."
	case "mime_ct", "mime_boundary", "multipart_alt":
		return "Das Template als RFC-konforme MIME-Mail erzeugen. Fuer HTML-Mails empfohlen: `multipart/alternative` mit `text/plain` und `text/html`, sauberer Boundary und `Content-Type: multipart/alternative; boundary=...`."
	case "plain_text":
		return "Im Versandtemplate einen text/plain-Part zusaetzlich zum HTML-Part ausliefern."
	case "attachments":
		return "Anhaenge nur verwenden, wenn noetig. Grosse Dateien extern verlinken, Dateinamen klar halten und riskante Dateitypen wie ausfuehrbare Dateien vermeiden."
	case "image_text_ratio":
		return "Mehr echten Text in die Mail aufnehmen und Bild-only-Layouts vermeiden. Richtwert: zentrale Aussage als Text ausgeben, Bilder mit Alt-Text versehen und nicht mehr als wenige Hero-/Produktbilder verwenden."
	case "charset":
		return "UTF-8 als Charset verwenden und Content-Type korrekt setzen, z. B. `Content-Type: text/html; charset=UTF-8`."
	case "links":
		return "Nur notwendige Links verwenden und sichtbare Link-Domain, Ziel-Domain und Absenderdomain plausibel zusammenhalten. Kritische Links mit der eigenen Domain oder einer sauber eingerichteten Tracking-Domain ausliefern."
	case "shortener":
		return "URL-Shortener entfernen. Stattdessen direkte HTTPS-URLs oder eine eigene Tracking-Domain mit passendem CNAME/A-Record und TLS verwenden."
	case "tracking_links":
		return "Tracking-Parameter reduzieren. Wenn Tracking notwendig ist, eine eigene Subdomain wie `click." + emptyFallback(ctx.FromDomain, "example.org") + "` verwenden und diese sauber per DNS/TLS konfigurieren."
	case "html", "hidden_html", "html_validity":
		return "HTML-Template validieren, versteckte Elemente minimieren und kritische Inhalte nicht per `display:none`, `font-size:0` oder komplexem CSS verstecken. Lange CSS-Blöcke und kaputte Tags bereinigen."
	case "subject":
		return "Einen konkreten, normalen Betreff setzen, der Inhalt und Absender widerspiegelt. Beispiel: `Ihre Buchungsbestätigung fuer Veranstaltung XY` statt leerer oder generischer Betreffzeile."
	case "subject_exclaim", "subject_caps":
		return "Betreff normalisieren: wenige Satzzeichen, keine durchgehende Grossschreibung, keine aggressiven Triggerwoerter. Beispiel: `Aktualisierung zu Ihrer Bestellung`."
	case "date", "date_skew":
		return "Serverzeit per NTP synchronisieren und Date-Header vom MTA korrekt erzeugen lassen. Bei Postfix/Exim keine manuell manipulierten Date-Header aus der Anwendung erzwingen."
	case "tls_transport":
		return "STARTTLS am ausgehenden MTA aktivieren und Zertifikat/Hostname pruefen."
	case "list_unsub":
		return "Fuer Newsletter einen RFC-konformen Header setzen, z. B. `List-Unsubscribe: <mailto:unsubscribe@" + emptyFallback(ctx.FromDomain, "example.org") + ">, <https://" + emptyFallback(ctx.FromDomain, "example.org") + "/unsubscribe/...>` und optional `List-Unsubscribe-Post: List-Unsubscribe=One-Click`."
	case "preheader":
		return "Im HTML-Template einen kurzen Preheader direkt am Anfang des Body platzieren. Beispiel: ein 80-120 Zeichen langer Vorschautext, visuell dezent versteckt, aber nicht missbraeuchlich obfuskiert."
	case "unicode":
		return "Zero-Width-Zeichen und unnoetige Unicode-Obfuskation aus Betreff und Body entfernen. Normale Sonderzeichen fuer Sprache sind ok; versteckte Zeichen sollten vermieden werden."
	default:
		return "Den genannten Wert im Mailserver, DNS oder Versandtemplate korrigieren und danach erneut testen."
	}
}

func spfRecommendation(ctx checkContext) string {
	domain := emptyFallback(ctx.EnvelopeDomain, "example.org")
	if len(ctx.SPFRecords) == 0 {
		return fmt.Sprintf("In der DNS-Zone der Envelope-From-Domain einen SPF-TXT-Record setzen. Beispiel: `%s. TXT \"v=spf1 ip4:%s -all\"`. Wenn ueber Dienstleister gesendet wird, dessen include-Mechanismus verwenden.", domain, emptyFallback(ctx.Message.RemoteIP, "203.0.113.10"))
	}
	return fmt.Sprintf("SPF-Record fuer %s pruefen und sicherstellen, dass die sendende IP %s oder der verwendete Versanddienst erlaubt ist. Aktuelle Records: %s", domain, emptyFallback(ctx.Message.RemoteIP, "<sender-ip>"), strings.Join(ctx.SPFRecords, " | "))
}

func dkimRecommendation(ctx checkContext) string {
	domain := emptyFallback(ctx.FromDomain, "example.org")
	return fmt.Sprintf("DKIM im ausgehenden MTA oder Versanddienst aktivieren. In der DNS-Zone einen Selector-TXT-Record setzen, z. B. `selector1._domainkey.%s. TXT \"v=DKIM1; k=rsa; p=<public-key>\"`, und mit `d=%s` signieren.", domain, domain)
}

func dmarcRecommendation(ctx checkContext) string {
	domain := emptyFallback(ctx.FromDomain, "example.org")
	if len(ctx.DMARCRecords) == 0 {
		return fmt.Sprintf("In der DNS-Zone einen DMARC-Record setzen. Einstieg: `_dmarc.%s. TXT \"v=DMARC1; p=none; rua=mailto:dmarc@%s\"`. Nach Stabilisierung auf `quarantine` oder `reject` erhoehen.", domain, domain)
	}
	return fmt.Sprintf("DMARC fuer %s pruefen: SPF oder DKIM muss aligned bestehen. Aktuelle Policy: %s.", domain, emptyFallback(ctx.DMARCPolicy, "none"))
}

func joinOrNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, "\n")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
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
	re := regexp.MustCompile(`(?:^|[;\s])` + regexp.QuoteMeta(key) + `=([a-zA-Z]+)`)
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}
	return strings.ToLower(m[1])
}

func headerValues(h mail.Header, key string) []string {
	k := textproto.CanonicalMIMEHeaderKey(key)
	v, ok := h[k]
	if !ok {
		return nil
	}
	out := make([]string, len(v))
	copy(out, v)
	return out
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

func ptrPlausibility(ctx context.Context, ip, helo string) model.CheckResult {
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
			hostMatchesHELO := strings.EqualFold(host, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(helo)), "."))
			if helo != "" && !hostMatchesHELO {
				return warn("ptr", "PTR/rDNS", -0.4, "PTR und Forward DNS sind konsistent, passen aber nicht zum HELO/EHLO.", "PTR/rDNS und HELO/EHLO auf denselben Mailserver-Hostnamen setzen.")
			}
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
		return []model.CheckResult{info("rbl", "DNSBL/RBL", 0.0, "RBL-Pruefung aktiv, aber keine Provider konfiguriert.", "")}
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil || ip.To4() == nil {
		return []model.CheckResult{info("rbl", "DNSBL/RBL", 0.0, "RBL nur fuer IPv4 geprueft.", "")}
	}
	octets := strings.Split(ip.String(), ".")
	queryIP := fmt.Sprintf("%s.%s.%s.%s", octets[3], octets[2], octets[1], octets[0])
	listed := 0
	listedProviders := make([]string, 0)
	cleanProviders := make([]string, 0, len(providers))
	for _, p := range providers {
		provider := strings.TrimSpace(p)
		if provider == "" {
			continue
		}
		cleanProviders = append(cleanProviders, provider)
		name := queryIP + "." + provider
		ips, _ := net.DefaultResolver.LookupHost(ctx, name)
		if len(ips) > 0 {
			listed++
			listedProviders = append(listedProviders, provider+" -> "+strings.Join(ips, ", "))
		}
	}
	details := map[string]string{
		"remote_ip":         remoteIP,
		"rbl_query_prefix":  queryIP,
		"checked_providers": strings.Join(cleanProviders, "\n"),
		"listed_providers":  emptyFallback(strings.Join(listedProviders, "\n"), "none"),
	}
	if listed > 0 {
		return []model.CheckResult{withDetails(warn("rbl", "DNSBL/RBL", -0.8, fmt.Sprintf("Absender-IP auf %d RBL(s) gelistet.", listed), "IP-Reputation pruefen und Delisting durchfuehren."), details)}
	}
	return []model.CheckResult{withDetails(pass("rbl", "DNSBL/RBL", 0.1, "Keine RBL-Listings in konfigurierten Listen erkannt.", ""), details)}
}
func spamAssassinHeuristic(ctx context.Context, hostport, raw string) model.CheckResult {
	details := map[string]string{"spamd_hostport": hostport}
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		details["error"] = err.Error()
		return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin nicht erreichbar.", "Optionalen spamd-Dienst pruefen oder Option deaktivieren."), details)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := fmt.Sprintf("SYMBOLS SPAMC/1.5\r\nContent-length: %d\r\n\r\n%s", len(raw), raw)
	if _, err := conn.Write([]byte(req)); err != nil {
		details["error"] = err.Error()
		return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Anfrage fehlgeschlagen.", "spamd-Verbindung pruefen."), details)
	}

	resp, err := readLimited(conn, 64*1024)
	if err != nil {
		details["error"] = err.Error()
		return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Antwort nicht lesbar.", "spamd Antwortformat pruefen."), details)
	}
	lower := strings.ToLower(string(resp))
	spamLine := ""
	for _, line := range strings.Split(string(resp), "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "spam:") {
			spamLine = strings.TrimSpace(line)
			break
		}
	}
	details["spam_line"] = emptyFallback(spamLine, "none")
	if strings.Contains(lower, "spam: true") {
		return withDetails(warn("spamassassin", "SpamAssassin", -1.0, emptyFallback(spamLine, "SpamAssassin stuft Nachricht als Spam ein."), "SpamAssassin-Regeln/Symbole pruefen und Mailinhalt ueberarbeiten."), details)
	}
	if spamLine != "" {
		return withDetails(pass("spamassassin", "SpamAssassin", 0.2, spamLine, ""), details)
	}
	return withDetails(info("spamassassin", "SpamAssassin", 0.0, "SpamAssassin Antwort ohne klassisches Spam-Headerformat erhalten.", ""), details)
}

type rspamdCheckResult struct {
	Score         float64                    `json:"score"`
	RequiredScore float64                    `json:"required_score"`
	Action        string                     `json:"action"`
	Symbols       map[string]json.RawMessage `json:"symbols"`
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
	topSymbols := topRspamdSymbols(parsed.Symbols, 4)
	topSummary := ""
	if len(topSymbols) > 0 {
		chunks := make([]string, 0, len(topSymbols))
		for _, s := range topSymbols {
			if s.Description != "" {
				chunks = append(chunks, fmt.Sprintf("%s(+%.2f): %s", s.Name, s.Score, s.Description))
			} else {
				chunks = append(chunks, fmt.Sprintf("%s(+%.2f)", s.Name, s.Score))
			}
		}
		topSummary = " top=[" + strings.Join(chunks, "; ") + "]"
	}
	summary := fmt.Sprintf("Rspamd action=%s score=%.2f required=%.2f symbols=%d%s", emptyFallback(action, "unknown"), parsed.Score, parsed.RequiredScore, len(parsed.Symbols), topSummary)
	suggestion := rspamdSuggestionFor(topSymbols, action)
	details := map[string]string{
		"action":         emptyFallback(action, "unknown"),
		"score":          fmt.Sprintf("%.2f", parsed.Score),
		"required_score": fmt.Sprintf("%.2f", parsed.RequiredScore),
		"symbol_count":   strconv.Itoa(len(parsed.Symbols)),
		"top_symbols":    emptyFallback(strings.TrimPrefix(strings.TrimSuffix(topSummary, "]"), " top=["), "none"),
	}

	switch action {
	case "reject", "soft reject":
		return withDetails(fail("rspamd", "Rspamd", -1.2, summary, suggestion), details)
	case "add header", "rewrite subject", "greylist":
		return withDetails(warn("rspamd", "Rspamd", -0.6, summary, suggestion), details)
	case "no action":
		return withDetails(pass("rspamd", "Rspamd", 0.2, summary, ""), details)
	default:
		if parsed.RequiredScore > 0 && parsed.Score >= parsed.RequiredScore {
			return withDetails(warn("rspamd", "Rspamd", -0.6, summary, suggestion), details)
		}
		return withDetails(info("rspamd", "Rspamd", 0.0, summary, ""), details)
	}
}

type rspamdSymbol struct {
	Name        string
	Score       float64
	Description string
}

func topRspamdSymbols(raw map[string]json.RawMessage, n int) []rspamdSymbol {
	symbols := make([]rspamdSymbol, 0, len(raw))
	for name, payload := range raw {
		score, desc := parseRspamdSymbolPayload(payload)
		if score <= 0 {
			continue
		}
		symbols = append(symbols, rspamdSymbol{Name: name, Score: score, Description: desc})
	}
	sort.SliceStable(symbols, func(i, j int) bool {
		if symbols[i].Score == symbols[j].Score {
			return symbols[i].Name < symbols[j].Name
		}
		return symbols[i].Score > symbols[j].Score
	})
	if n > 0 && len(symbols) > n {
		return symbols[:n]
	}
	return symbols
}

func parseRspamdSymbolPayload(payload json.RawMessage) (float64, string) {
	var typed struct {
		Score       float64 `json:"score"`
		Description string  `json:"description"`
	}
	if err := json.Unmarshal(payload, &typed); err == nil {
		return typed.Score, strings.TrimSpace(typed.Description)
	}

	var generic map[string]any
	if err := json.Unmarshal(payload, &generic); err != nil {
		return 0, ""
	}
	score := anyNumberToFloat(generic["score"])
	desc := ""
	if d, ok := generic["description"]; ok {
		desc = strings.TrimSpace(fmt.Sprintf("%v", d))
	}
	return score, desc
}

func anyNumberToFloat(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func rspamdSuggestionFor(symbols []rspamdSymbol, action string) string {
	parts := make([]string, 0, 4)
	if action == "reject" || action == "soft reject" {
		parts = append(parts, "Message was rejected by Rspamd; fix the highest positive symbols first.")
	}
	for _, s := range symbols {
		name := strings.ToUpper(s.Name)
		switch {
		case strings.Contains(name, "SPF"):
			parts = append(parts, "Fix SPF for the envelope sender and align with visible From.")
		case strings.Contains(name, "DKIM"):
			parts = append(parts, "Ensure DKIM signatures validate for this sending stream.")
		case strings.Contains(name, "DMARC"):
			parts = append(parts, "Align DMARC with SPF or DKIM pass for the From domain.")
		case strings.Contains(name, "URL"), strings.Contains(name, "PHISH"):
			parts = append(parts, "Review links; remove suspicious redirects/shorteners and limit tracking parameters.")
		case strings.Contains(name, "MIME"), strings.Contains(name, "HTML"):
			parts = append(parts, "Simplify MIME/HTML structure and avoid hidden/deceptive markup.")
		case strings.Contains(name, "RBL"), strings.Contains(name, "DNSBL"):
			parts = append(parts, "Check sender IP reputation and remove DNSBL/RBL listings.")
		}
		if len(parts) >= 4 {
			break
		}
	}
	if len(parts) == 0 {
		return "Inspect Rspamd symbol details and adjust auth, content, and link hygiene."
	}
	return strings.Join(dedupeSorted(parts), " ")
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
