package main

import (
	"context"
	"fmt"
	"net"
	"net/mail"
	"sort"
	"strconv"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"

	"github.com/brightcolor/mailprobe/internal/config"
	"github.com/brightcolor/mailprobe/internal/smtp"
)

type authResults struct {
	SPFResult   string
	SPFDomain   string
	DKIMResult  string
	DKIMDomain  string
	DMARCResult string
	FromDomain  string
}

func enrichWithReceiverAuthHeaders(ctx context.Context, cfg config.Config, rm smtp.ReceivedMail, raw string) string {
	res := evaluateAuthResults(ctx, rm, raw)
	authHeader := buildAuthenticationResultsHeader(cfg.SMTPDomain, res)
	receivedSPF := buildReceivedSPFHeader(cfg.SMTPDomain, rm, res.SPFResult)
	return prependHeaders(raw, []string{authHeader, receivedSPF})
}

func evaluateAuthResults(ctx context.Context, rm smtp.ReceivedMail, raw string) authResults {
	out := authResults{
		SPFResult:   "none",
		DKIMResult:  "none",
		DMARCResult: "none",
	}

	ip := net.ParseIP(strings.TrimSpace(rm.RemoteIP))
	spfRes, spfDomain := evaluateSPF(ctx, ip, rm.HELO, rm.MailFrom)
	out.SPFResult = spfRes
	out.SPFDomain = spfDomain

	dkimRes, dkimDomain := evaluateDKIM(raw)
	out.DKIMResult = dkimRes
	out.DKIMDomain = dkimDomain

	out.FromDomain = fromDomain(raw)
	out.DMARCResult = evaluateDMARC(ctx, out.FromDomain, out.SPFResult, out.SPFDomain, out.DKIMResult, out.DKIMDomain)

	return out
}

func buildAuthenticationResultsHeader(authServID string, res authResults) string {
	if strings.TrimSpace(authServID) == "" {
		authServID = "mailprobe.local"
	}
	spfDomain := safeAuthValue(emptyFallback(res.SPFDomain, "unknown"))
	dkimDomain := safeAuthValue(emptyFallback(res.DKIMDomain, "unknown"))
	fromDomain := safeAuthValue(emptyFallback(res.FromDomain, "unknown"))

	line := fmt.Sprintf(
		"Authentication-Results: %s; spf=%s smtp.mailfrom=%s; dkim=%s header.d=%s; dmarc=%s header.from=%s",
		authServID,
		safeAuthValue(res.SPFResult),
		spfDomain,
		safeAuthValue(res.DKIMResult),
		dkimDomain,
		safeAuthValue(res.DMARCResult),
		fromDomain,
	)
	return line
}

func buildReceivedSPFHeader(receiver string, rm smtp.ReceivedMail, spfResult string) string {
	return fmt.Sprintf(
		"Received-SPF: %s client-ip=%s; envelope-from=%s; helo=%s; receiver=%s",
		safeAuthValue(spfResult),
		safeAuthValue(rm.RemoteIP),
		safeAuthValue(emptyFallback(rm.MailFrom, "<>")),
		safeAuthValue(emptyFallback(rm.HELO, "unknown")),
		safeAuthValue(emptyFallback(receiver, "mailprobe.local")),
	)
}

func prependHeaders(raw string, extra []string) string {
	norm := strings.ReplaceAll(raw, "\r\n", "\n")
	parts := strings.SplitN(norm, "\n\n", 2)
	headerPart := ""
	bodyPart := ""
	if len(parts) > 0 {
		headerPart = parts[0]
	}
	if len(parts) == 2 {
		bodyPart = parts[1]
	}

	all := make([]string, 0, len(extra)+1)
	for _, h := range extra {
		h = strings.TrimSpace(h)
		if h != "" {
			all = append(all, h)
		}
	}
	if strings.TrimSpace(headerPart) != "" {
		all = append(all, headerPart)
	}

	joined := strings.Join(all, "\n")
	if bodyPart != "" {
		joined += "\n\n" + bodyPart
	} else {
		joined += "\n\n"
	}
	return strings.ReplaceAll(joined, "\n", "\r\n")
}

func safeAuthValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	v = strings.ReplaceAll(v, ";", "")
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return v
}

func fromDomain(raw string) string {
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		return ""
	}
	from := strings.TrimSpace(msg.Header.Get("From"))
	if from == "" {
		return ""
	}
	addr, err := mail.ParseAddress(from)
	if err != nil {
		return extractDomain(from)
	}
	return extractDomain(addr.Address)
}

func evaluateDKIM(raw string) (result, domain string) {
	verifs, err := dkim.Verify(strings.NewReader(raw))
	if len(verifs) == 0 {
		if err != nil {
			switch {
			case dkim.IsTempFail(err):
				return "temperror", ""
			case dkim.IsPermFail(err):
				return "permerror", ""
			default:
				return "fail", ""
			}
		}
		return "none", ""
	}

	for _, v := range verifs {
		if v == nil {
			continue
		}
		if v.Err == nil {
			return "pass", strings.ToLower(strings.TrimSpace(v.Domain))
		}
	}
	for _, v := range verifs {
		if v == nil || v.Err == nil {
			continue
		}
		if dkim.IsTempFail(v.Err) {
			return "temperror", strings.ToLower(strings.TrimSpace(v.Domain))
		}
	}
	for _, v := range verifs {
		if v == nil || v.Err == nil {
			continue
		}
		if dkim.IsPermFail(v.Err) {
			return "permerror", strings.ToLower(strings.TrimSpace(v.Domain))
		}
	}
	for _, v := range verifs {
		if v != nil {
			return "fail", strings.ToLower(strings.TrimSpace(v.Domain))
		}
	}
	return "fail", ""
}

func evaluateDMARC(ctx context.Context, fromDomain, spfResult, spfDomain, dkimResult, dkimDomain string) string {
	if strings.TrimSpace(fromDomain) == "" {
		return "none"
	}
	rec, err := dmarc.LookupWithOptions(fromDomain, &dmarc.LookupOptions{
		LookupTXT: func(domain string) ([]string, error) {
			return net.DefaultResolver.LookupTXT(ctx, domain)
		},
	})
	if err != nil {
		switch {
		case err == dmarc.ErrNoPolicy:
			return "none"
		case dmarc.IsTempFail(err):
			return "temperror"
		default:
			return "permerror"
		}
	}

	spfAligned := false
	if spfResult == "pass" {
		spfAligned = domainAligned(spfDomain, fromDomain, rec.SPFAlignment == dmarc.AlignmentStrict)
	}
	dkimAligned := false
	if dkimResult == "pass" {
		dkimAligned = domainAligned(dkimDomain, fromDomain, rec.DKIMAlignment == dmarc.AlignmentStrict)
	}
	if spfAligned || dkimAligned {
		return "pass"
	}
	return "fail"
}

func domainAligned(authDomain, fromDomain string, strict bool) bool {
	authDomain = strings.ToLower(strings.TrimSpace(authDomain))
	fromDomain = strings.ToLower(strings.TrimSpace(fromDomain))
	if authDomain == "" || fromDomain == "" {
		return false
	}
	if strict {
		return authDomain == fromDomain
	}
	return authDomain == fromDomain || strings.HasSuffix(authDomain, "."+fromDomain) || strings.HasSuffix(fromDomain, "."+authDomain)
}

func evaluateSPF(ctx context.Context, remoteIP net.IP, helo, envelopeFrom string) (result, domain string) {
	domain = extractDomain(envelopeFrom)
	if domain == "" {
		domain = strings.ToLower(strings.TrimSpace(helo))
	}
	if domain == "" || remoteIP == nil {
		return "none", domain
	}
	seen := make(map[string]struct{})
	return checkSPFDomain(ctx, remoteIP, domain, 0, seen), domain
}

func checkSPFDomain(ctx context.Context, remoteIP net.IP, domain string, depth int, seen map[string]struct{}) string {
	if depth > 10 {
		return "permerror"
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return "none"
	}
	if _, ok := seen[domain]; ok {
		return "permerror"
	}
	seen[domain] = struct{}{}
	defer delete(seen, domain)

	record, recErr := lookupSPFRecord(ctx, domain)
	if recErr == "none" {
		return "none"
	}
	if recErr == "temperror" {
		return "temperror"
	}
	if recErr == "permerror" {
		return "permerror"
	}

	tokens := strings.Fields(record)
	if len(tokens) == 0 {
		return "none"
	}

	redirect := ""
	for _, tok := range tokens[1:] {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(tok), "redirect=") {
			redirect = strings.TrimSpace(strings.SplitN(tok, "=", 2)[1])
			continue
		}
		if strings.Contains(tok, "=") {
			continue
		}

		qualifier := byte('+')
		if strings.ContainsRune("+-~?", rune(tok[0])) {
			qualifier = tok[0]
			tok = tok[1:]
		}
		matched, errRes := matchSPFMechanism(ctx, remoteIP, domain, tok, depth, seen)
		if errRes != "" {
			return errRes
		}
		if matched {
			return qualifierToResult(qualifier)
		}
	}

	if redirect != "" {
		return checkSPFDomain(ctx, remoteIP, redirect, depth+1, seen)
	}
	return "neutral"
}

func lookupSPFRecord(ctx context.Context, domain string) (record string, status string) {
	txts, err := net.DefaultResolver.LookupTXT(ctx, domain)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return "", "none"
		}
		return "", "temperror"
	}
	for _, rec := range txts {
		rec = strings.TrimSpace(rec)
		if strings.HasPrefix(strings.ToLower(rec), "v=spf1") {
			return rec, ""
		}
	}
	return "", "none"
}

func matchSPFMechanism(ctx context.Context, remoteIP net.IP, currentDomain, mechanism string, depth int, seen map[string]struct{}) (bool, string) {
	name, value, cidr := parseSPFMechanism(mechanism)
	switch name {
	case "all":
		return true, ""
	case "include":
		if value == "" {
			return false, "permerror"
		}
		res := checkSPFDomain(ctx, remoteIP, value, depth+1, seen)
		if res == "pass" {
			return true, ""
		}
		if res == "temperror" || res == "permerror" {
			return false, res
		}
		return false, ""
	case "ip4":
		return ipMatchesWithOptionalCIDR(remoteIP, net.ParseIP(value), normalizeCIDR(cidr, 32)), ""
	case "ip6":
		return ipMatchesWithOptionalCIDR(remoteIP, net.ParseIP(value), normalizeCIDR(cidr, 128)), ""
	case "a":
		target := value
		if target == "" {
			target = currentDomain
		}
		return hostResolvesToIP(ctx, target, remoteIP, cidr), ""
	case "mx":
		target := value
		if target == "" {
			target = currentDomain
		}
		return mxResolvesToIP(ctx, target, remoteIP, cidr), ""
	default:
		return false, ""
	}
}

func parseSPFMechanism(mech string) (name, value string, cidr int) {
	cidr = -1
	raw := strings.TrimSpace(mech)
	if i := strings.Index(raw, ":"); i >= 0 {
		name = strings.ToLower(strings.TrimSpace(raw[:i]))
		value = strings.TrimSpace(raw[i+1:])
	} else {
		name = strings.ToLower(raw)
	}
	if j := strings.Index(name, "/"); j >= 0 {
		cidr = parseCIDRBits(name[j+1:])
		name = strings.TrimSpace(name[:j])
	}
	if slash := strings.Index(value, "/"); slash >= 0 {
		rawCIDR := strings.TrimSpace(value[slash+1:])
		value = value[:slash]
		cidr = parseCIDRBits(rawCIDR)
	}
	return name, value, cidr
}

func hostResolvesToIP(ctx context.Context, host string, remoteIP net.IP, cidr int) bool {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ipMatchesWithOptionalCIDR(remoteIP, a.IP, cidr) {
			return true
		}
	}
	return false
}

func mxResolvesToIP(ctx context.Context, domain string, remoteIP net.IP, cidr int) bool {
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err != nil {
		return false
	}
	sort.SliceStable(mxs, func(i, j int) bool {
		return mxs[i].Pref < mxs[j].Pref
	})
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if hostResolvesToIP(ctx, host, remoteIP, cidr) {
			return true
		}
	}
	return false
}

func ipMatchesWithOptionalCIDR(remoteIP, candidate net.IP, cidr int) bool {
	if remoteIP == nil || candidate == nil {
		return false
	}
	if cidr < 0 {
		return remoteIP.Equal(candidate)
	}
	bits := 128
	base := candidate
	check := remoteIP
	if candidate.To4() != nil && remoteIP.To4() != nil {
		bits = 32
		base = candidate.To4()
		check = remoteIP.To4()
	}
	if cidr > bits {
		return false
	}
	mask := net.CIDRMask(cidr, bits)
	if mask == nil {
		return false
	}
	return base.Mask(mask).Equal(check.Mask(mask))
}

func qualifierToResult(q byte) string {
	switch q {
	case '+':
		return "pass"
	case '-':
		return "fail"
	case '~':
		return "softfail"
	case '?':
		return "neutral"
	default:
		return "neutral"
	}
}

func extractDomain(v string) string {
	v = strings.TrimSpace(strings.Trim(v, "<>"))
	if v == "" {
		return ""
	}
	at := strings.LastIndex(v, "@")
	if at < 0 || at+1 >= len(v) {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(v[at+1:]))
}

func parseCIDRBits(v string) int {
	i, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return -1
	}
	return i
}

func normalizeCIDR(cidr int, bits int) int {
	if cidr < 0 {
		return bits
	}
	return cidr
}

func emptyFallback(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
