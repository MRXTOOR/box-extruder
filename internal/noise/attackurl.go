package noise

import (
	"net/url"
	"strings"
)

// attackXSSPatterns are lowercase substrings that strongly indicate an XSS payload.
var attackXSSPatterns = []string{
	"alert(", "prompt(", "confirm(",
	"document.cookie", "document.location", "document.write",
	"string.fromcharcode", "eval(",
	"<script", "%3cscript", "%3c%73cript",
	"onerror=", "onload=", "onerror%3d", "onload%3d",
	"javascript:", "javascript%3a",
	"data:text/html", "vbscript:",
	"<svg/onload", "%3csvg/onload",
	"<img/src", "%3cimg/src",
	"<iframe", "%3ciframe",
	"expression(alert",
	// JS string concatenation extracted from source by Katana -jc
	"'+", "+a+", "'+a+", "'+b+",
}

// attackSQLiPatterns are lowercase substrings that strongly indicate a SQLi payload.
var attackSQLiPatterns = []string{
	"' or 1=1", "' and 1=1", "' union select", "' union all select",
	" or 1=1", " and 1=1", " or '1'='1", " and '1'='1",
	" or '1'='2", " and '1'='2",
	"' insert into", "' drop table", "' truncate ",
	" create table", " drop table", " alter table",
	"; shutdown", "'; shutdown",
	"union/*", "select/*", "*/select", "*/from",
	"sleep(", "benchmark(", "waitfor delay", "waitfor time",
	"pg_sleep(", "dbms_pipe.receive_message(", "rlike sleep(",
	"extractvalue(", "updatexml(", "exp(~",
	"utl_inaddr", "utl_http", "utl_file", "dbms_", "sys.all_tables",
	"all_tables", "user_tables",
	"ascii(", "ascii%28", "substring(", "char(", "hex(",
	"mid(", "ord(", "conv(", "bin(",
	"xp_cmdshell", "xp_dirtree", "xp_fileexist",
	"load_file(", "into outfile", "into dumpfile",
	"information_schema", "sysobjects", "syscolumns",
	"@@version", "@@servername",
	"convert(int", ";--", "'--",
	"%27%3b", "%27%3B",
}

// IsAttackPayloadURL reports URLs whose query/path looks like an injected XSS/SQLi probe.
func IsAttackPayloadURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return urlMatchesAttackPattern(rawURL) || queryHasInjectionChars(u)
}

func urlMatchesAttackPattern(rawURL string) bool {
	for _, src := range decodeURLVariants(rawURL) {
		if src == "" {
			continue
		}
		for _, pat := range attackXSSPatterns {
			if strings.Contains(src, pat) {
				return true
			}
		}
		for _, pat := range attackSQLiPatterns {
			if strings.Contains(src, strings.ToLower(pat)) {
				return true
			}
		}
	}
	return false
}

func decodeURLVariants(rawURL string) []string {
	out := []string{strings.ToLower(rawURL)}
	if d, err := url.QueryUnescape(rawURL); err == nil {
		dec := strings.ToLower(d)
		out = append(out, dec)
		if d2, err := url.QueryUnescape(dec); err == nil {
			out = append(out, strings.ToLower(d2))
		}
	}
	return out
}

func queryHasInjectionChars(u *url.URL) bool {
	if u.RawQuery == "" {
		return false
	}
	qs, _ := url.ParseQuery(u.RawQuery)
	for key, vals := range qs {
		k := strings.ToLower(strings.TrimSpace(key))
		if k != "q" && k != "x" {
			continue
		}
		for _, v := range vals {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				continue
			}
			if strings.ContainsAny(v, "'\"") || strings.Contains(v, "--") || strings.Contains(v, ";") {
				return true
			}
		}
	}
	return false
}
