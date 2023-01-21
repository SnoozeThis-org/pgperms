package pgperms

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/samber/lo"
)

// TODO: Write test

func Escape(s string) string {
	encodingType := ""
	var buf bytes.Buffer
	buf.WriteByte('\'')
	buf.Grow(len(s)+2)
	for _, c := range s {
		switch c {
		case '\'':
			buf.WriteByte('\'')
			buf.WriteByte('\'')
		case '\n':
			buf.WriteByte('\\')
			buf.WriteByte('n')
			encodingType = "E"
		case '\r':
			buf.WriteByte('\\')
			buf.WriteByte('r')
			encodingType = "E"
		case '\\':
			buf.WriteByte('\\')
			buf.WriteByte('\\')
			encodingType = "E"
		default:
			if c > 128 {
				fmt.Fprintf(&buf, `\u%04x`, c)
				encodingType = "E"
			} else if unicode.IsPrint(c) {
				buf.WriteByte(byte(c))
			} else {
				fmt.Fprintf(&buf, `\x%x`, c)
				encodingType = "E"
			}
		}
	}
	buf.WriteByte('\'')
	return encodingType + buf.String()
}

func splitObjectName(name string) (string, string) {
	sp := strings.SplitN(name, ".", 2)
	if len(sp) == 1 {
		return "", sp[0]
	}
	return sp[0], sp[1]
}

func joinTableName(database, schema, table string) string {
	return database + "." + safeIdentifier(schema) + "." + safeIdentifier(table)
}

var safeCharactersRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

func identifierNeedsEscaping(s string) bool {
	if lo.Contains(keywords, s) {
		return true
	}
	return !safeCharactersRe.MatchString(s)
}

func safeIdentifier(s string) string {
	if identifierNeedsEscaping(s) {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
