package netrc

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

type tkType int

const (
	tkMachine tkType = iota
	tkDefault
	tkLogin
	tkPassword
	tkAccount
	tkMacdef
	tkComment
	tkWhitespace
)

var keywords = map[string]tkType{
	"machine":  tkMachine,
	"default":  tkDefault,
	"login":    tkLogin,
	"password": tkPassword,
	"account":  tkAccount,
	"macdef":   tkMacdef,
	"#":        tkComment,
}

type token struct {
	kind      tkType
	macroName string
	value     string
	rawkind   []byte
	rawvalue  []byte
}

func newToken(rawb []byte) (*token, error) {
	_, tkind, err := bufio.ScanWords(rawb, true)
	if err != nil {
		return nil, err
	}
	var ok bool
	t := token{rawkind: rawb}
	t.kind, ok = keywords[string(tkind)]
	if !ok {
		trimmed := strings.TrimSpace(string(tkind))
		if trimmed == "" {
			t.kind = tkWhitespace // whitespace-only, should happen only at EOF
			return &t, nil
		}
		if strings.HasPrefix(trimmed, "#") {
			t.kind = tkComment // this is a comment
			return &t, nil
		}
		return &t, fmt.Errorf("keyword expected; got " + string(tkind))
	}
	return &t, nil
}

// scanLinesKeepPrefix is a split function for a Scanner that returns each line
// of text. The returned token may include newlines if they are before the
// first non-space character. The returned line may be empty. The end-of-line
// marker is one optional carriage return followed by one mandatory newline. In
// regular expression notation, it is `\r?\n`. The last non-empty line of
// input will be returned even if it has no newline.
func scanLinesKeepPrefix(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !unicode.IsSpace(r) {
			break
		}
	}
	if i := bytes.IndexByte(data[start:], '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return start + i, data[0 : start+i], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

// scanWordsKeepPrefix is a split function for a Scanner that returns each
// space-separated word of text, with prefixing spaces included. It will never
// return an empty string. The definition of space is set by unicode.IsSpace.
//
// Adapted from bufio.ScanWords().
func scanTokensKeepPrefix(data []byte, atEOF bool) (advance int, token []byte, err error) {
	// Skip leading spaces.
	start := 0
	for width := 0; start < len(data); start += width {
		var r rune
		r, width = utf8.DecodeRune(data[start:])
		if !unicode.IsSpace(r) {
			break
		}
	}
	if atEOF && len(data) == 0 || start == len(data) {
		return len(data), data, nil
	}
	if len(data) > start && data[start] == '#' {
		return scanLinesKeepPrefix(data, atEOF)
	}
	// Scan until space, marking end of word.
	for width, i := 0, start; i < len(data); i += width {
		var r rune
		r, width = utf8.DecodeRune(data[i:])
		if unicode.IsSpace(r) {
			return i, data[:i], nil
		}
	}
	// If we're at EOF, we have a final, non-empty, non-terminated word. Return it.
	if atEOF && len(data) > start {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

func scanValue(scanner *bufio.Scanner, pos int) ([]byte, string, int, error) {
	if scanner.Scan() {
		raw := scanner.Bytes()
		pos += bytes.Count(raw, []byte{'\n'})
		return raw, strings.TrimSpace(string(raw)), pos, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, "", pos, &Error{pos, err.Error()}
	}
	return nil, "", pos, nil
}
