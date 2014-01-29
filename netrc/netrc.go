package netrc

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
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

type Netrc struct {
	pre      string
	tokens   []*token
	machines []*Machine
	macros   Macros
}

func (n *Netrc) FindMachine(name string) (*Machine, error) {
	var def *Machine
	for _, m := range n.machines {
		if m.Name == name {
			return m, nil
		}
		if m.Name == "" {
			def = m
		}
	}
	if def == nil {
		return nil, errors.New("no machine found")
	}
	return def, nil
}

// MarshalText implements the encoding.TextMarshaler interface to encode a
// Netrc into text format.
func (n *Netrc) MarshalText() (text []byte, err error) {
	for i := range n.tokens {
		text = append(text, n.tokens[i].rawkind...)
		switch n.tokens[i].kind {
		case tkMacdef:
			text = append(text, ' ')
			text = append(text, n.tokens[i].macroName...)
		}
		text = append(text, n.tokens[i].rawvalue...)
	}
	return
}

// Machine contains information about a remote machine.
type Machine struct {
	Name     string
	Login    string
	Password string
	Account  string
}

// Macros contains all the macro definitions in a netrc file.
type Macros map[string]string

type token struct {
	kind      tkType
	macroName string
	value     string
	rawkind   []byte
	rawvalue  []byte
}

// Error represents a netrc file parse error.
type Error struct {
	LineNum int    // Line number
	Msg     string // Error message
}

// Error returns a string representation of error e.
func (e *Error) Error() string {
	return fmt.Sprintf("line %d: %s", e.LineNum, e.Msg)
}

func (e *Error) BadDefaultOrder() bool {
	return e.Msg == errBadDefaultOrder
}

const errBadDefaultOrder = "default token must appear after all machine tokens"

// scanLinesKeepPrefix is a split function for a Scanner that returns each line
// of text. The returned token may include newlines if they are before the
// first non-space character. The returned line may be empty. The end-of-line
// marker is one optional carriage return followed by one mandatory newline. In
// regular expression notation, it is `\r?\n`.  The last non-empty line of
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

func parse(r io.Reader, pos int) (*Netrc, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	nrc := Netrc{machines: make([]*Machine, 0, 20), macros: make(Macros, 10)}

	defaultSeen := false
	var currentMacro *token
	var m *Machine
	var t *token
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Split(scanTokensKeepPrefix)

	for scanner.Scan() {
		rawb := scanner.Bytes()
		if len(rawb) == 0 {
			break
		}
		pos += bytes.Count(rawb, []byte{'\n'})
		t, err = newToken(rawb)
		if err != nil {
			if currentMacro == nil {
				return nil, &Error{pos, err.Error()}
			}
			currentMacro.rawvalue = append(currentMacro.rawvalue, rawb...)
			continue
		}

		if currentMacro != nil && bytes.Contains(rawb, []byte{'\n', '\n'}) {
			// if macro rawvalue + rawb would contain \n\n, then macro def is over
			currentMacro.value = string(bytes.TrimLeft(currentMacro.rawvalue, "\r\n"))
			nrc.macros[currentMacro.macroName] = currentMacro.value
			currentMacro = nil
		}

		switch t.kind {
		case tkMacdef:
			if _, t.macroName, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			currentMacro = t
		case tkDefault:
			if defaultSeen {
				return nil, &Error{pos, "multiple default token"}
			}
			if m != nil {
				nrc.machines, m = append(nrc.machines, m), nil
			}
			m = new(Machine)
			m.Name = ""
			defaultSeen = true
		case tkMachine:
			if defaultSeen {
				return nil, &Error{pos, errBadDefaultOrder}
			}
			if m != nil {
				nrc.machines, m = append(nrc.machines, m), nil
			}
			m = new(Machine)
			if t.rawvalue, m.Name, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Name
		case tkLogin:
			if m == nil || m.Login != "" {
				return nil, &Error{pos, "unexpected token login "}
			}
			if t.rawvalue, m.Login, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Login
		case tkPassword:
			if m == nil || m.Password != "" {
				return nil, &Error{pos, "unexpected token password"}
			}
			if t.rawvalue, m.Password, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Password
		case tkAccount:
			if m == nil || m.Account != "" {
				return nil, &Error{pos, "unexpected token account"}
			}
			if t.rawvalue, m.Account, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Account
		}

		nrc.tokens = append(nrc.tokens, t)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if m != nil {
		nrc.machines, m = append(nrc.machines, m), nil
	}
	return &nrc, nil
}

// ParseFile opens the file at filename and then passes its io.Reader to
// Parse().
func ParseFile(filename string) (*Netrc, error) {
	fd, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return Parse(fd)
}

// Parse parses from the the Reader r as a netrc file and returns the set of
// machine information and macros defined in it. The ``default'' machine,
// which is intended to be used when no machine name matches, is identified
// by an empty machine name. There can be only one ``default'' machine.
//
// If there is a parsing error, an Error is returned.
func Parse(r io.Reader) (*Netrc, error) {
	return parse(r, 1)
}

// FindMachine parses the netrc file identified by filename and returns
// the Machine named by name. If no Machine with name name is found, the
// ``default'' machine is returned.
func FindMachine(filename, name string) (*Machine, error) {
	n, err := ParseFile(filename)
	if err != nil {
		return nil, err
	}
	return n.FindMachine(name)
}
