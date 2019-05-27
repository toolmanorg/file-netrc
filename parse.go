package netrc

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

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
			currentMacro.value = strings.TrimLeft(string(currentMacro.rawvalue), "\r\n")
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
			m.nametoken = t
		case tkLogin:
			if m == nil || m.Login != "" {
				return nil, &Error{pos, "unexpected token login "}
			}
			if t.rawvalue, m.Login, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Login
			m.logintoken = t
		case tkPassword:
			if m == nil || m.Password != "" {
				return nil, &Error{pos, "unexpected token password"}
			}
			if t.rawvalue, m.Password, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Password
			m.passtoken = t
		case tkAccount:
			if m == nil || m.Account != "" {
				return nil, &Error{pos, "unexpected token account"}
			}
			if t.rawvalue, m.Account, pos, err = scanValue(scanner, pos); err != nil {
				return nil, &Error{pos, err.Error()}
			}
			t.value = m.Account
			m.accounttoken = t
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
