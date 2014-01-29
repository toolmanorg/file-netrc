// Copyright © 2010 Fazlul Shahriar <fshahriar@gmail.com> and
// Copyright © 2014 Blake Gentry <blakesgentry@gmail.com>.
// See LICENSE file for license details.

package netrc

import (
	"bytes"
	"io"
	"io/ioutil"
	"testing"
)

var expectedMachines = []*Machine{
	&Machine{"mail.google.com", "joe@gmail.com", "somethingSecret", "gmail"},
	&Machine{"ray", "demo", "mypassword", ""},
	&Machine{"weirdlogin", "uname", "pass#pass", ""},
	&Machine{"", "anonymous", "joe@example.com", ""},
}
var expectedMacros = Macros{
	"allput":  "put src/*",
	"allput2": "  put src/*\nput src2/*",
}

func eqMachine(a *Machine, b *Machine) bool {
	return a.Name == b.Name &&
		a.Login == b.Login &&
		a.Password == b.Password &&
		a.Account == b.Account
}

func testExpected(n *Netrc, t *testing.T) {
	if len(expectedMachines) != len(n.machines) {
		t.Errorf("expected %d machines, got %d", len(expectedMachines), len(n.machines))
	} else {
		for i, e := range expectedMachines {
			if !eqMachine(e, n.machines[i]) {
				t.Errorf("bad machine; expected %v, got %v\n", e, n.machines[i])
			}
		}
	}

	if len(expectedMacros) != len(n.macros) {
		t.Errorf("expected %d macros, got %d", len(expectedMacros), len(n.macros))
	} else {
		for k, v := range expectedMacros {
			if v != n.macros[k] {
				t.Errorf("bad macro for %s; expected %q, got %q\n", k, v, n.macros[k])
			}
		}
	}
}

var newTokenTests = []struct {
	rawkind string
	tkind   tkType
}{
	{"machine", tkMachine},
	{"\n\n\tmachine", tkMachine},
	{"\n   machine", tkMachine},
	{"default", tkDefault},
	{"login", tkLogin},
	{"password", tkPassword},
	{"account", tkAccount},
	{"macdef", tkMacdef},
	{"\n # comment stuff ", tkComment},
	{"\n # I am another comment", tkComment},
	{"\n\t\n ", tkWhitespace},
}

var newTokenInvalidTests = []string{
	" junk",
	"sdfdsf",
	"account#unspaced comment",
}

func TestNewToken(t *testing.T) {
	for _, tktest := range newTokenTests {
		tok, err := newToken([]byte(tktest.rawkind))
		if err != nil {
			t.Fatal(err)
		}
		if tok.kind != tktest.tkind {
			t.Errorf("expected tok.kind %d, got %d", tktest.tkind, tok.kind)
		}
		if string(tok.rawkind) != tktest.rawkind {
			t.Errorf("expected tok.rawkind %q, got %q", tktest.rawkind, string(tok.rawkind))
		}
	}

	for _, tktest := range newTokenInvalidTests {
		_, err := newToken([]byte(tktest))
		if err == nil {
			t.Errorf("expected error with %q, got none", tktest)
		}
	}
}

func TestParse(t *testing.T) {
	r := netrcReader("examples/good.netrc", t)
	n, err := Parse(r)
	if err != nil {
		t.Fatal(err)
	}
	testExpected(n, t)
}

func TestParseFile(t *testing.T) {
	n, err := ParseFile("examples/good.netrc")
	if err != nil {
		t.Fatal(err)
	}
	testExpected(n, t)

	_, err = ParseFile("examples/bad_default_order.netrc")
	if err == nil {
		t.Error("expected an error parsing bad_default_order.netrc, got none")
	} else if !err.(*Error).BadDefaultOrder() {
		t.Error("expected BadDefaultOrder() to be true, got false")
	}
}

func TestFindMachine(t *testing.T) {
	m, err := FindMachine("examples/good.netrc", "ray")
	if err != nil {
		t.Fatal(err)
	}
	if !eqMachine(m, expectedMachines[1]) {
		t.Errorf("bad machine; expected %v, got %v\n", expectedMachines[1], m)
	}

	m, err = FindMachine("examples/good.netrc", "non.existent")
	if err != nil {
		t.Fatal(err)
	}
	if !eqMachine(m, expectedMachines[3]) {
		t.Errorf("bad machine; expected %v, got %v\n", expectedMachines[3], m)
	}
}

func TestMarshalText(t *testing.T) {
	// load up expected netrc Marshal output
	expected, err := ioutil.ReadAll(netrcReader("examples/good.netrc", t))
	if err != nil {
		t.Fatal(err)
	}

	n, err := ParseFile("examples/good.netrc")
	if err != nil {
		t.Fatal(err)
	}

	result, err := n.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(result) != string(expected) {
		t.Errorf("expected:\n%q\ngot:\n%q", string(expected), string(result))
	}
}

func netrcReader(filename string, t *testing.T) io.Reader {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}
