// Copyright © 2010 Fazlul Shahriar <fshahriar@gmail.com>.
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
	&Machine{"", "anonymous", "joe@example.com", ""},
}
var expectedMacros = Macros{
	"allput": "put src/*",
}

func eqMachine(a *Machine, b *Machine) bool {
	return a.Name == b.Name &&
		a.Login == b.Login &&
		a.Password == b.Password &&
		a.Account == b.Account
}

func testExpected(n *Netrc, t *testing.T) {
	for i, e := range expectedMachines {
		if !eqMachine(e, n.machines[i]) {
			t.Errorf("bad machine; expected %v, got %v\n", e, n.machines[i])
		}
	}

	for k, v := range expectedMacros {
		if v != n.macros[k] {
			t.Errorf("bad macro for %s; expected %s, got %s\n", k, v, n.macros[k])
		}
	}
}

func netrcReader(filename string, t *testing.T) io.Reader {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
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
	if !eqMachine(m, expectedMachines[2]) {
		t.Errorf("bad machine; expected %v, got %v\n", expectedMachines[2], m)
	}
}
