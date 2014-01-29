// Copyright © 2010 Fazlul Shahriar <fshahriar@gmail.com> and
// Copyright © 2014 Blake Gentry <blakesgentry@gmail.com>.
// See LICENSE file for license details.

package netrc

import (
	"bytes"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

var expectedMachines = []*Machine{
	&Machine{Name: "mail.google.com", Login: "joe@gmail.com", Password: "somethingSecret", Account: "gmail"},
	&Machine{Name: "ray", Login: "demo", Password: "mypassword", Account: ""},
	&Machine{Name: "weirdlogin", Login: "uname", Password: "pass#pass", Account: ""},
	&Machine{Name: "", Login: "anonymous", Password: "joe@example.com", Account: ""},
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
	m, def, err := FindMachine("examples/good.netrc", "ray")
	if err != nil {
		t.Fatal(err)
	}
	if !eqMachine(m, expectedMachines[1]) {
		t.Errorf("bad machine; expected %v, got %v\n", expectedMachines[1], m)
	}
	if def {
		t.Errorf("expected def to be false")
	}

	m, def, err = FindMachine("examples/good.netrc", "non.existent")
	if err != nil {
		t.Fatal(err)
	}
	if !eqMachine(m, expectedMachines[3]) {
		t.Errorf("bad machine; expected %v, got %v\n", expectedMachines[3], m)
	}
	if !def {
		t.Errorf("expected def to be true")
	}
}

func TestNetrcFindMachine(t *testing.T) {
	n, err := ParseFile("examples/good.netrc")
	if err != nil {
		t.Fatal(err)
	}

	m, def, err := n.FindMachine("ray")
	if err != nil {
		t.Fatal(err)
	}
	if !eqMachine(m, expectedMachines[1]) {
		t.Errorf("bad machine; expected %v, got %v\n", expectedMachines[1], m)
	}
	if def {
		t.Errorf("expected def to be false")
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

func TestNewMachine(t *testing.T) {
	n, err := ParseFile("examples/good.netrc")
	if err != nil {
		t.Fatal(err)
	}
	nameVal := "heroku.com"
	loginVal := "dodging-samurai-42@heroku.com"
	passwordVal := "octocatdodgeballchampions"
	accountVal := "someacct"

	// sanity check
	bodyb, _ := n.MarshalText()
	body := string(bodyb)
	for _, value := range []string{nameVal, loginVal, passwordVal, accountVal} {
		if strings.Contains(body, value) {
			t.Errorf("MarshalText() before NewMachine() contained unexpected %q", value)
		}
	}

	m := n.NewMachine(nameVal, loginVal, passwordVal, accountVal)
	if m == nil {
		t.Fatalf("NewMachine() returned nil")
	}
	// check values
	if m.Name != nameVal {
		t.Errorf("m.Name expected %q, got %q", nameVal, m.Name)
	}
	if m.Login != loginVal {
		t.Errorf("m.Login expected %q, got %q", loginVal, m.Login)
	}
	if m.Password != passwordVal {
		t.Errorf("m.Password expected %q, got %q", passwordVal, m.Password)
	}
	if m.Account != accountVal {
		t.Errorf("m.Account expected %q, got %q", accountVal, m.Account)
	}
	// check tokens
	checkToken(t, "nametoken", m.nametoken, tkMachine, "\nmachine", nameVal)
	checkToken(t, "logintoken", m.logintoken, tkLogin, "\n\tlogin", loginVal)
	checkToken(t, "passtoken", m.passtoken, tkPassword, "\n\tpassword", passwordVal)
	checkToken(t, "accounttoken", m.accounttoken, tkAccount, "\n\taccount", accountVal)
	// check marshal output
	bodyb, _ = n.MarshalText()
	body = string(bodyb)
	for _, value := range []string{nameVal, loginVal, passwordVal, accountVal} {
		if !strings.Contains(body, value) {
			t.Errorf("MarshalText() after NewMachine() did not include %q as expected", value)
		}
	}
}

func checkToken(t *testing.T, name string, tok *token, kind tkType, rawkind, value string) {
	if tok == nil {
		t.Errorf("%s not defined", name)
		return
	}
	if tok.kind != kind {
		t.Errorf("%s expected kind %d, got %d", name, kind, tok.kind)
	}
	if string(tok.rawkind) != rawkind {
		t.Errorf("%s expected rawkind %q, got %q", name, rawkind, string(tok.rawkind))
	}
	if tok.value != value {
		t.Errorf("%s expected value %q, got %q", name, value, tok.value)
	}
	if tok.value != value {
		t.Errorf("%s expected value %q, got %q", name, value, tok.value)
	}
}

type tokenss struct {
	kind      tkType
	macroName string
	value     string
	rawkind   []byte
	rawvalue  []byte
}

func TestUpdateLogin(t *testing.T) {
	n, err := ParseFile("examples/good.netrc")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		exists   bool
		name     string
		oldlogin string
		newlogin string
	}{
		{true, "mail.google.com", "joe@gmail.com", "joe2@gmail.com"},
		{false, "heroku.com", "", "dodging-samurai-42@heroku.com"},
	}

	bodyb, _ := n.MarshalText()
	body := string(bodyb)
	for _, test := range tests {
		if strings.Contains(body, test.newlogin) {
			t.Errorf("MarshalText() before UpdateLogin() contained unexpected %q", test.newlogin)
		}
	}

	for _, test := range tests {
		m, def, err := n.FindMachine(test.name)
		if err != nil {
			t.Fatal(err)
		}
		if def == test.exists {
			t.Errorf("expected machine %s to not exist, but it did", test.name)
		} else {
			if !test.exists {
				m = n.NewMachine(test.name, test.newlogin, "", "")
			}
			if m == nil {
				t.Errorf("machine %s was nil", test.name)
				continue
			}
			m.UpdateLogin(test.newlogin)
			m, _, err := n.FindMachine(test.name)
			if err != nil {
				t.Fatal(err)
			}
			if m.Login != test.newlogin {
				t.Errorf("expected new login %q, got %q", test.newlogin, m.Login)
			}
			if m.logintoken.value != test.newlogin {
				t.Errorf("expected m.logintoken %q, got %q", test.newlogin, m.logintoken.value)
			}
		}
	}

	bodyb, _ = n.MarshalText()
	body = string(bodyb)
	for _, test := range tests {
		if test.exists && strings.Contains(body, test.oldlogin) {
			t.Errorf("MarshalText() after UpdateLogin() contained unexpected %q", test.oldlogin)
		}
		if !strings.Contains(body, test.newlogin) {
			t.Errorf("MarshalText after UpdatePassword did not contain %q as expected", test.newlogin)
		}
	}
}

func TestUpdatePassword(t *testing.T) {
	n, err := ParseFile("examples/good.netrc")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		exists      bool
		name        string
		oldpassword string
		newpassword string
	}{
		{true, "ray", "mypassword", "supernewpass"},
		{false, "heroku.com", "", "octocatdodgeballchampions"},
	}

	bodyb, _ := n.MarshalText()
	body := string(bodyb)
	for _, test := range tests {
		if test.exists && !strings.Contains(body, test.oldpassword) {
			t.Errorf("MarshalText() before UpdatePassword() did not include %q as expected", test.oldpassword)
		}
		if strings.Contains(body, test.newpassword) {
			t.Errorf("MarshalText() before UpdatePassword() contained unexpected %q", test.newpassword)
		}
	}

	for _, test := range tests {
		m, def, err := n.FindMachine(test.name)
		if err != nil {
			t.Fatal(err)
		}
		if def == test.exists {
			t.Errorf("expected machine %s to not exist, but it did", test.name)
		} else {
			if !test.exists {
				m = n.NewMachine(test.name, "", test.newpassword, "")
			}
			if m == nil {
				t.Errorf("machine %s was nil", test.name)
				continue
			}
			m.UpdatePassword(test.newpassword)
			m, _, err := n.FindMachine(test.name)
			if err != nil {
				t.Fatal(err)
			}
			if m.Password != test.newpassword {
				t.Errorf("expected new password %q, got %q", test.newpassword, m.Password)
			}
			if m.passtoken.value != test.newpassword {
				t.Errorf("expected m.passtoken %q, got %q", test.newpassword, m.passtoken.value)
			}
		}
	}

	bodyb, _ = n.MarshalText()
	body = string(bodyb)
	for _, test := range tests {
		if test.exists && strings.Contains(body, test.oldpassword) {
			t.Errorf("MarshalText() after UpdatePassword() contained unexpected %q", test.oldpassword)
		}
		if !strings.Contains(body, test.newpassword) {
			t.Errorf("MarshalText() after UpdatePassword() did not contain %q as expected", test.newpassword)
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
