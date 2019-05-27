package netrc // import "toolman.org/file/netrc"

import (
	"bytes"
	"sync"
)

type Netrc struct {
	tokens     []*token
	machines   []*Machine
	macros     Macros
	updateLock sync.Mutex
}

// FindMachine returns the Machine in n named by name. If a machine named by
// name exists, it is returned. If no Machine with name name is found and there
// is a ``default'' machine, the ``default'' machine is returned. Otherwise, nil
// is returned.
func (n *Netrc) FindMachine(name string) (m *Machine) {
	// TODO(bgentry): not safe for concurrency
	var def *Machine
	for _, m = range n.machines {
		if m.Name == name {
			return m
		}
		if m.IsDefault() {
			def = m
		}
	}
	if def == nil {
		return nil
	}
	return def
}

// FindMachine parses the netrc file identified by filename and returns the
// Machine named by name. If a problem occurs parsing the file at filename, an
// error is returned. If a machine named by name exists, it is returned. If no
// Machine with name name is found and there is a ``default'' machine, the
// ``default'' machine is returned. Otherwise, nil is returned.
func FindMachine(filename, name string) (m *Machine, err error) {
	n, err := ParseFile(filename)
	if err != nil {
		return nil, err
	}
	return n.FindMachine(name), nil
}

// MarshalText implements the encoding.TextMarshaler interface to encode a
// Netrc into text format.
func (n *Netrc) MarshalText() (text []byte, err error) {
	// TODO(bgentry): not safe for concurrency
	for i := range n.tokens {
		switch n.tokens[i].kind {
		case tkComment, tkDefault, tkWhitespace: // always append these types
			text = append(text, n.tokens[i].rawkind...)
		default:
			if n.tokens[i].value != "" { // skip empty-value tokens
				text = append(text, n.tokens[i].rawkind...)
			}
		}
		if n.tokens[i].kind == tkMacdef {
			text = append(text, ' ')
			text = append(text, n.tokens[i].macroName...)
		}
		text = append(text, n.tokens[i].rawvalue...)
	}
	return
}

func (n *Netrc) insertMachineTokensBeforeDefault(m *Machine) {
	newtokens := []*token{m.nametoken}
	if m.logintoken.value != "" {
		newtokens = append(newtokens, m.logintoken)
	}
	if m.passtoken.value != "" {
		newtokens = append(newtokens, m.passtoken)
	}
	if m.accounttoken.value != "" {
		newtokens = append(newtokens, m.accounttoken)
	}
	for i := range n.tokens {
		if n.tokens[i].kind == tkDefault {
			// found the default, now insert tokens before it
			n.tokens = append(n.tokens[:i], append(newtokens, n.tokens[i:]...)...)
			return
		}
	}
	// didn't find a default, just add the newtokens to the end
	n.tokens = append(n.tokens, newtokens...)
	return
}

func (n *Netrc) RemoveMachine(name string) {
	n.updateLock.Lock()
	defer n.updateLock.Unlock()

	for i := range n.machines {
		if n.machines[i] != nil && n.machines[i].Name == name {
			m := n.machines[i]
			for _, t := range []*token{
				m.nametoken, m.logintoken, m.passtoken, m.accounttoken,
			} {
				n.removeToken(t)
			}
			n.machines = append(n.machines[:i], n.machines[i+1:]...)
			return
		}
	}
}

func (n *Netrc) Equal(o *Netrc) bool {
	if n == nil && o == nil {
		return true
	}

	if n == nil || o == nil {
		return false
	}

	nmm := n.machineMap()
	omm := o.machineMap()

	if len(nmm) != len(omm) {
		return false
	}

	for k, nm := range nmm {
		om, ok := omm[k]
		if !ok || !om.Equal(nm) {
			return false
		}
	}

	for k := range omm {
		if _, ok := nmm[k]; !ok {
			return false
		}
	}

	return n.macros.equal(o.macros)
}

func (n *Netrc) Visit(vfunc func(*Machine) error) error {
	for _, m := range n.machines {
		if err := vfunc(m); err != nil {
			return err
		}
	}
	return nil
}

func (n *Netrc) machineMap() map[string]*Machine {
	mm := make(map[string]*Machine)
	for _, m := range n.machines {
		mm[m.key()] = m
	}
	return mm
}

func (n *Netrc) removeToken(t *token) {
	if t != nil {
		for i := range n.tokens {
			if n.tokens[i] == t {
				n.tokens = append(n.tokens[:i], n.tokens[i+1:]...)
				return
			}
		}
	}
}

func updateTokenValue(t *token, value string) {
	oldvalue := t.value
	t.value = value
	newraw := make([]byte, len(t.rawvalue))
	copy(newraw, t.rawvalue)
	t.rawvalue = append(
		bytes.TrimSuffix(newraw, []byte(oldvalue)),
		[]byte(value)...,
	)
}
