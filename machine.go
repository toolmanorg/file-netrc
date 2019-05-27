package netrc

import (
	"strings"
)

// Machine contains information about a remote machine.
type Machine struct {
	Name     string
	Login    string
	Password string
	Account  string

	nametoken    *token
	logintoken   *token
	passtoken    *token
	accounttoken *token
}

func (n *Netrc) NewMachine(name, login, password, account string) *Machine {
	n.updateLock.Lock()
	defer n.updateLock.Unlock()

	prefix := "\n"
	if len(n.tokens) == 0 {
		prefix = ""
	}
	m := &Machine{
		Name:     name,
		Login:    login,
		Password: password,
		Account:  account,

		nametoken: &token{
			kind:     tkMachine,
			rawkind:  []byte(prefix + "machine"),
			value:    name,
			rawvalue: []byte(" " + name),
		},
		logintoken: &token{
			kind:     tkLogin,
			rawkind:  []byte("\n\tlogin"),
			value:    login,
			rawvalue: []byte(" " + login),
		},
		passtoken: &token{
			kind:     tkPassword,
			rawkind:  []byte("\n\tpassword"),
			value:    password,
			rawvalue: []byte(" " + password),
		},
		accounttoken: &token{
			kind:     tkAccount,
			rawkind:  []byte("\n\taccount"),
			value:    account,
			rawvalue: []byte(" " + account),
		},
	}
	n.insertMachineTokensBeforeDefault(m)
	for i := range n.machines {
		if n.machines[i].IsDefault() {
			n.machines = append(append(n.machines[:i], m), n.machines[i:]...)
			return m
		}
	}
	n.machines = append(n.machines, m)
	return m
}

// IsDefault returns true if the machine is a "default" token, denoted by an
// empty name.
func (m *Machine) IsDefault() bool {
	return m.Name == ""
}

// UpdatePassword sets the password for the Machine m.
func (m *Machine) UpdatePassword(newpass string) {
	m.Password = newpass
	updateTokenValue(m.passtoken, newpass)
}

// UpdateLogin sets the login for the Machine m.
func (m *Machine) UpdateLogin(newlogin string) {
	m.Login = newlogin
	updateTokenValue(m.logintoken, newlogin)
}

// UpdateAccount sets the login for the Machine m.
func (m *Machine) UpdateAccount(newaccount string) {
	m.Account = newaccount
	updateTokenValue(m.accounttoken, newaccount)
}

func (m *Machine) Equal(o *Machine) bool {
	switch {
	case m == nil && o == nil:
		return true
	case m == nil || o == nil:
		return false
	default:
		return m.Name == o.Name && m.Login == o.Login && m.Password == o.Password && m.Account == o.Account
	}
}

const keysep = "\000"

func (m *Machine) key() string {
	return strings.Join([]string{m.Login, m.Account, m.Name}, keysep)
}
