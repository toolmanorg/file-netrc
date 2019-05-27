package netrc

import "fmt"

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
