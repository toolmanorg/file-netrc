package netrc

// Macros contains all the macro definitions in a netrc file.
type Macros map[string]string

func (m Macros) equal(o Macros) bool {
	if m == nil && o == nil {
		return true
	}

	if m == nil || o == nil {
		return false
	}

	for k, mv := range m {
		if ov, ok := o[k]; !ok || mv != ov {
			return false
		}
	}

	for k := range o {
		if _, ok := m[k]; !ok {
			return false
		}
	}

	return true
}
