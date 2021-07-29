package authority

type SimpleGrantedAuthority struct {
	role string
}

func NewSimpleGrantedAuthority(role string) *SimpleGrantedAuthority {
	return &SimpleGrantedAuthority{role: role}
}

func (s SimpleGrantedAuthority) Authority() string {
	return s.role
}
