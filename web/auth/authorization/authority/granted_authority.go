package authority

type GrantedAuthority interface {
	Authority() string
}
