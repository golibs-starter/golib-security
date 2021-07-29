package authen

type Provider interface {
	Manager
	Supports(authentication Authentication) bool
}
