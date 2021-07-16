package client

type HttpClientSecurityProperties struct {
}

func (h HttpClientSecurityProperties) Prefix() string {
	return "vinid.security.http.client"
}
