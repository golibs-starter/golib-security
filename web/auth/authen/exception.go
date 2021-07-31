package authen

import (
	"gitlab.id.vin/vincart/golib/exception"
	"net/http"
)

var BadCredentials = exception.New(http.StatusUnauthorized, "Bad credentials")
