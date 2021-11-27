package authen

import (
	"gitlab.com/golibs-starter/golib/exception"
	"net/http"
)

var BadCredentials = exception.New(http.StatusUnauthorized, "Bad credentials")
