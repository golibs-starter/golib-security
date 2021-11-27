package authorization

import (
	"gitlab.com/golibs-starter/golib/exception"
	"net/http"
)

var (
	AccessDenied = exception.New(http.StatusForbidden, "Access is denied")
)
