package authorization

import (
	"github.com/golibs-starter/golib/exception"
	"net/http"
)

var (
	AccessDenied = exception.New(http.StatusForbidden, "Access is denied")
)
