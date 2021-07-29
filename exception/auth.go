package exception

import (
	"gitlab.id.vin/vincart/golib/exception"
	"net/http"
)

var (
	AccessDenied = exception.New(http.StatusForbidden, "Access is denied")
)
