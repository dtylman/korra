package cookiestore

import (
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
)

//Store is a global cookie store
var Store = sessions.NewCookieStore([]byte("cuwedhificMolbIbOnsabowwoivapDawthoavCejrujodModNijLomhoharjerbacewgyanedtadsOrUgedudijicNougamWakFi"))

//Session returns a session from the cookie store
func Session(name string, c echo.Context) (*sessions.Session, error) {
	return Store.Get(c.Request(), name)
}

//DefaultSession returns the default session name
func DefaultSession(c echo.Context) (*sessions.Session, error) {
	return Session("default", c)
}
