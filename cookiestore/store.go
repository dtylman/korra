package cookiestore

import (
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
)

//Store is a global cookie store
var store = sessions.NewCookieStore([]byte("cuwedhificMolbIbOnsabowwoivapDawthoavCejrujodModNijLomhoharjerbacewgyanedtadsOrUgedudijicNougamWakFi"))

//Session returns a session from the cookie store
func Session(name string, c echo.Context) (*sessions.Session, error) {
	return store.Get(c.Request(), name)
}

//DefaultSession returns the default session name
func DefaultSession(c echo.Context) (*sessions.Session, error) {
	return Session("default", c)
}

// MaxAge sets the maximum age for the store
func MaxAge(age int) {
	store.MaxAge(age)
}

//Middleware ...
func Middleware() echo.MiddlewareFunc {
	return session.Middleware(store)
}
