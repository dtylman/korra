package simpleauth

import (
	"fmt"

	"github.com/labstack/echo"
	"github.com/labstack/echo-contrib/session"
)

// Middleware is the middleware function.
func Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sess, err := session.Get("session", c)
		fmt.Println(sess, err)
		return next(c)
	}
}
