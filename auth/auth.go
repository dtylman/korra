package auth

import (
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/dtylman/korra/cookiestore"
	"github.com/labstack/echo"
)

const sessionName = "simpleauth"

// Middleware is the middleware function.
func Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		_, err := LoggedUser(c)
		if err != nil {
			return c.Redirect(http.StatusFound, "/login")
		}
		fmt.Print(err)
		return next(c)
	}
}

//User ...
type User struct {
	Name     string
	Password string
}

func init() {
	gob.Register(&User{})
}

//LoggedUser return the user associated with the current session
func LoggedUser(c echo.Context) (*User, error) {
	sess, err := cookiestore.DefaultSession(c)
	if err != nil {
		return nil, err
	}
	user, ok := sess.Values["user"]
	if !ok {
		return nil, errors.New("Not found")
	}
	return user.(*User), nil
}

//DoLogin checks credentials and logs in a user
func DoLogin(username string, password string, c echo.Context) error {
	if username == "" {
		return errors.New("Invalid credentials")
	}
	sess, err := cookiestore.DefaultSession(c)
	if err != nil {
		return err
	}
	sess.Values["user"] = &User{Name: username}
	sess.Save(c.Request(), c.Response())
	log.Printf("user '%v' logged in", username)
	return nil
}

//Logout logs out the current user
func Logout(c echo.Context) error {
	user, err := LoggedUser(c)
	if user == nil {
		log.Println("No user logged in")
		return nil
	}
	sess, err := cookiestore.DefaultSession(c)
	if err != nil {
		return err
	}
	sess.Options.MaxAge = -1
	sess.Save(c.Request(), c.Response())
	log.Printf("User %v logged out", user.Name)
	return nil
}
