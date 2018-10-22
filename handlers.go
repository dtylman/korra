package main

import (
	"log"
	"net/http"

	"github.com/dtylman/korra/auth"
	"github.com/labstack/echo"
)

func newPageData(c echo.Context, title string) map[string]interface{} {
	data := map[string]interface{}{
		"Title":          title,
		title + "Active": "active",
	}
	user, err := auth.LoggedUser(c)
	if err == nil {
		data["UserName"] = user.Name
		data["UserRole"] = user.Role
	}
	return data
}

func handleLoginPost(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")
	err := auth.DoLogin(username, password, c)
	if err != nil {
		log.Print(err)
		data := map[string]interface{}{
			"Title": "Login",
			"Error": err,
		}
		return c.Render(http.StatusOK, "login.html", data)
	}
	return c.Redirect(http.StatusFound, "/")
}

func handleLoginGet(c echo.Context) error {
	data := newPageData(c, "Login")
	return c.Render(http.StatusOK, "login.html", data)
}

func handleLogoutGet(c echo.Context) error {
	err := auth.Logout(c)
	if err != nil {
		return err
	}
	return c.Redirect(http.StatusFound, "/")
}

func handleHomeGet(c echo.Context) error {
	data := newPageData(c, "Korra")
	return c.Render(http.StatusOK, "index.html", data)
}

func handleRolesGet(c echo.Context) error {
	data := newPageData(c, "Roles")
	return c.Render(http.StatusOK, "roles.html", data)
}

func handleSettingsGet(c echo.Context) error {
	data := newPageData(c, "Settings")
	return c.Render(http.StatusOK, "settings.html", data)
}
