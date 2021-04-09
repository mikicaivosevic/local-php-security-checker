package main

/*

	Checks security issues in project dependencies. Without arguments, it looks
	for a "composer.lock" file in the current directory. Pass it explicitly to check
	a specific "composer.lock" file.

*/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/fabpot/local-php-security-checker/security"
	"github.com/gofiber/fiber/v2"
)

var (
	version = "dev"
	date    = "unknown"
)

type SecurityResponse struct {
	PackageName string `json:"package_name"`
	Vulnerabilities[] *security.Vulnerability `json:"vulnerabilities"`
}

func main() {

	app := fiber.New()
	db, _ := security.NewDB(false)

	app.Post("/api/v1/check", func(c *fiber.Ctx) error {
		composer := c.Body()
		if !json.Valid(composer) {
			c.Status(400)
			return c.JSON("Bad request")
		}
		lockReader := bytes.NewReader(composer)
		lock, _ := security.NewLock(lockReader)
		vulns := security.Analyze(lock, db)
		var responses []SecurityResponse
		item := SecurityResponse{}
		for _, pkg := range vulns.Keys() {
			fmt.Print(pkg)
			v := vulns.Get(pkg)
			item.PackageName = pkg
			item.Vulnerabilities = append(item.Vulnerabilities, v)
			responses = append(responses, item)
		}
		return c.JSON(responses)
	})
	app.Listen(":3000")
}


