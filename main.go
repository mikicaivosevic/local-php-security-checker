package main

/*

	Checks security issues in project dependencies. Without arguments, it looks
	for a "composer.lock" file in the current directory. Pass it explicitly to check
	a specific "composer.lock" file.

*/

import (
	"bytes"
	"encoding/json"
	"github.com/fabpot/local-php-security-checker/security"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"
)

var (
	version = "dev"
	date    = "unknown"
)

type PackageResponse struct {
	PackageName string `json:"package_name"`
	Vulnerabilities[] *security.Vulnerability `json:"vulnerabilities"`
}

type ApiResponse struct {
	Data []PackageResponse `json:"data"`
}

func apiSecurityHandler(db *security.AdvisoryDB) fiber.Handler {
	return func(c *fiber.Ctx) error {
		composer := c.Body()
		if !json.Valid(composer) {
			c.Status(400)
			return c.JSON("Bad request")
		}
		lockReader := bytes.NewReader(composer)
		lock, _ := security.NewLock(lockReader)
		vulns := security.Analyze(lock, db)
		var response ApiResponse
		item := PackageResponse{}
		for _, pkg := range vulns.Keys() {
			v := vulns.Get(pkg)
			item.PackageName = pkg
			item.Vulnerabilities = append(item.Vulnerabilities, v)
			response.Data = append(response.Data, item)
		}
		return c.JSON(response)
	}
}

func homeHandler(c *fiber.Ctx) error {
	return c.Render("index", fiber.Map{})
}


func main() {

	engine := html.New("./views", ".html")
	app := fiber.New(fiber.Config{
		Views: engine,
	})
	db, _ := security.NewDB(false)

	app.Get("/", homeHandler)
	app.Post("/api/v1/check", apiSecurityHandler(db))
	app.Listen(":3000")
}



