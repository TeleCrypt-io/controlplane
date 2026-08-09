package steward

import (
	_ "embed"
	"html/template"
)

// The Plan presentation is kept in local embedded assets. This makes the page
// independently maintainable without introducing a frontend build or a runtime
// dependency. Its tokens mirror the framework-neutral shared UI package:
// light canvas and surfaces, system type, compact controls, small radii, and
// neutral borders. Product identity remains local: Plan uses TeleCrypt's
// original custom mark, not a Storage-specific product icon.

//go:embed assets/plan.html
var planHTML string

// planProductCSS is vendored byte-for-byte from the exact shared UI release
// source used by Storage. It is embedded because Steward has no frontend build
// or runtime package manager.
//
//go:embed assets/product.css
var planProductCSS []byte

//go:embed assets/plan.css
var planCSS []byte

//go:embed assets/plan.js
var planJS []byte

//go:embed assets/logo-mark.png
var planLogoPNG []byte

var planTmpl = template.Must(template.New("plan").Parse(planHTML))
