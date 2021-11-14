package authwall

import (
	"fmt"
	"html/template"
)

var defaultFuncMap = template.FuncMap{
	"tabindex": func(i int) string {
		return fmt.Sprintf("%d", i+1)
	},
	"autofocus": func(i int) string {
		if i == 0 {
			return "autofocus"
		}

		return ""
	},
	"inputtype": func(isSecret bool) string {
		if isSecret {
			return "password"
		}

		return "text"
	},
}
