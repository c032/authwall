package authwall

import (
	"html/template"

	"github.com/c032/authwall/thirdparty"
)

var tmplLayout = template.Must(
	template.New("layout").Funcs(defaultFuncMap).Parse(`
		{{define "layout"}}
			<!doctype html>
			<html>
			<head>
				<meta charset="utf-8">
				<title>{{.Title}}</title>
				<link rel="icon" href="data:,">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				` + thirdparty.RawInlineStyleNormalize + `
				` + rawInlineStyle + `
			</head>
			<body>
				{{template "body" .}}
			</body>
			</html>
		{{end}}
	`),
)
