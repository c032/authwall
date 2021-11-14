package authwall

import (
	"html/template"
)

var tmplLogin = template.Must(
	template.Must(tmplLayout.Clone()).New("login").Parse(`
		{{define "login-form"}}
			<main>
				<form method="POST">
					<header>
						<h1>
							Login

							{{$howManyProviders := len .Providers}}
							{{if gt $howManyProviders 1}}
								({{.SelectedProvider.Name}})
							{{end}}
						</h1>
					</header>

					<input
						id="authwall_provider_id"
						name="authwall_provider_id"
						type="hidden"
						value="{{.SelectedProvider.ID}}"
					>

					{{range $index, $element := .SelectedProvider.Fields}}
						<div>
							<label for="{{.ID}}">
								{{.Name}}
							</label>

							<input
								id="{{.ID}}"
								name="{{.ID}}"
								placeholder="{{.Name}}"
								tabindex="{{$index | tabindex}}"
								type="{{.IsSecret | inputtype}}"

								{{$autofocus := $index | autofocus}}
								{{if $autofocus}}
									{{$autofocus}}
								{{end}}

								{{if .IsRequired}}
									required
								{{end}}
							>
						</div>
					{{end}}

					<div>&nbsp;</div>

					<div>
						<button
							tabindex="3"
							type="submit"
						>
							Log in
						</button>
					</div>
				</form>
			</main>
		{{end}}

		{{define "body"}}
			{{template "login-form" .}}
		{{end}}
	`),
)

type PageLogin struct {
	Page

	ErrorMessage string

	Providers        []Provider
	SelectedProvider Provider
}
