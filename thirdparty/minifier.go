package thirdparty

import (
	"bytes"
	"fmt"

	minify "github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
)

var Minifier = minify.New()

func init() {
	Minifier.AddFunc("text/html", html.Minify)
	Minifier.AddFunc("text/css", css.Minify)

	RawInlineStyleNormalize = fmt.Sprintf(
		`<style
			data-github-repository="necolas/normalize.css"
			data-license="MIT"
		>
			%s
		</style>
		`,
		MustMinifyCSS(rawCSSNormalize),
	)
}

func MustMinifyHTML(unminifiedHTML string) string {
	var err error

	out := &bytes.Buffer{}
	in := bytes.NewBufferString(unminifiedHTML)

	err = Minifier.Minify("text/html", out, in)
	if err != nil {
		panic(err)
	}

	return out.String()
}

func MustMinifyCSS(unminifiedCSS string) string {
	var err error

	out := &bytes.Buffer{}
	in := bytes.NewBufferString(unminifiedCSS)

	err = Minifier.Minify("text/css", out, in)
	if err != nil {
		panic(err)
	}

	return out.String()
}
