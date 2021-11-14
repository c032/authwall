package authwall

import (
	"fmt"

	"github.com/c032/authwall/thirdparty"
)

var rawInlineStyle = fmt.Sprintf("<style>%s</style>", thirdparty.MustMinifyCSS(`
	:root {
		--field-padding: .5rem;
		--field-border-radius: 8px;

		font-size: 16px;
	}

	* {
		box-sizing: border-box;
	}

	html, body {
		margin: 0;
		padding: 0;
	}

	body {
		background: #f0f0f0;
		color: #222;
		font-family: sans-serif;
		font-size: 1rem;
	}

	.container {
		clear: both;
		margin: 0 auto;
		max-width: 1200px;
		width: 80vw;
	}
	.container::after {
		clear: both;
		content: ' ';
		display: block;
		float: none;
	}

	a,
	a:link,
	a:visited,
	a:hover,
	a:active {
		color: #333;
	}

	main {
		min-height: 100vh;
		position: relative;
	}

	main > form {
		left: 50%;
		max-width: 400px;
		position: absolute;
		top: 40%;
		transform: translateX(-50%) translateY(-50%);
		width: 80%;
	}

	main > form > div {
		margin: 1rem 0;
	}

	main > form > div > label {
		display: block;
		padding: var(--field-padding) 0;
		width: 100%;
	}

	main > form > div > input {
		border: 1px solid #ccc;
		display: block;
		padding: var(--field-padding);
		width: 100%;
	}

	main > form button {
		background: #0074d9;
		border-radius: var(--field-border-radius);
		border: 1px solid transparent;
		color: #fff;
		display: block;
		padding: var(--field-padding);
		width: 100%;
	}
`))
