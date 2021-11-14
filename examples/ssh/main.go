package main

import (
	"net/http"
	"os"

	"github.com/c032/authwall"
	awSSH "github.com/c032/authwall/providers/ssh"

	"github.com/c032/go-logger"
	"golang.org/x/crypto/ssh"
)

func main() {
	log := logger.Default

	const addr = ":3333"

	sshProvider := &awSSH.Provider{
		Logger: log,
		Host:   "sftp.example.com:22",

		// FIXME.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	s := &authwall.Server{
		Logger: log,

		// E.g. `python -m http.server`.
		BackendURL: "http://127.0.0.1:8000/",

		VerboseHTTPServerErrors: true,
		LoginPathPrefix:         "/login/",
		Providers: []authwall.Provider{
			sshProvider,
		},
	}

	var err error

	err = s.Open()
	if err != nil {
		log.Print(err)

		os.Exit(1)
	}
	defer s.Close()

	err = http.ListenAndServe(addr, s)
	if err != nil {
		log.Print(err)

		os.Exit(1)
	}
}
