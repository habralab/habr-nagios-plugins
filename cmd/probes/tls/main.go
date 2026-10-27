package main

import (
	"os"

	tlsapp "github.com/habralab/habr-nagios-plugins/internal/app/tls"
)

func main() {
	os.Exit(tlsapp.Run(os.Args[0], os.Args[1:]))
}
