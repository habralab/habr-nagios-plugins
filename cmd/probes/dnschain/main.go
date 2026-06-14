package main

import (
	"os"

	dnschainapp "github.com/habralab/habr-nagios-plugins/internal/app/dnschain"
)

func main() {
	os.Exit(dnschainapp.Run(os.Args[0], os.Args[1:]))
}
