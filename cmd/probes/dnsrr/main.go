package main

import (
	"os"

	dnsrrapp "github.com/habralab/habr-nagios-plugins/internal/app/dnsrr"
)

func main() {
	os.Exit(dnsrrapp.Run(os.Args[0], os.Args[1:]))
}
