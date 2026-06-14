package main

import (
	"os"

	robotsapp "github.com/habralab/habr-nagios-plugins/internal/app/robots"
)

func main() {
	os.Exit(robotsapp.Run(os.Args[0], os.Args[1:]))
}
