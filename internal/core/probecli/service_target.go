package probecli

import (
	"fmt"
	"strconv"
	"strings"
)

type ServiceTargetInput struct {
	Hostname string
	Port     int
}

type ServiceTarget struct {
	Hostname string
	Port     int
	Service  string
}

func ServiceTargetInputSpecs(defaultPort int) []InputSpec {
	return []InputSpec{
		{
			Key:  "hostname",
			Type: InputString,
			Aliases: []InputAlias{
				{Short: "H", Usage: "target hostname"},
				{Long: "hostname", Usage: "target hostname"},
			},
		},
		{
			Key:     "port",
			Type:    InputInt,
			Default: strconv.Itoa(defaultPort),
			Aliases: []InputAlias{
				{Short: "p", Usage: "target port"},
				{Long: "port", Usage: "target port"},
			},
		},
	}
}

func ResolveServiceTargetInput(input ServiceTargetInput) (ServiceTarget, error) {
	host := strings.TrimSuffix(strings.TrimSpace(input.Hostname), ".")
	if host == "" {
		return ServiceTarget{}, ErrInputRequired(InputRefHostname)
	}
	if input.Port <= 0 || input.Port > 65535 {
		return ServiceTarget{}, ErrInputConstraint(InputRefPort, "must be in range 1..65535")
	}
	return ServiceTarget{
		Hostname: host,
		Port:     input.Port,
		Service:  fmt.Sprintf("%s:%d", host, input.Port),
	}, nil
}
