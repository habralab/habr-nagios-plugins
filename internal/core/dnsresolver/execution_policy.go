package dnsresolver

type glueAcceptanceMode string

const (
	glueAcceptanceStrict     glueAcceptanceMode = "strict"
	glueAcceptanceNormal     glueAcceptanceMode = "normal"
	glueAcceptancePermissive glueAcceptanceMode = "permissive"
)

type executionPolicy struct {
	GlueMode glueAcceptanceMode
}

func defaultExecutionPolicy() executionPolicy {
	return executionPolicy{
		GlueMode: glueAcceptancePermissive,
	}
}
