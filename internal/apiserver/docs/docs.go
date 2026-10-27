// Package docs embeds openapi.yaml at compile time and converts it to
// JSON once, so handlers can serve fixed bytes with no filesystem I/O.
package docs

import (
	_ "embed"
	"fmt"

	"sigs.k8s.io/yaml"
)

//go:embed openapi.yaml
var openAPIYAML []byte

var SwaggerJSON []byte

func init() {
	j, err := yaml.YAMLToJSON(openAPIYAML)
	if err != nil {
		panic(fmt.Sprintf("docs: openapi.yaml is not valid YAML: %v", err))
	}
	SwaggerJSON = j
}
