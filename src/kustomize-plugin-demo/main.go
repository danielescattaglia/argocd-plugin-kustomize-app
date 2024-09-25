// $GOPATH/src/kustomize-plugin-demo/main.go
package main

import (
  "os"
  "fmt"
  "strings"

  "github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
  "sigs.k8s.io/kustomize/api/types"
  _ "sigs.k8s.io/yaml"
  "github.com/getsops/sops/v3/decrypt"
  "github.com/getsops/sops/v3/cmd/sops/formats"

  //"sigs.k8s.io/kustomize/kyaml/fn/framework"
  //"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
  //"sigs.k8s.io/kustomize/kyaml/kio"
  //"sigs.k8s.io/kustomize/kyaml/yaml"
)

type kubernetesSecret struct {
	APIVersion string            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string            `json:"kind" yaml:"kind"`
	Metadata   types.ObjectMeta  `json:"metadata" yaml:"metadata"`
	Type       string            `json:"type,omitempty" yaml:"type,omitempty"`
	StringData map[string]string `json:"stringData,omitempty" yaml:"stringData,omitempty"`
	Data       map[string]string `json:"data,omitempty" yaml:"data,omitempty"`
}

func help() {
	msg := `
		KSOPS is a flexible kustomize plugin for SOPS encrypted resources.
		KSOPS supports both legacy and KRM style exec kustomize functions.

		kustomize Usage:
		- kustomize build --enable-alpha-plugins --enable-exec

		Standalone Usage :
		- Legacy: ksops secret-generator.yaml
		- KRM: cat secret-generator.yaml | ksops
`
	fmt.Fprintf(os.Stderr, "%s", strings.ReplaceAll(msg, "		", ""))
	os.Exit(1)
}

func krm(rl *fn.ResourceList) (bool, error) {
    var items fn.KubeObjects
    var modifiedItem []byte

    for _, manifest := range rl.Items {
        if string(manifest.GetKind()) == "Secret" {
            decrypted, err := decryptContent(manifest.String())
            if err != nil {
            	fmt.Fprintf(os.Stderr, "unable to generate manifests: %v", err)
            	fmt.Fprintf(os.Stderr, "unable to generate manifests: %s", manifest.String())
            	return false, err
            }

            modifiedItem = decrypted
        } else {
            fmt.Println("Unable to decrypt: " + string(manifest.GetKind()))
            modifiedItem  = []byte(manifest.String())
        }

        objs, err := fn.ParseKubeObjects(modifiedItem)
        if err != nil {
            rl.LogResult(err)
        	return false, err
        }
        items = append(items, objs...)
    }

    rl.Items = items

    return true, nil
}

func decryptContent(content string) ([]byte, error) {
    format := formats.FormatFromString("yaml")

	data, err := decryptBytes([]byte(content), format)

    if err != nil {
        fmt.Println(err)
        return nil, err
    }

	return data, nil
}

func decryptBytes(b []byte, f formats.Format) ([]byte, error) {
	data, err := decrypt.DataWithFormat(b, f)

	if err != nil {
		return nil, fmt.Errorf("trouble decrypting file: %w", err)
	}
	return data, nil
}

func main() {
    stat, _ := os.Stdin.Stat()

	// Check the StdIn content.
	if !(stat.Mode()&os.ModeCharDevice == 0) {
		help()
	}
	err := fn.AsMain(fn.ResourceListProcessorFunc(krm))
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to generate manifests: %v", err)
		os.Exit(1)
	}
	return
}
