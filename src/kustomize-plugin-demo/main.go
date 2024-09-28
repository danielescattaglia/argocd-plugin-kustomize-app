// $GOPATH/src/kustomize-plugin-demo/main.go
package main

import (
	"fmt"
	"os"
	"strings"
	_ "gopkg.in/yaml.v2"

	"github.com/GoogleContainerTools/kpt-functions-sdk/go/fn"
	"github.com/getsops/sops/v3/cmd/sops/formats"
	"github.com/getsops/sops/v3/decrypt"
	_ "sigs.k8s.io/yaml"
	//"sigs.k8s.io/kustomize/kyaml/fn/framework"
	//"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
	//"sigs.k8s.io/kustomize/kyaml/kio"
	//"sigs.k8s.io/kustomize/kyaml/yaml"
)

type kubernetesSecret struct {
	APIVersion string                   
	Kind       string                   
	Metadata   *fn.SubObject     
	Type       string                  
    Data       *fn.SubObject     
	StringData *fn.SubObject        
	Sops       *fn.SubObject   
}

func help() {
	msg := `
		ESOPS is a flexible kustomize plugin for SOPS encrypted resources.
		ESOPS supports KRM style exec kustomize functions.

		kustomize Usage:
		- kustomize build --enable-alpha-plugins --enable-exec

		Standalone Usage :
		- KRM: cat secret-generator.yaml | esops
`
	fmt.Fprintf(os.Stderr, "%s", strings.ReplaceAll(msg, "		", ""))
	os.Exit(1)
}

func krm(rl *fn.ResourceList) (bool, error) {
    var items fn.KubeObjects
    var modifiedItem []byte

    for _, manifest := range rl.Items {
        if string(manifest.GetKind()) == "Secret" {
            var m kubernetesSecret            
            
            m.APIVersion = manifest.GetAPIVersion()
            m.Kind = manifest.GetKind()
            m.Type = manifest.GetString("type")

            if manifest.GetMap("data") != nil {
                m.Data = manifest.GetMap("data")
            }

            if manifest.GetMap("stringData") != nil {
                m.Data = manifest.GetMap("stringData")
            }

            if manifest.GetMap("sops") != nil {
                m.Sops = manifest.GetMap("sops")
            }
            
            if manifest.GetMap("metadata") != nil {
                m.Metadata = manifest.GetMap("metadata")
            }

            krmAnnotations := make(map[string]string)
            secretAnnotations := make(map[string]string)

            for annotation, value := range manifest.GetAnnotations() {                
                if strings.HasPrefix(annotation, "config.kubernetes.io/") {
                    krmAnnotations[annotation] = value
                } else if strings.HasPrefix(annotation, "internal.config.kubernetes.io/") {
                    krmAnnotations[annotation] = value
                } else if strings.HasPrefix(annotation, "kustomize.config.k8s.io/") {
                    krmAnnotations[annotation] = value
                } else if strings.HasPrefix(annotation, "config.k8s.io/") {
                    krmAnnotations[annotation] = value
                } else {
                    secretAnnotations[annotation] = value
                }
            }
        
            // TODO: decrypt potrebbe andare in errore nel caso in cui siano state aggiunte annotations
            // poi rimosse prima di dare in pasto al manifest a sops. Al momento sono rimosse prima
            // solo quelle well-known ma se ne esistevano prima del filtro kustomize, sono rimosse
            // e il mac del sops cambia. 

            manifest.GetMap("metadata").RemoveNestedField("annotations")            
            for k, v := range secretAnnotations {
                manifest.SetAnnotation(k, v)
            }
                
            decrypted , err := decryptContent(manifest.String())
            if err != nil {
            	fmt.Fprintf(os.Stderr, "unable to decrypt manifests: %v", err)
            	return false, err
            }
                                    
            // terminata la decriptazione reinserisce le label            
            finalManifest, err := fn.ParseKubeObject(decrypted)
            if err != nil {
            	fmt.Fprintf(os.Stderr, "Error parsing manifests: %v", err)
            	return false, err
            }

            for k, v := range krmAnnotations {
                finalManifest.SetAnnotation(k, v)
            }

            modifiedItem = []byte(finalManifest.String())
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
		fmt.Fprintf(os.Stderr, "unable to generate final manifests: %v", err)
		os.Exit(1)
	}
}
