package output

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/steffakasid/trivy-scanner/internal"
)

func Json(results internal.TrivyResults, outputFile string) {
	file, _ := json.MarshalIndent(results, "", "  ")
	if len(outputFile) > 0 {
		if err := ioutil.WriteFile(outputFile, file, 0644); err != nil {
			panic(err)
		}
	} else {
		fmt.Println(string(file))
	}
}
