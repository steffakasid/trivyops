package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/steffakasid/trivy-scanner/pkg"
)

func printResultJson(results pkg.TrivyResults) {
	file, _ := json.Marshal(results)
	if err := ioutil.WriteFile("result.json", file, 0644); err != nil {
		panic(err)
	}
}
