package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/spf13/viper"
	"github.com/steffakasid/trivy-scanner/internal"
)

func printResultJson(results internal.TrivyResults) {
	file, _ := json.MarshalIndent(results, "", "  ")
	if len(viper.GetString(OUTPUT_FILE)) > 0 {
		if err := ioutil.WriteFile(viper.GetString(OUTPUT_FILE), file, 0644); err != nil {
			panic(err)
		}
	} else {
		fmt.Println(string(file))
	}
}
