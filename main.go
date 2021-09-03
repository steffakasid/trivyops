package main

import (
	"flag"
	"log"

	"github.com/steffakasid/trivy-scanner/pkg"
)

var (
	groupId string
)

func main() {
	flag.StringVar(&groupId, "group-id", "", "Set group-id to scan for trivy results")
	flag.Parse()
	_, err := pkg.ScanGroup(groupId)
	if err != nil {
		log.Fatalf("Failed to scan trivy results: %s!", err)
	}
}
