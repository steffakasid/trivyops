package main

import (
	"flag"
	"log"

	"github.com/steffakasid/trivy-scanner/pkg"
)

var (
	groupId       string
	trivyJobName  string
	trivyFileName string
	help          bool
)

func main() {
	flag.StringVar(&groupId, "group-id", "", "Set group-id to scan for trivy results")
	flag.StringVar(&trivyJobName, "job-name", "scan_oci_image_trivy", "The gitlab ci jobname to check")
	flag.StringVar(&trivyFileName, "artifact-name", "trivy-results.json", "The artifact filename of the trivy result")
	flag.BoolVar(&help, "help", false, "Print help message")
	flag.Parse()
	if help {
		flag.Usage()
	} else {
		scan := pkg.Scan{ID: groupId, JobName: trivyJobName, ArtifactFileName: trivyFileName}
		_, err := scan.ScanGroup()
		if err != nil {
			log.Fatalf("Failed to scan trivy results: %s!", err)
		}
	}
}
