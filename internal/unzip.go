package internal

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/steffakasid/eslog"
)

func unzipFromReader(rdr *bytes.Reader, fileName string) ([]byte, error) {
	unzip, err := zip.NewReader(rdr, rdr.Size())
	if err != nil {
		eslog.Error("Error unzip")
		return nil, err
	}

	for _, file := range unzip.File {
		if fileName == file.Name {
			rc, err := file.Open()

			if err != nil {
				eslog.Error("Error file open")
				return nil, err
			}

			bt, err := ioutil.ReadAll(rc)
			if err != nil {
				return nil, err
			}
			eslog.Debugf("read %d byte", len(bt))
			rc.Close()
			return bt, nil
		}
	}
	return nil, fmt.Errorf("didn't find %s in zip", fileName)
}
