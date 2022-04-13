package internal

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"

	logger "github.com/sirupsen/logrus"
)

func unzipFromReader(rdr *bytes.Reader, fileName string) ([]byte, error) {
	unzip, err := zip.NewReader(rdr, rdr.Size())
	if err != nil {
		logger.Error("Error unzip")
		return nil, err
	}

	for _, file := range unzip.File {
		if fileName == file.Name {
			rc, err := file.Open()

			if err != nil {
				logger.Error("Error file open")
				return nil, err
			}

			bt, err := ioutil.ReadAll(rc)
			if err != nil {
				return nil, err
			}
			logger.Debugf("read %d byte", len(bt))
			rc.Close()
			return bt, nil
		}
	}
	return nil, fmt.Errorf("didn't find %s in zip", fileName)
}
