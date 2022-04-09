package internal

import (
	"bytes"
	"fmt"
	"os"
	"path"

	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"go.mozilla.org/sops/decrypt"
)

const (
	configFileType = "yaml"
	configFileName = ".trivyops"
)

const (
	GITLAB_HOST  = "GITLAB_HOST"
	GTILAB_TOKEN = "GITLAB_TOKEN"
	LOG_LEVEL    = "LOG_LEVEL"
	METRICS_PORT = "METRICS_PORT"
)

func init() {
	err := viper.BindEnv(GTILAB_TOKEN)
	if err != nil {
		logger.Error(err)
	}
	viper.SetDefault(GITLAB_HOST, "https://gitlab.com")
	viper.SetDefault(LOG_LEVEL, "info")
	viper.SetDefault(METRICS_PORT, 2112)
}

func InitConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		logger.Fatal(err)
	}

	viper.AddConfigPath(home)
	viper.SetConfigType(configFileType)
	viper.SetConfigName(configFileName)

	usedConfigFile := getConfigFilename(home)
	if usedConfigFile != "" {
		cleartext, err := decrypt.File(usedConfigFile, configFileType)

		if err != nil {
			logger.Warnf("Error decrypting. %s. Maybe you're not using an encrypted config?", err)
			if err := viper.ReadInConfig(); err != nil {
				logger.Warnf("Error reading config. %s. Are you using a config?", err)
			} else {
				logger.Debug("Using config file:", viper.ConfigFileUsed())
			}
		} else {
			if err := viper.ReadConfig(bytes.NewBuffer(cleartext)); err != nil {
				logger.Fatal(err)
			} else {
				logger.Debug("Using sops encrypted config file:", viper.ConfigFileUsed())
			}
		}
		viper.AutomaticEnv()
		SetLogLevel()
	} else {
		logger.Debug("No config file used!")
	}
}

func getConfigFilename(homedir string) string {
	pathWithoutExt := path.Join(homedir, configFileName)
	logger.Debugf("Check if %s exists", pathWithoutExt)
	if _, err := os.Stat(pathWithoutExt); err == nil {
		return pathWithoutExt
	}

	pathWithExt := fmt.Sprintf("%s.%s", pathWithoutExt, configFileType)
	logger.Debugf("Check if %s exists", pathWithExt)
	if _, err := os.Stat(pathWithExt); err == nil {
		return pathWithExt
	}
	pathWithExt = fmt.Sprintf("%s.%s", pathWithoutExt, "yml")
	logger.Debugf("Check if %s exists", pathWithExt)
	if _, err := os.Stat(pathWithExt); err == nil {
		return pathWithExt
	}
	return ""
}

func SetLogLevel() {
	lvl, err := logger.ParseLevel(viper.GetString(LOG_LEVEL))
	if err == nil {
		logger.SetLevel(lvl)
	} else {
		logger.Error(err)
	}
}
