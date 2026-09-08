// Package config loads Mansa configuration from YAML files, environment
// variables, and CLI flags. A missing config file is not an error; a
// malformed one is.
package config

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Load reads Mansa configuration from cfgFile (or default search dirs)
// and merges environment variables prefixed QYVORA_MANSA_.
func Load(cfgFile string) (*viper.Viper, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	for _, dir := range configSearchDirs(cfgFile) {
		v.AddConfigPath(dir)
	}
	v.SetEnvPrefix("QYVORA_MANSA")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()
	setDefaults(v)
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	}
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return v, err
		}
	}
	return v, nil
}

func configSearchDirs(cfgFile string) []string {
	dirs := []string{"."}
	if cfgFile != "" {
		if dir := filepath.Dir(cfgFile); dir != "." {
			dirs = append([]string{dir}, dirs...)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs,
			filepath.Join(home, ".qyvora-mansa"),
			filepath.Join(home, ".config", "qyvora", "mansa"),
		)
	}
	dirs = append(dirs, "/etc/qyvora-mansa")
	return dirs
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("authorized", false)
	v.SetDefault("output", "terminal")
	v.SetDefault("verbose", false)
	v.SetDefault("quiet", false)
	v.SetDefault("report.dir", "reports")
	v.SetDefault("report.format", "terminal")
	v.SetDefault("session.dir", "")
	v.SetDefault("log.level", "info")
	v.SetDefault("wireless.interface", "")
	v.SetDefault("wireless.timeout_seconds", 30)
	v.SetDefault("analysis.confidence_threshold", "medium")
}

// Timeout returns the wireless scan timeout.
func Timeout(v *viper.Viper) time.Duration {
	secs := v.GetInt("wireless.timeout_seconds")
	if secs <= 0 {
		secs = 30
	}
	return time.Duration(secs) * time.Second
}
