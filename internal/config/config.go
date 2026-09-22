package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Storage struct {
		Path string `yaml:"path"`
	} `yaml:"storage"`
	Correlation struct {
		Window           time.Duration `yaml:"window"`
		MaxIncidentAge   time.Duration `yaml:"max_incident_age"`
		SuppressionsFile string        `yaml:"suppressions_file"`
	} `yaml:"correlation"`
	Enrichment struct {
		AssetsFile string `yaml:"assets_file"`
		IOCFile    string `yaml:"ioc_file"`
		AbuseIPDB  struct {
			BaseURL   string `yaml:"base_url"`
			APIKeyEnv string `yaml:"api_key_env"`
		} `yaml:"abuseipdb"`
		VirusTotal struct {
			BaseURL   string `yaml:"base_url"`
			APIKeyEnv string `yaml:"api_key_env"`
		} `yaml:"virustotal"`
	} `yaml:"enrichment"`
	Triage struct {
		LLMThreshold int    `yaml:"llm_threshold"`
		Mode         string `yaml:"mode"`
	} `yaml:"triage"`
}

func Defaults() Config {
	var c Config
	c.Storage.Path = "data/triage.db"
	c.Correlation.Window = 15 * time.Minute
	c.Correlation.MaxIncidentAge = 6 * time.Hour
	c.Triage.LLMThreshold = 40
	c.Triage.Mode = "rule-only"
	return c
}
func Load(path string) (Config, error) {
	c := Defaults()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err = yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	if c.Storage.Path == "" {
		c.Storage.Path = "data/triage.db"
	}
	if c.Correlation.Window <= 0 {
		c.Correlation.Window = 15 * time.Minute
	}
	if c.Correlation.MaxIncidentAge <= 0 {
		c.Correlation.MaxIncidentAge = 6 * time.Hour
	}
	if c.Triage.Mode == "" {
		c.Triage.Mode = "rule-only"
	}
	return c, nil
}
