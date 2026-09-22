package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Storage struct {
		Path      string    `yaml:"path"`
		Retention Retention `yaml:"retention"`
	} `yaml:"storage"`
	Correlation struct {
		Window           time.Duration `yaml:"window"`
		MaxIncidentAge   time.Duration `yaml:"max_incident_age"`
		SuppressionsFile string        `yaml:"suppressions_file"`
		Grouping         Grouping      `yaml:"grouping"`
	} `yaml:"correlation"`
	Enrichment struct {
		AssetsFile string `yaml:"assets_file"`
		IOCFile    string `yaml:"ioc_file"`
		GeoIPFile  string `yaml:"geoip_file"`
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
		LLMThreshold int        `yaml:"llm_threshold"`
		Mode         string     `yaml:"mode"`
		Providers    []Provider `yaml:"providers"`
		Budget       Budget     `yaml:"budget"`
	} `yaml:"triage"`
}

type Grouping struct {
	Default   []string           `yaml:"default"`
	Overrides []GroupingOverride `yaml:"overrides"`
}

type GroupingOverride struct {
	Match GroupingMatch `yaml:"match"`
	Key   []string      `yaml:"key"`
}

type GroupingMatch struct {
	Groups []string `yaml:"groups"`
}

type Retention struct {
	Alerts   time.Duration `yaml:"alerts"`
	LLMCalls time.Duration `yaml:"llm_calls"`
}

type Provider struct {
	Name      string `yaml:"name"`
	Type      string `yaml:"type"`
	BaseURL   string `yaml:"base_url"`
	Model     string `yaml:"model"`
	APIKeyEnv string `yaml:"api_key_env"`
}
type Budget struct {
	CallsPerHour int     `yaml:"calls_per_hour"`
	USDPerDay    float64 `yaml:"usd_per_day"`
	CostPerCall  float64 `yaml:"cost_per_call"`
}

func Defaults() Config {
	var c Config
	c.Storage.Path = "data/triage.db"
	c.Storage.Retention.Alerts = 30 * 24 * time.Hour
	c.Storage.Retention.LLMCalls = 90 * 24 * time.Hour
	c.Correlation.Window = 15 * time.Minute
	c.Correlation.MaxIncidentAge = 6 * time.Hour
	c.Correlation.Grouping.Default = []string{"rule.id", "agent.id", "src_ip"}
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
	if c.Storage.Retention.Alerts <= 0 {
		c.Storage.Retention.Alerts = 30 * 24 * time.Hour
	}
	if c.Storage.Retention.LLMCalls <= 0 {
		c.Storage.Retention.LLMCalls = 90 * 24 * time.Hour
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
