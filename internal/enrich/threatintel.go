package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type ThreatResult struct {
	Malicious bool
	Source    string
	Details   string
}

type ThreatProvider interface {
	LookupIP(context.Context, string) (ThreatResult, error)
}

type ThreatChain []ThreatProvider

func (c ThreatChain) LookupIP(ctx context.Context, ip string) (ThreatResult, error) {
	for _, p := range c {
		r, err := p.LookupIP(ctx, ip)
		if err == nil && r.Malicious {
			return r, nil
		}
	}
	return ThreatResult{}, nil
}

type AbuseIPDB struct {
	BaseURL, APIKey string
	Client          *http.Client
}

func (p AbuseIPDB) LookupIP(ctx context.Context, ip string) (ThreatResult, error) {
	if p.APIKey == "" {
		return ThreatResult{}, fmt.Errorf("abuseipdb API key is required")
	}
	base := p.BaseURL
	if base == "" {
		base = "https://api.abuseipdb.com/api/v2"
	}
	u := strings.TrimRight(base, "/") + "/check?ipAddress=" + url.QueryEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ThreatResult{}, err
	}
	req.Header.Set("Key", p.APIKey)
	req.Header.Set("Accept", "application/json")
	resp, err := client(p.Client).Do(req)
	if err != nil {
		return ThreatResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ThreatResult{}, fmt.Errorf("abuseipdb HTTP %s", resp.Status)
	}
	var v struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return ThreatResult{}, err
	}
	return ThreatResult{Malicious: v.Data.AbuseConfidenceScore >= 50, Source: "abuseipdb", Details: fmt.Sprintf("confidence=%d", v.Data.AbuseConfidenceScore)}, nil
}

type VirusTotal struct {
	BaseURL, APIKey string
	Client          *http.Client
}

func (p VirusTotal) LookupIP(ctx context.Context, ip string) (ThreatResult, error) {
	if p.APIKey == "" {
		return ThreatResult{}, fmt.Errorf("virustotal API key is required")
	}
	base := p.BaseURL
	if base == "" {
		base = "https://www.virustotal.com/api/v3"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/ip_addresses/"+url.PathEscape(ip), nil)
	if err != nil {
		return ThreatResult{}, err
	}
	req.Header.Set("x-apikey", p.APIKey)
	resp, err := client(p.Client).Do(req)
	if err != nil {
		return ThreatResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return ThreatResult{}, fmt.Errorf("virustotal HTTP %s", resp.Status)
	}
	var v struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious int `json:"malicious"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return ThreatResult{}, err
	}
	return ThreatResult{Malicious: v.Data.Attributes.LastAnalysisStats.Malicious > 0, Source: "virustotal", Details: fmt.Sprintf("malicious=%d", v.Data.Attributes.LastAnalysisStats.Malicious)}, nil
}

type CachedThreat struct {
	Result    ThreatResult
	ExpiresAt time.Time
}
type ThreatCache struct {
	mu     sync.Mutex
	ttl    time.Duration
	values map[string]CachedThreat
}

func NewThreatCache(ttl time.Duration) *ThreatCache {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &ThreatCache{ttl: ttl, values: map[string]CachedThreat{}}
}
func (c *ThreatCache) Lookup(ctx context.Context, ip string, p ThreatProvider) (ThreatResult, error) {
	c.mu.Lock()
	v, ok := c.values[ip]
	c.mu.Unlock()
	if ok && time.Now().Before(v.ExpiresAt) {
		return v.Result, nil
	}
	r, err := p.LookupIP(ctx, ip)
	if err != nil {
		return ThreatResult{}, err
	}
	c.mu.Lock()
	c.values[ip] = CachedThreat{Result: r, ExpiresAt: time.Now().Add(c.ttl)}
	c.mu.Unlock()
	return r, nil
}

func client(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 5 * time.Second}
}
