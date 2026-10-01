package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/adikezh/siem-triage-agent/internal/config"
	"github.com/adikezh/siem-triage-agent/internal/enrich"
	"github.com/adikezh/siem-triage-agent/internal/ingest"
	"github.com/adikezh/siem-triage-agent/internal/pipeline"
	"github.com/adikezh/siem-triage-agent/internal/rules"
	"github.com/adikezh/siem-triage-agent/internal/store"
	triageengine "github.com/adikezh/siem-triage-agent/internal/triage"
	"github.com/adikezh/siem-triage-agent/internal/triage/llm"
	"github.com/adikezh/siem-triage-agent/internal/triage/scoring"
)

type liveProcessor struct {
	db                                *store.Store
	correlationWindow, maxIncidentAge time.Duration
	grouping                          config.Grouping
	internalCIDRs                     []string
	assets                            map[string]enrich.Asset
	iocs                              enrich.IOC
	geoip                             *enrich.GeoIP
	engine                            *triageengine.Engine
	sender                            pipeline.Sender
	suppressionFile                   string
}

func (p liveProcessor) Prepare(ctx context.Context, hits []ingest.Hit) (store.Page, error) {
	var page store.Page
	suppressions, err := liveSuppressions(ctx, p.db, p.suppressionFile)
	if err != nil {
		return page, fmt.Errorf("load suppressions: %w", err)
	}
	accepted := make([]Alert, 0, len(hits))
	for _, hit := range hits {
		payload := ingest.NormalizeHit(hit)
		encoded, err := json.Marshal(payload)
		if err != nil {
			return page, err
		}
		var alert Alert
		if err := json.Unmarshal(encoded, &alert); err != nil {
			return page, fmt.Errorf("normalize source alert: %w", err)
		}
		// Identity and time belong to the source envelope, not untrusted fields
		// named id/timestamp inside a Wazuh document.
		alert.ID, alert.Timestamp = hit.ID, hit.Timestamp
		alert.Internal = enrich.IsInternal(alert.SrcIP, p.internalCIDRs)
		agentID, _ := alert.Agent["id"].(string)
		decision := rules.Evaluate(rules.Alert{RuleID: alert.RuleID, RuleDesc: alert.RuleDesc, SrcIP: alert.SrcIP, Groups: alert.Groups, AgentID: agentID, Fingerprint: alertFingerprint(alert, p.grouping)}, suppressions, time.Now().UTC())
		if decision.Downgrade && alert.RuleLevel > 3 {
			alert.RuleLevel = 3
		}
		alert.Tag = decision.Tag
		if asset, ok := enrich.Apply(p.assets, alert.SrcIP); ok {
			alert.Criticality = asset.Criticality
		}
		alert.Malicious = p.iocs.MaliciousIP(alert.SrcIP)
		adjusted, err := json.Marshal(alert)
		if err != nil {
			return page, err
		}
		if err := json.Unmarshal(adjusted, &payload); err != nil {
			return page, err
		}
		payload["suppressed"] = decision.Suppressed
		page.Alerts = append(page.Alerts, store.AlertWrite{ID: hit.ID, Source: "wazuh", Timestamp: hit.Timestamp, Payload: payload})
		if !decision.Suppressed {
			accepted = append(accepted, alert)
		}
	}
	for _, incident := range groupWithWindowConfig(accepted, p.correlationWindow, p.maxIncidentAge, p.grouping) {
		id := incident.Fingerprint + "/" + incident.FirstSeen.Format(time.RFC3339Nano)
		previous, lookupErr := p.db.LatestIncidentByFingerprint(ctx, incident.Fingerprint)
		if lookupErr != nil && !errors.Is(lookupErr, sql.ErrNoRows) {
			return page, fmt.Errorf("load previous incident: %w", lookupErr)
		}
		if lookupErr == nil {
			oldFirst, err := time.Parse(time.RFC3339Nano, previous.FirstSeen)
			if err != nil {
				return page, err
			}
			oldLast, err := time.Parse(time.RFC3339Nano, previous.LastSeen)
			if err != nil {
				return page, err
			}
			if !incident.FirstSeen.Before(oldLast) && incident.FirstSeen.Sub(oldLast) <= p.correlationWindow && incident.LastSeen.Sub(oldFirst) <= p.maxIncidentAge {
				incident.FirstSeen = oldFirst
				incident.AlertCount += previous.AlertCount
				incident.Score = max(previous.Score, incident.Score)
				incident.Severity = scoring.Severity(incident.Score)
				var earlier Incident
				if err := json.Unmarshal(previous.Payload, &earlier); err != nil {
					return page, err
				}
				incident.RuleLevel = max(incident.RuleLevel, earlier.RuleLevel)
				incident.Criticality = max(incident.Criticality, earlier.Criticality)
				incident.Malicious = incident.Malicious || earlier.Malicious
				incident.HighImpactTactic = incident.HighImpactTactic || earlier.HighImpactTactic
				incident.Internal = incident.Internal && earlier.Internal
				id = previous.ID
			}
		}
		if p.engine != nil {
			historyRows, historyErr := p.db.IncidentHistoryByContext(ctx, incident.AgentID, incident.SrcIP, 5)
			if historyErr == nil && len(historyRows) == 0 {
				historyRows, historyErr = p.db.IncidentHistory(ctx, incident.Fingerprint, 5)
			}
			if historyErr != nil {
				return page, fmt.Errorf("incident history: %w", historyErr)
			}
			historyParts := make([]string, 0, len(historyRows))
			for _, h := range historyRows {
				historyParts = append(historyParts, h.LastSeen+":"+h.Severity+":"+h.Verdict)
			}
			geo, _ := p.geoip.Lookup(incident.SrcIP) // GeoIP is optional enrichment.
			result := p.engine.Analyze(ctx, triageengine.Case{
				Rule:         scoring.Input{RuleLevel: incident.RuleLevel, Malicious: incident.Malicious, Criticality: incident.Criticality, HighImpactTactic: incident.HighImpactTactic, InternalWhitelist: incident.Internal},
				RuleSeverity: incident.Severity,
				Prompt:       llm.PromptInput{Rule: incident.Fingerprint, Description: "live correlated SIEM incident", SourceIP: incident.SrcIP, Geo: geo, History: strings.Join(historyParts, "; ")},
			})
			incident.Score, incident.Severity = result.Score, result.Severity
			incident.Summary, incident.Actions = result.Summary, result.Actions
			incident.FPProbability = result.FPProbability
			page.Traces = append(page.Traces, store.LLMTrace{IncidentID: id, Provider: result.Trace.Provider, Model: result.Trace.Model, PromptHash: result.Trace.PromptHash, LatencyMS: result.Trace.LatencyMS, Used: result.Trace.Used, Error: result.Trace.Error})
		}
		page.Incidents = append(page.Incidents, store.IncidentWrite{ID: id, Fingerprint: incident.Fingerprint, Severity: incident.Severity, Score: incident.Score, Count: incident.AlertCount, FirstSeen: incident.FirstSeen, LastSeen: incident.LastSeen, Payload: incident})
		if p.sender != nil {
			payload, err := json.Marshal(incident)
			if err != nil {
				return page, err
			}
			channels := []string{"webhook"}
			if fanout, ok := p.sender.(interface{ Channels() []string }); ok {
				channels = fanout.Channels()
			}
			for _, channel := range channels {
				page.Notifications = append(page.Notifications, store.NotificationWrite{IncidentID: id, Channel: channel, Payload: payload})
			}
		}
	}
	return page, nil
}
