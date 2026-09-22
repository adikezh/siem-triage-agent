package scoring

type Input struct {
	RuleLevel             int
	Malicious             bool
	Criticality           int
	HighImpactTactic      bool
	FrequentFalsePositive bool
	InternalWhitelist     bool
}

func Score(in Input) int {
	score := in.RuleLevel * 5
	if in.Malicious {
		score += 20
	}
	if in.Criticality > 3 {
		score += 10 * (in.Criticality - 3)
	}
	if in.HighImpactTactic {
		score += 15
	}
	if in.FrequentFalsePositive {
		score -= 25
	}
	if in.InternalWhitelist {
		score -= 40
	}
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
func Severity(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}
