package scoring

import "testing"

func TestScoreFormula(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want int
	}{{"base", Input{RuleLevel: 5}, 25}, {"threat and asset", Input{RuleLevel: 8, Malicious: true, Criticality: 5, HighImpactTactic: true}, 95}, {"whitelist floors at zero", Input{RuleLevel: 3, InternalWhitelist: true}, 0}, {"repeat fp", Input{RuleLevel: 10, FrequentFalsePositive: true}, 25}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Score(tc.in); got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
