package eval

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

type Result struct {
	Samples, TP, FP, FN   int
	Precision, Recall, F1 float64
}

func Run(r io.Reader) (Result, error) {
	s := bufio.NewScanner(r)
	var o Result
	for s.Scan() {
		if strings.TrimSpace(s.Text()) == "" {
			continue
		}
		var x struct {
			Verdict string `json:"Verdict"`
			Payload struct {
				Severity string `json:"severity"`
			} `json:"Payload"`
		}
		if e := json.Unmarshal([]byte(s.Text()), &x); e != nil {
			return o, e
		}
		o.Samples++
		p := x.Payload.Severity == "high" || x.Payload.Severity == "critical"
		a := x.Verdict == "tp"
		if p && a {
			o.TP++
		} else if p && !a {
			o.FP++
		} else if !p && a {
			o.FN++
		}
	}
	if e := s.Err(); e != nil {
		return o, e
	}
	if o.TP+o.FP > 0 {
		o.Precision = float64(o.TP) / float64(o.TP+o.FP)
	}
	if o.TP+o.FN > 0 {
		o.Recall = float64(o.TP) / float64(o.TP+o.FN)
	}
	if o.Precision+o.Recall > 0 {
		o.F1 = 2 * o.Precision * o.Recall / (o.Precision + o.Recall)
	}
	return o, nil
}
