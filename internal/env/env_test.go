package env

import "testing"

func TestDetect(t *testing.T) {
	d, err := NewDetector([]string{"db1", "db2", "gitlab-db*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		s    Signals
		want bool
	}{
		{"laptop", Signals{Hostname: "duvan-thinkpad"}, false},
		{"explicit prod", Signals{Explicit: "production", Hostname: "duvan-thinkpad"}, true},
		{"explicit dev wins over hostname", Signals{Explicit: "dev", Hostname: "api-prod-1"}, false},
		{"prod hostname", Signals{Hostname: "api-prod-1.internal"}, true},
		{"prd hostname", Signals{Hostname: "eks-prd-node"}, true},
		{"word containing prod is not prod", Signals{Hostname: "product-docs"}, false},
		{"listed host short", Signals{Hostname: "db1"}, true},
		{"listed host fqdn", Signals{Hostname: "db2.cluster.gitlab.com"}, true},
		{"listed prefix", Signals{Hostname: "gitlab-db-03"}, true},
		{"kube context", Signals{Hostname: "laptop", KubeContext: "arn:aws:eks:us-east-1:1:cluster/prod"}, true},
		{"aws profile", Signals{Hostname: "laptop", AWSProfile: "company-prod"}, true},
		{"staging profile", Signals{Hostname: "laptop", AWSProfile: "company-staging"}, false},
	}
	for _, tt := range tests {
		if got := d.Detect(tt.s); got.Production != tt.want {
			t.Errorf("%s: production = %v (%v), want %v", tt.name, got.Production, got.Reasons, tt.want)
		}
	}
}

func TestBadPattern(t *testing.T) {
	if _, err := NewDetector(nil, []string{"("}); err == nil {
		t.Error("invalid regexp must fail")
	}
}
