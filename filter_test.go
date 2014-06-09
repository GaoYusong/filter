package filter

import (
	"testing"
)

func TestCompile(t *testing.T) {
	filter := FilterT{}

	err := filter.Compile("10.232.64.77 And 10.232.64.76 oR 0.0.0.0/0 or Not 0.0.0.0/0")

	if err != nil {
		t.Error(err)
	}

	ip, err := ParseHost("127.0.0.1")
	if err != nil {
		t.Error(err)
	}

	if !filter.Check(ip) {
		t.Error("check ip ", ip, " expected true")
	}

}
