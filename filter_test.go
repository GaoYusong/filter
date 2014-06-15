package filter

import (
	"testing"
)

func TestBasic(t *testing.T) {
	filter := FilterT{}

	if filter.OK() {
		t.Error("uninit filter return ok")
	}

	err := filter.Compile("not")

	if err == nil {
		panic("Compile isn't fail")
	}

	if filter.OK() {
		t.Error("filter return ok,  but not compile success")
	}

	if filter.Check(0) {
		t.Error("uinit filter return true")
	}

	successFilter := "10.232.64.77 And 10.232.64.76 oR 127.0.0.2/24"

	err = filter.Compile(successFilter)

	if err != nil {
		t.Error(err)
	}

	if !filter.OK() {
		t.Error("filter is not ok")
	}

	err = filter.Compile("not")
	if err == nil {
		panic("Compile isn't fail")
	}

	if !filter.OK() {
		t.Error("filter is not ok, after one success compile follow by one fail compile")
	}

	ip, err := ParseHost("127.0.0.1")
	if err != nil {
		t.Error(err)
	}

	if !filter.Check(ip) {
		t.Error("check ip ", ip, " expected true")
	}

	ip, err = ParseHost("127.0.1.0")
	if err != nil {
		t.Error(err)
	}
	if filter.Check(ip) {
		t.Error("check ip ", ip, " expected false")
	}

	if filter.GetFilter() != successFilter {
		t.Error("get filter fail")
	}

	if filter.GetRPN() != "10.232.64.77/32[0] 10.232.64.76/32[17] and[13] 127.0.0.2/24[33] or[30]" {
		t.Error("get rpn fail")
	}
	
}

func TestErrorToken(t *testing.T) {
	e := NewErrorToken(err_code_filter, token_not_exsits, -1)

	if e.Error() != "[1000], imcompleted filter string" {
		t.Errorf("token error is not expected, got %s", e.Error())
	}
}

func TestParseHost(t *testing.T) {
	for host, expect := range map[string]int{
		"127.0.0.1":   0x7f000001,
		"192.168.1.1": 0xc0a80101,
	} {
		r, err := ParseHost(host)
		if err != nil {
			t.Errorf("ParseHost(%q): err %s", host, err.Error())
		} else if r != expect {
			t.Errorf("ParseHost(%q): expected %d, got %d", host, expect, r)
		}
	}
}

func TestFailParseHost(t *testing.T) {
	for host, expect := range map[string]string{
		"288.0.0.1":    err_msg_parse_host_ip_domain,
		"127":          err_msg_parse_host_malformed,
		"127.0.0.1/10": err_msg_parse_host_ip_domain,
		"127.0.0.1.1":  err_msg_parse_host_malformed,
	} {
		_, err := ParseHost(host)
		if err == nil || err.Error() != expect {
			var err_msg string
			if err == nil {
				err_msg = "nil"
			} else {
				err_msg = err.Error()
			}
			t.Errorf("ParseHost(%q): expected %q, got %q", host, expect, err_msg)
		}
	}
}

func TestFailCompile(t *testing.T) {
	filter := FilterT{}
	for content, rawExpect := range map[string]error{
		// err filter
		"":                          NewErrorToken(err_code_filter, token_not_exsits, -1),
		"127.0.0.1 not 10":          NewErrorToken(err_code_filter, token_not_exsits, -1),
		"127.0.0.1 10 and 12 or 17": NewErrorToken(err_code_filter, token_not_exsits, -1),
		"(1 and 2) (3 or 4)":        NewErrorToken(err_code_filter, token_not_exsits, -1),
		"(1 and 2) not 3":           NewErrorToken(err_code_filter, token_not_exsits, -1),

		// err no values
		"127.0.0.1 or 127.0.0.2/32 not not 10":                    NewErrorToken(err_code_no_values, token_or, 10),
		"127.0.0.1 127.0.0.2 or":                                  NewErrorToken(err_code_no_values, token_or, 20),
		"127.0.0.1 not or 127.0.0.2/32 10":                        NewErrorToken(err_code_no_values, token_not, 10),
		"127.0.0.1 not not or 127.0.0.2/32 10":                    NewErrorToken(err_code_no_values, token_not, 14),
		"127.0.0.1 and or 127.0.0.2/32 10":                        NewErrorToken(err_code_no_values, token_and, 10),
		"127.0.0.1 and 127.0.0.2/32 or 10 or or":                  NewErrorToken(err_code_no_values, token_or, 33),
		"and not not 127.0.0.2/32":                                NewErrorToken(err_code_no_values, token_and, 0),
		"not 127.0.0.2/32 not":                                    NewErrorToken(err_code_no_values, token_not, 17),
		"127 or 138 and (137 or 123) and 213 or 43 and (137 or )": NewErrorToken(err_code_no_values, token_or, 51),

		// unbalanced brackets
		"127 or 137 and not (17))":          NewErrorToken(err_code_brackets, token_right, 23),
		"127 or 137 and (not (17)":          NewErrorToken(err_code_brackets, token_left, 15),
		"(127 or (137) (and (() not (17)))": NewErrorToken(err_code_brackets, token_left, 0),
		")":     NewErrorToken(err_code_brackets, token_right, 0),
		")123(": NewErrorToken(err_code_brackets, token_right, 0),
		"(123(": NewErrorToken(err_code_brackets, token_left, 4),

		// unknown charactor
		"127 Or 13x7":          NewErrorToken(err_code_charactor, token_unknown, 9),
		"127 Or e 137 and 172": NewErrorToken(err_code_charactor, token_unknown, 7),
		"/12":  NewErrorToken(err_code_charactor, token_unknown, 0),
		"Note": NewErrorToken(err_code_charactor, token_unknown, 3),

		// err_msg_mask
		"127.0.0.1 or 123.0.0.1/-10": NewErrorToken(err_code_mask, token_value, 13),
		"127.0.0.1 or 123.0.0.1/abc": NewErrorToken(err_code_mask, token_value, 13),
		"127.0.0.1 or 123.0.0.1/33":  NewErrorToken(err_code_mask, token_value, 13),

		// err_msg_set_mask
		"127.0.0/12": NewErrorToken(err_code_set_mask, token_value, 0),
		"127/12":     NewErrorToken(err_code_set_mask, token_value, 0),
		"127.333/12": NewErrorToken(err_code_set_mask, token_value, 0),

		// err_msg_ip
		"127.0.0.1 and 127.1.213.233.1": NewErrorToken(err_code_ip, token_value, 14),

		// err_msg_too_many_mask
		"127.0.0.1/3/23": NewErrorToken(err_code_too_many_mask, token_value, 0),

		// err_msg_ip_domain
		"256.0.0.1/20": NewErrorToken(err_code_ip_domain, token_value, 0),

		// err_msg_token
		"127.0.0.1 Oer": NewErrorToken(err_code_token, token_or, 10),
		"127.0.0.1 Noe": NewErrorToken(err_code_token, token_not, 10),
		"127.0.0.1 Ad":  NewErrorToken(err_code_token, token_and, 10),
		"127.0.0.1 ad":  NewErrorToken(err_code_token, token_and, 10),
	} {
		expect := *(rawExpect.(*errorTokenT))
		err := filter.Compile(content)
		if err == nil {
			t.Errorf("Compile(%q): expected %v, got nil", content, expect)
		} else if *(err.(*errorTokenT)) != expect {
			t.Errorf("Compile(%q): expected %v, got %v", content, expect, *(err.(*errorTokenT)))
		}
	}

	oldFilter := "127.0.0.1 or (123.23 and 123)"
	// test keep old rpn, when new compile fail
	err := filter.Compile(oldFilter)

	if err != nil {
		t.Fatal(err)
	}

	oldRPN := filter.rpn

	err = filter.Compile("127.0.0.1 not")

	if err == nil {
		t.Fatal("compile malformed filter, but not return err")
	}

	if filter.filter != oldFilter {
		t.Error("not keep old filter")
	}

	if !compareTokens(filter.rpn, oldRPN) {
		t.Error("not keep old rpn")
	}

}

func TestCompile(t *testing.T) {

	f := FilterT{}

	for content, rpn := range map[string][]tokenT{
		// test tokenize and toRPN
		"127.0.0.1/24": {newV("127.0.0.1", 24, 0)},
		"127.0.0.1/24 And 0.0.0.0/8 or (127 or 192 oR (10 and 10.232.64)) and nOt 172.24 and NoT 172.178.88.1/0 and (172.0.0.1/32 and not not 11.12.13.14/15)and10.1.1.1  oR (12)    Or notnot17  && 17 || 12 || !!13": {
			newV("127.0.0.1", 24, 0), newV("0.0.0.0", 8, 17), newOP(token_and, 13),
			newV("127.0.0.0", 8, 31), newV("192.0.0.0", 8, 38), newOP(token_or, 35), newV("10.0.0.0", 8, 46),
			newV("10.232.64.0", 24, 53), newOP(token_and, 49), newOP(token_or, 42), newOP(token_or, 27),
			newV("172.24.0.0", 16, 73), newOP(token_not, 69), newOP(token_and, 65), newV("172.178.88.1", 0, 88),
			newOP(token_not, 84), newOP(token_and, 80), newV("172.0.0.1", 32, 108), newV("11.12.13.14", 15, 133),
			newOP(token_not, 129), newOP(token_not, 125), newOP(token_and, 121), newOP(token_and, 103), newV("10.1.1.1", 32, 151),
			newOP(token_and, 148), newV("12.0.0.0", 8, 165), newOP(token_or, 161), newV("17.0.0.0", 8, 181),
			newOP(token_not, 178), newOP(token_not, 175), newOP(token_or, 172), newV("17.0.0.0", 8, 188), newOP(token_and, 185),
			newV("12.0.0.0", 8, 194), newOP(token_or, 191), newV("13.0.0.0", 8, 202), newOP(token_not, 201), newOP(token_not, 200),
			newOP(token_or, 197),
		},
		// priority
		// and and
		"1 and 2 and 3": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 6), newOP(token_and, 2),
			newV("3.0.0.0", 8, 12), newOP(token_and, 8)},
		// and or
		"1 and 2 or 3": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 6), newOP(token_and, 2),
			newV("3.0.0.0", 8, 11), newOP(token_or, 8)},
		// and not
		"1 and not 2": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 10), newOP(token_not, 6), newOP(token_and, 2)},
		// and (
		"1 and (2 or 3)": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 7), newV("3.0.0.0", 8, 12), newOP(token_or, 9), newOP(token_and, 2)},
		// and )
		"1 or (2 and 3)": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 6), newV("3.0.0.0", 8, 12), newOP(token_and, 8), newOP(token_or, 2)},
		// or and
		"1 or 2 and 3": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 5), newOP(token_or, 2), newV("3.0.0.0", 8, 11), newOP(token_and, 7)},
		// or or
		"1 or 2 or 3": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 5), newOP(token_or, 2), newV("3.0.0.0", 8, 10), newOP(token_or, 7)},
		// or not
		"1 or not 2": {newV("1.0.0.0", 8, 0), newV("2.0.0.0", 8, 9), newOP(token_not, 5), newOP(token_or, 2)},
		// or (, same with and )

		// or ), same with and (

		// not and
		"not 1 and 2": {newV("1.0.0.0", 8, 4), newOP(token_not, 0), newV("2.0.0.0", 8, 10), newOP(token_and, 6)},
		// not or
		"not 1 or 2": {newV("1.0.0.0", 8, 4), newOP(token_not, 0), newV("2.0.0.0", 8, 9), newOP(token_or, 6)},
		// not not
		"not not 1": {newV("1.0.0.0", 8, 8), newOP(token_not, 4), newOP(token_not, 0)},
		// not (
		"not (1 or 2)": {newV("1.0.0.0", 8, 5), newV("2.0.0.0", 8, 10), newOP(token_or, 7), newOP(token_not, 0)},
		// not )
		"(not 1)": {newV("1.0.0.0", 8, 5), newOP(token_not, 1)},

		// ( and, same with and )
		// ( or, same with and (
		// ( not, same with not )
		// ( (
		"((1 or 2) and 3)": {newV("1.0.0.0", 8, 2), newV("2.0.0.0", 8, 7), newOP(token_or, 4), newV("3.0.0.0", 8, 14), newOP(token_and, 10)},
		// ( )
		"(1)": {newV("1.0.0.0", 8, 1)},

		// ) and, same with ( (
		// ) or
		"(1 and 2) or 3": {newV("1.0.0.0", 8, 1), newV("2.0.0.0", 8, 7), newOP(token_and, 3), newV("3.0.0.0", 8, 13), newOP(token_or, 10)},
		// ) not, also test in err
		"() not 1": {newV("1.0.0.0", 8, 7), newOP(token_not, 3)},
		// ) (, also test in err
		"() 1 ()": {newV("1.0.0.0", 8, 3)},
		// ) )
		"(1 and (2 or 3))": {newV("1.0.0.0", 8, 1), newV("2.0.0.0", 8, 8), newV("3.0.0.0", 8, 13), newOP(token_or, 10), newOP(token_and, 3)},
	} {
		err := f.Compile(content)
		if err != nil {
			t.Fatalf("Compile(%q): err %s", content, err.Error())
		} else if !compareTokens(f.rpn, rpn) {
			t.Errorf("Compile(%q): expect \"%s\", got \"%s\"", content, outputTokens(rpn), outputTokens(f.rpn))
		}

	}
}

func TestCheck(t *testing.T) {
	f := FilterT{}
	for filter, checks := range map[string]map[string]bool{
		"127": map[string]bool{
			"127.0.0.1": true,
			"128.0.0.1": false,
			"192.0.0.0": false,
		},
		"192.168.0.1 or 191.168.0 or 190.168": map[string]bool{
			"192.168.0.1": true,
			"192.168.0.2": false,
			"191.168.0.1": true,
			"191.168.1.1": false,
			"191.167.0.0": false,
			"190.168.0.0": true,
			"190.167.0.0": false,
		},
		"not not 192.168.0.1 or not not 191.168.0 and 191.168": map[string]bool{
			"192.168.0.1": false,
			"192.168.0.2": false,
			"191.168.0.1": true,
		},
		"192.168.0.1 or 191.168.0 and not 191.168": map[string]bool{
			"192.168.0.1": true,
			"192.168.0.2": false,
			"191.168.0.1": false,
		},
		"192.168.0.1 or (not not 191.168.0 and 191.168)": map[string]bool{
			"192.168.0.1": true,
			"192.168.0.2": false,
			"191.168.0.1": true,
		},
	} {
		err := f.Compile(filter)
		if err != nil {
			panic(err)
		}
		for host, expect := range checks {
			ip, err := ParseHost(host)
			if err != nil {
				panic(err)
			}
			if got := f.Check(ip); got != expect {
				t.Errorf("Check(%q): expect %v, got %v, filter \"%s\"", host, expect, got, filter)
			}
		}
	}
}

func newOP(t int, pos int) tokenT {
	return tokenT{t: t, pos: pos}
}

func newV(ip string, mask int, pos int) tokenT {
	ip1, err := ParseHost(ip)
	if err != nil {
		panic(err)
	}
	return tokenT{t: token_value, cidr: cidrT{ip: ip1, mask: (-1) << uint(32-mask)}, pos: pos}
}

func compareTokens(t1 []tokenT, t2 []tokenT) bool {
	if len(t1) != len(t2) {
		return false
	}
	for i := 0; i < len(t1); i++ {
		if t1[i] != t2[i] {
			return false
		}
	}
	return true
}
