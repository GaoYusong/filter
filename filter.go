package filter

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type cidrT struct {
	ip   int
	mask int
}

type tokenT struct {
	t    int
	cidr cidrT
	pos  int
}

type FilterT struct {
	filter string
	rpn    []tokenT
}

const (
	token_space   = -1
	token_unknown = 0
	token_value   = 1
	token_and     = 2
	token_or      = 3
	token_not     = 4
	token_left    = 5
	token_right   = 6
	token_border  = 7
)

var tokenOut map[int]string = map[int]string{
	token_border: "#",
	token_left:   "(",
	token_right:  ")",
	token_and:    "and",
	token_or:     "or",
	token_not:    "not",
}

const (
	rank_equal   = 0
	rank_less    = -1
	rank_greater = 1
	rank_illegal = -2
)

/*
 *  Priority Table
 *      #  and  or  not  (  )
 * #    =  <    <   <    <  *
 * and  >  >    >   <    <  >
 * or   >  >    >   <    <  >
 * not  >  >    >   <    <  >
 * (    *  <    <   <    <  =
 * )    *  *    *   *    *  *
 */

var ranks map[int]map[int]int = map[int]map[int]int{
	token_border: map[int]int{
		token_border: rank_equal,
		token_and:    rank_less,
		token_or:     rank_less,
		token_not:    rank_less,
		token_left:   rank_less,
		token_right:  rank_illegal,
	},
	token_and: map[int]int{
		token_border: rank_greater,
		token_and:    rank_greater,
		token_or:     rank_greater,
		token_not:    rank_less,
		token_left:   rank_less,
		token_right:  rank_greater,
	},
	token_or: map[int]int{
		token_border: rank_greater,
		token_and:    rank_greater,
		token_or:     rank_greater,
		token_not:    rank_less,
		token_left:   rank_less,
		token_right:  rank_greater,
	},
	token_not: map[int]int{
		token_border: rank_greater,
		token_and:    rank_greater,
		token_or:     rank_greater,
		token_not:    rank_less,
		token_left:   rank_less,
		token_right:  rank_greater,
	},
	token_left: map[int]int{
		token_border: rank_illegal,
		token_and:    rank_less,
		token_or:     rank_less,
		token_not:    rank_less,
		token_left:   rank_less,
		token_right:  rank_equal,
	},
	token_right: map[int]int{
		token_border: rank_illegal,
		token_and:    rank_illegal,
		token_or:     rank_illegal,
		token_not:    rank_illegal,
		token_left:   rank_illegal,
		token_right:  rank_illegal,
	},
}

func ParseHost(rawIP string) (int, error) {
	ip := strings.Split(rawIP, ".")
	if len(ip) == 4 {
		r := 0
		for i := 0; i < 4; i++ {
			ipInt, err := strconv.ParseInt(ip[i], 10, 0)
			if err != nil || ipInt < 0 || ipInt > 255 {
				return 0, errors.New("ip domain must be 0~255")
			}
			r = (r << 8) | int(ipInt)
		}
		return r, nil
	} else {
		return 0, errors.New("malformed")
	}
}

func (f *FilterT) GetFilter() string {
	return f.filter
}

func (f *FilterT) Compile(filter string) error {
	tokens, err := tokenize(filter)
	if err != nil {
		//fmt.Println(err)
		return err
	}

	//outputTokens(tokens)

	rpn, err := toRPN(tokens)

	if err != nil {
		//fmt.Println(err)
		return err
	}

	//outputTokens(rpn)

	f.rpn = rpn

	return nil
}

func (f *FilterT) Check(ip int) bool {
	var stack []bool

	if len(f.rpn) == 0 {
		return false
	}

	for _, token := range f.rpn {
		top := len(stack)
		switch token.t {
		case token_value:
			stack = append(stack, CheckIn(ip, token.cidr))
		case token_not:
			stack[top-1] = !stack[top-1]
		case token_and:
			stack[top-2] = stack[top-2] && stack[top-1]
			stack = stack[0 : top-1]
		case token_or:
			stack[top-2] = stack[top-2] || stack[top-1]
			stack = stack[0 : top-1]
		default:
			panic("illegal token")
		}
	}

	if len(stack) != 1 {
		panic("illegal rpn")
	}
	
	return stack[0]
}

func CheckIn(ip int, cidr cidrT) bool {
	return (ip & cidr.mask) == cidr.ip
}

func tokenize(filter string) ([]tokenT, error) {
	var tokens []tokenT
	filter_len := len(filter)
	for i := 0; i < filter_len; {
		token, next_i, err := lex(&filter, i)
		if err != nil {
			return nil, err
		}
		if token.t != token_space {
			tokens = append(tokens, token)
		}
		i = next_i
	}
	return tokens, nil
}

func toRPN(tokens []tokenT) ([]tokenT, error) {
	var rpn, stack []tokenT

	stack = append(stack, tokenT{t: token_border})
	tokens = append(tokens, tokenT{t: token_border})

	vals := 0

	for _, token := range tokens {

		if token.t == token_value {
			rpn = append(rpn, token)
			vals++
		} else {
			top := len(stack)

			for ; ranks[stack[top-1].t][token.t] == rank_greater; top-- {
				t := stack[top-1].t
				var needVals int
				switch t {
				case token_not:
					needVals = 1
				case token_and:
					needVals = 2
				case token_or:
					needVals = 2
				default:
					panic("token illegal")
				}

				if vals < needVals {
					return toRPNError(stack[top-1], "no values")
				}

				vals = vals - needVals + 1
				rpn = append(rpn, stack[top-1])
			}

			switch ranks[stack[top-1].t][token.t] {
			case rank_equal:
				stack = stack[0 : top-1]
			case rank_less:
				stack = stack[0:top]
				stack = append(stack, token)
			case rank_illegal:
				brackets := stack[top-1]
				if token.t == token_right {
					brackets = token
				}
				return toRPNError(brackets, "unbalanced brackets")
			default:
				panic("rank illegal")
			}
		}
	}

	if len(stack) != 0 {
		panic("stack is not empty")
	}

	if vals != 1 {
		return nil, errors.New("imcompleted filter string")
	}

	return rpn, nil
}

func toRPNError(token tokenT, msg string) ([]tokenT, error) {
	return nil, errors.New(fmt.Sprint("token \"", tokenOut[token.t], "\" in pos ", token.pos, ", ", msg))
}

func lex(filter *string, i int) (tokenT, int, error) {
	ch := (*filter)[i]
	if ch >= '0' && ch <= '9' {
		return lexCIDR(filter, i)
	} else if isSpace(ch) {
		return tokenT{t: token_space}, i + 1, nil
	} else {
		switch ch {
		case '&':
			return lexOP(filter, i, "&&")
		case '|':
			return lexOP(filter, i, "||")
		case '!':
			return lexOP(filter, i, "!")
		case 'a', 'A':
			return lexOP(filter, i, "and")
		case 'o', 'O':
			return lexOP(filter, i, "or")
		case 'n', 'N':
			return lexOP(filter, i, "not")
		case '(':
			return lexOP(filter, i, "(")
		case ')':
			return lexOP(filter, i, ")")
		default:
			return lexError(errors.New(fmt.Sprint("unknown charactor in pos ", i)))
		}
	}
}

// must not start a space charactor
func lexCIDR(filter *string, pos int) (tokenT, int, error) {
	cidr := ""
	i := pos
	for ; i < len(*filter); i++ {
		ch := (*filter)[i]
		if (ch >= '0' && ch <= '9') || ch == '.' || ch == '/' {
			cidr += string(ch)
		} else {
			break
		}
	}
	ipmask := strings.Split(cidr, "/")
	if len(ipmask) == 2 {
		ip := strings.Split(ipmask[0], ".")
		if len(ip) == 4 {
			mask, err := strconv.ParseInt(ipmask[1], 10, 0)
			if err != nil || mask < 0 || mask > 32 {
				return lexCIDRError(pos, "malformed mask")
			}
			return cidrToken(ip, int(mask), pos, i)
		} else {
			return lexCIDRError(pos, "need a dotted quad ip when set mask")
		}
	} else if len(ipmask) == 1 {
		ip := strings.Split(ipmask[0], ".")
		if len(ip) >= 1 && len(ip) <= 4 {
			return cidrToken(ip, len(ip)*8, pos, i)
		} else {
			return lexCIDRError(pos, "malformed ip")
		}
	} else {
		return lexCIDRError(pos, "too many /")
	}
}

func cidrToken(rawIP []string, mask int, pos int, next_i int) (tokenT, int, error) {
	cidr := cidrT{}
	cidr.ip = 0

	for i := 0; i < 4; i++ {
		cidr.ip <<= 8
		if i < len(rawIP) {
			ip, err := strconv.ParseInt(rawIP[i], 10, 0)
			if err != nil || ip < 0 || ip > 255 {
				return lexCIDRError(pos, "ip domain must be 0~255")
			}
			cidr.ip |= int(ip)
		}
	}

	cidr.mask = (-1) << uint(32-mask)

	return tokenT{
		t:    token_value,
		cidr: cidr,
		pos:  pos,
	}, next_i, nil
}

func lexCIDRError(pos int, msg string) (tokenT, int, error) {
	return lexError(errors.New(fmt.Sprint("malformed cidr begin in pos ", pos, ", ", msg)))
}

func lexOP(filter *string, pos int, op string) (tokenT, int, error) {
	if equal(filter, pos, op) {
		return tokenT{t: toOP(op), pos: pos}, (pos + len(op)), nil
	} else {
		return lexError(errors.New(fmt.Sprint("malformed ", op, " in pos ", pos)))
	}
}

func toOP(op string) int {
	switch op {
	case "&&", "and":
		return token_and
	case "||", "or":
		return token_or
	case "!", "not":
		return token_not
	case "(":
		return token_left
	case ")":
		return token_right
	}
	panic("unknown op")
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

func equal(filter *string, pos int, obj string) bool {
	if pos+len(obj) <= len(*filter) {
		return obj == strings.ToLower((*filter)[pos:pos + len(obj)])
	}
	return false
}

func lexError(err error) (tokenT, int, error) {
	return tokenT{}, 0, err
}

func outputTokens(tokens []tokenT) {
	for _, token := range tokens {
		outputToken(token)
		fmt.Print(" ")
	}
	fmt.Print("\n")
}

func outputToken(token tokenT) {
	switch token.t {
	case token_value:
		outputCidr(token.cidr)
	default:
		fmt.Print(tokenOut[token.t])
	}
}

func outputCidr(cidr cidrT) {
	i := 0
	for ; i <= 32; i++ {
		if cidr.mask == (-1)<<uint32(32-i) {
			break
		}
	}
	if i > 32 {
		panic(fmt.Sprint("malformed value token ", cidr))
	}
	fmt.Printf("%d.%d.%d.%d/%d",
		(cidr.ip>>24)&255, (cidr.ip>>16)&255, (cidr.ip>>8)&255, cidr.ip&255, i)
}
