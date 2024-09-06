filter
======
A lightweight IP filter library inspired by [pcap-filter](https://www.tcpdump.org/manpages/pcap-filter.7.html).

The library is stable and robust, with a test coverage of 95.3%.

## Installation

```bash
go get github.com/GaoYusong/filter
```

## Network Addresses

Network addresses can be abbreviated. For example:

* 192.168.1.0 represents 192.168.1.0/32
* 192.168.1 -> 192.168.1.0/24
* 172.16 -> 172.16.0.0/16
* 10 -> 10.0.0.0/8

## Operator and Precedence

Operators are evaluated from top to bottom in decreasing order of precedence.

It is recommended to use parentheses for clarity.

Level|Operator     | Associativity
-----|-------------|-------------------
1    |not,!          | right
2    |and,&&,or,&#124;&#124; | left

## Example

Check if a host is either a private IP address or within the network 100.0.10.0/24, but not in 100.0.10.128/25:

```Go
package main

import (
	"fmt"
	"github.com/GaoYusong/filter"
)

func main() {
	f := filter.FilterT{}

	err := f.Compile("(10 or 172.16 or 192.168) or (100.0.10 and !100.0.10.128/25)")
	if err != nil {
		panic(err)
	}

	for _, host := range []string{
		"10.0.0.1",
		"172.16.0.1",
		"192.168.0.1",
		"100.0.10.1",
		"100.0.10.129",
		"166.1.1.1",
	} {
		sHost, err := filter.ParseHost(host)
		if err != nil {
			panic(err)
		}
		fmt.Printf("Host %-16s%t\n", host, f.Check(sHost))
	}

}

```

## Lisence
MIT
