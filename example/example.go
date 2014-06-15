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
