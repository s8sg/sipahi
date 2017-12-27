package main

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
)

func main() {
	c := new(dns.Client)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeMX)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort("10.40.221.132", "5053"))
	if r == nil {
		log.Fatalf("*** error: %s\n", err.Error())
	}

	if r.Rcode != dns.RcodeSuccess {
		log.Fatalf(" *** invalid answer name %s after MX query for %s\n", os.Args[1], os.Args[1])
	}
	// Stuff must be in the answer section
	for _, a := range r.Answer {
		fmt.Printf("%v\n", a)
	}
}
