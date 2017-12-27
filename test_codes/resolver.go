package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	domain := os.Args[1]
	ips, err := net.LookupIP(domain)
	if err != nil {
		fmt.Printf("Error: %v", err)
		return
	}
	for _, ip := range ips {
		fmt.Println(ip)
	}
}
