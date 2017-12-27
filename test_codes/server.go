package main

import "fmt"
import "github.com/miekg/dns"
import "os"
import "os/signal"
import "syscall"

type DnsProtector struct {
	ReqCount int
	serv     *dns.Server
}

func main() {
	dnsProtector := &DnsProtector{}
	shutdownChannel := makeShutdownChannel()
	dnsProtector.run()
	//we block on this channel
	<-shutdownChannel
	dnsProtector.stop()
}

func (self *DnsProtector) run() {
	go func() {
		self.serv = &dns.Server{Addr: "10.40.221.132:5053", Net: "tcp"}
		if err := self.serv.ListenAndServe(); err != nil {
			fmt.Println("Failed to start DNS Protector: %v", err)
			os.Exit(0)
		}
		fmt.Println("ListenAndServe unexpectedly returned")
	}()
	go func() {
		for true {
			fmt.Println("%d", self.ReqCount)
		}
	}()
	dns.HandleFunc("samsung", self.ServeDNS)
	fmt.Println("DNS Protector started successfully ")
}

func (self *DnsProtector) stop() {
	self.serv.Shutdown()
	fmt.Println("DNS Protector stopped ")
}

func makeShutdownChannel() chan os.Signal {
	//channel for catching signals of interest
	signalCatchingChannel := make(chan os.Signal)

	//catch Ctrl-C and Kill -9 signals
	signal.Notify(signalCatchingChannel, syscall.SIGINT, syscall.SIGTERM)

	return signalCatchingChannel
}

func (self *DnsProtector) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	fmt.Println("New request")
	self.ReqCount += 1
	m := new(dns.Msg)
	m.SetReply(r)
	w.WriteMsg(m)
}
