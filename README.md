SIPAHI is a transparent DNS proxy that works as a traffic rate limiter for DNS servers

**NOTE**
* Its Transparent in Layer 7
* Works with any DNS resolver
* Meant to protect DNS from DDOS


##### Getting Started
```
go get github.com/miekg/dns 
go get github.com/pmylund/go-cache
go build sipahi.go 
```
or Just
```
make build
```

##### Useage
```
$ ./sipahi -h

Usage of ./sipahi:
  -6	skip ipv6 record query AAAA
  -cache
    	enable sipahi-cache (default true)
  -debug int
    	debug level 0 1 2
  -expire int
    	default cache expire seconds, -1 means use domain ttl time (default 3600)
  -file string
    	cached file (default "resp_cache.dat")
  -dns ,
    	dns address, use ',' as sep (default "192.168.2.1:53:udp,8.8.8.8:53:udp,8.8.4.4:53:udp,8.8.8.8:53:tcp,8.8.4.4:53:tcp")
  -local string
    	local listen address (default ":53")
  -revalidation int
    	default revalidation period, -1 means never revalidate (default 1800)
  -timeout int
    	read/write timeout (default 200)
  -ttl int
    	default ttl that will be set as validation period (default 1800)
```
running with default values: 
```
$ sudo ./sipahi
ready for accept connection on tcp/udp :53 ...
^CSignal received: 2
Shutting Down...
SIPAHI STAT:
                  COUNTER |     VALUE 
-------------------------------------------
                Total Req |    155522 
                Cache Hit |    100532 
           Validation Req |      1400 
           Validation Err |         0 
                Dns Query |      3984 
              Dns Failure |      2570 
                 Resolved |      1418 
                 NXDomain |        66 
                  Refused |         0 
            Total Failure |        66 
```

##### How Sipahi Works
   
   
###### Understanding how sipahi verify resolver

Verification of a resolver is required in case the resolver is making request at high rate  
Validation loop can be debugged by disabling the rate limit  
Validation can also be disabled by providing flag `-validate=false`  
  
To check sipahi validation loop, lets dig for a domain name `google.com` 
```bash
$ dig @127.0.0.1 google.com

; <<>> DiG 9.8.3-P1 <<>> @127.0.0.1 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 5234
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		1800	IN	CNAME	472f0851a62dfc74c5bee85b5c64a546.google.com.

;; Query time: 10 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Sep 15 18:25:59 2017
;; MSG SIZE  rcvd: 95
```
It will returned a CNAME <req_identity>.google.com  
On CNAME response resolver should try to resolve the CNAME like below  
```bash
$ dig @127.0.0.1 472f0851a62dfc74c5bee85b5c64a546.google.com

; <<>> DiG 9.8.3-P1 <<>> @127.0.0.1 472f0851a62dfc74c5bee85b5c64a546.google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 26349
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;472f0851a62dfc74c5bee85b5c64a546.google.com. IN	A

;; ANSWER SECTION:
472f0851a62dfc74c5bee85b5c64a546.google.com. 299 IN A 172.217.27.78

;; Query time: 319 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Sep 15 18:26:53 2017
;; MSG SIZE  rcvd: 120
```
It got the IP from actual resolved address  
Once it gets a request for the ealier CNAME, it vaidates the client  
A resolver should always make an iterative query for the CNAME response  
Now when a request for the same domain from same client is received, the client is already verified for the same    
```bash
dig @127.0.0.1 google.com                                 

; <<>> DiG 9.8.3-P1 <<>> @127.0.0.1 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 19947
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		299	IN	A	172.217.27.78

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Sep 15 18:27:06 2017
;; MSG SIZE  rcvd: 54
```
we are verified and you got the response within a sec 0  
Once sipahi got the actual DNS response, it caches the DNS response into response cache  
   
The response cache should expire after 5 min  
```bash
$ dig @127.0.0.1 google.com

; <<>> DiG 9.8.3-P1 <<>> @127.0.0.1 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 23320
;; flags: qr rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;google.com.			IN	A

;; ANSWER SECTION:
google.com.		299	IN	A	172.217.27.78

;; Query time: 7 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Sep 15 18:31:31 2017
;; MSG SIZE  rcvd: 54
```
it took 7ms now. Cause the resp cache in sipahi is expired after the TTL 
period (299ms) but the validation cache is maintained!  
    
After 10min the validation cache would be expired too and a re-validation  
would be forced  
   
`revalidation` flag can be used to change the revalidation period  
   
   
   

###### Test in real scenario

In a real deployment scenario, a host resolve query by application results in a recursive query to the resolver. The resolver then makes an iterative query to the DNS server and send the response to the client. Sipahi is meant to run in between resolver and DNS server which makes it behave just like another dns server. 
    
    
This can be checked by local resolver by replacing sipahi as a nameserver/DNS. 
   
* Run sipahi
* If you are using mac    
```
1> Goto System Preference -> Network -> Advanced (for the network you using)
2> Goto DNS tab and set your localhost (127.0.0.1) as only dns
```
* If you are using any other linux machine
```
1> Open to edit /etc/resolv.conf
2> Add nameserver as your localhost (127.0.0.1)
   nameserver 127.0.0.1
```
