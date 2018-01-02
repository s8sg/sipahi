package main

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/pmylund/go-cache"
	"hash/fnv"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// fixed values
const (
	// EDNS0 Cokkie Handling
	CLIENTDUMMYCOOKIE = "24"
	SERVERSECRET      = "CDNW"
	// Cache file for validatedcache
	validatedCFile = "validated_cache.dat"
	// Cache file for validitycache
	validationCFile = "validation_cache.dat"
)

// the request state
const (
	// filter request by applying static rule and defined abnormality
	FILTER_REQ = 0
	// parse req and generate validation and req key
	PARSE_REQ = 1
	// check if response cache have resp store for the request (check resp cache)
	RESP_CACHE_CHECK = 2
	// check if the request is a validation request (populate validation cache)
	VALIDATE = 3
	// check if the requester is already validated (check validation cache)
	// else make the requester to perform validation loop by returning cname
	VALIDITY_CHECK = 4
	// perform dns request (send resp to the DNSs)
	PERFORM_DNS = 5
	// add to resp cache (populate resp cache)
	ADD_RESP_CACHE = 6
	// send reponse to the requester
	SEND_RESP = 7
	// ens of request processing
	END = 8
)

// Flags
var (
	dnss         = flag.String("dns", "192.168.2.1:53:udp,8.8.8.8:53:udp,8.8.4.4:53:udp,8.8.8.8:53:tcp,8.8.4.4:53:tcp", "dns address, use `,` as sep")
	local        = flag.String("local", ":53", "local listen address")
	debug        = flag.Int("debug", 0, "debug level 0 1 2")
	encache      = flag.Bool("cache", true, "enable cache")
	expire       = flag.Int64("expire", 3600, "default cache expire seconds, -1 means use domain ttl time")
	revalidation = flag.Int64("revalidation", 1800, "default revalidation period, -1 means never revalidate")
	ttl          = flag.Int64("ttl", 1800, "default ttl that will be set as validation period")
	respCFile    = flag.String("file", filepath.Join(path.Dir(os.Args[0]), "resp_cache.dat"), "cached file")
	ipv6         = flag.Bool("6", false, "skip ipv6 record query AAAA")
	timeout      = flag.Int("timeout", 200, "read/write timeout")
)

// req processor global variables
var (
	// Dns Client to perform TCP and UDP request towards DNS
	clientTCP *dns.Client
	clientUDP *dns.Client

	DEBUG   int
	ENCACHE bool

	// The list of DNSs
	DNS [][]string

	// Cache to store the resp for <expire> amount of time if sipahi-cache is enabled
	respcache *cache.Cache
	// Cache to store the validated req info
	validatedcache *cache.Cache
	// Cache to store the intermidiate req for validation process
	validitycache *cache.Cache

	saveSig = make(chan os.Signal)
)

// statistics variables
var (
	totalRequestCount     uint64 = 0
	respCacheHitCount     uint64 = 0
	valReqCount           uint64 = 0
	valErrCount           uint64 = 0
	totalDnsQueryCount    uint64 = 0
	failedDnsQueryCount   uint64 = 0
	resolvedDnsQueryCount uint64 = 0
	nxDomainCount         uint64 = 0
	refusedCount          uint64 = 0
	totalErrorCount       uint64 = 0
)

func toMd5(data string) string {
	m := md5.New()
	m.Write([]byte(data))
	return hex.EncodeToString(m.Sum(nil))
}

func intervalSaveCache(file string, cacheref *cache.Cache) {
	save := func() {
		err := cacheref.SaveFile(file)
		if err == nil {
			//fmt.Printf("cache saved: %s\n", file)
		} else {
			//fmt.Printf("cache save failed: %s, %s\n", file, err)
		}
	}

	// Run the thread that periodically saves the cache content
	go func() {
		for {
			select {
			case sig := <-saveSig:
				save()
				switch sig {
				case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
					os.Exit(0)
				case syscall.SIGHUP:
					log.Println("recv SIGHUP clear cache")
					cacheref.Flush()
				}
			case <-time.After(time.Second * 60):
				save()
			}
		}
	}()
}

// Method to Map Question Query to Mapped Data in Corresponsing CNAME in provided ans
func resolveDomainFromCname(questions []dns.Question, answers []dns.RR) []dns.Question {
	var newQuestion []dns.Question
	for _, q := range questions {
		for _, a := range answers {
			if strings.Contains(a.String(), q.Name) {
				q.Name = a.Header().Name
				newQuestion = append(newQuestion, q)
				break
			}
		}
	}
	return newQuestion
}

// Method to Map Ans Query to Mapped Data in Corresponsing CNAME in provided ans
func resolveCnameFromDomian(answers []dns.RR, cnameMap []dns.RR) []dns.RR {
	var newAns []dns.RR
	for _, ans := range answers {
		for _, cname := range cnameMap {
			if ans.Header().Name == cname.Header().Name {
				ans.Header().Name = (cname).(*dns.CNAME).Target
				newAns = append(newAns, ans)
				break
			}
		}
	}
	return newAns
}

func init() {
	flag.Parse()

	ENCACHE = *encache
	DEBUG = *debug

	runtime.GOMAXPROCS(runtime.NumCPU()*2 - 1)

	clientTCP = new(dns.Client)
	clientTCP.Net = "tcp"
	clientTCP.ReadTimeout = time.Duration(*timeout) * time.Millisecond
	clientTCP.WriteTimeout = time.Duration(*timeout) * time.Millisecond

	clientUDP = new(dns.Client)
	clientUDP.Net = "udp"
	clientUDP.ReadTimeout = time.Duration(*timeout) * time.Millisecond
	clientUDP.WriteTimeout = time.Duration(*timeout) * time.Millisecond

	// If resp cache is enabled initialize it
	if ENCACHE {
		respcache = cache.New(time.Second*time.Duration(*expire), time.Second*60)
		respcache.LoadFile(*respCFile)
		intervalSaveCache(*respCFile, respcache)
	}

	// Initialize validity cache
	validatedcache = cache.New(time.Second*time.Duration(*revalidation), time.Second*60)
	validatedcache.LoadFile(validatedCFile)
	intervalSaveCache(validatedCFile, validatedcache)

	// Initialize validity cache
	validitycache = cache.New(time.Second*time.Duration(*ttl), time.Second*60)
	validitycache.LoadFile(validationCFile)
	intervalSaveCache(validationCFile, validitycache)

	// Create the list of DNSs
	for _, s := range strings.Split(*dnss, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		dns := s
		proto := "udp"
		parts := strings.Split(s, ":")
		if len(parts) > 2 {
			dns = strings.Join(parts[:2], ":")
			if parts[2] == "tcp" {
				proto = "tcp"
			}
		}
		_, err := net.ResolveTCPAddr("tcp", dns)
		if err != nil {
			log.Fatalf("wrong dns address %s\n", dns)
		}
		DNS = append(DNS, []string{dns, proto})
	}

	if len(DNS) == 0 {
		log.Fatalln("dns address must be not empty")
	}

	signal.Notify(saveSig, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
}

func generateReqKey(req *dns.Msg) string {
	id := req.Id
	req.Id = 0
	// delete cookie if present
	if len(req.Extra) != 0 {
		for _, extra := range req.Extra {
			// Check if EDNS OPT type
			if extra.Header().Rrtype != dns.TypeOPT {
				continue
			}
			pos := 0
			opt := extra.(*dns.OPT)
			// For Each Option Chck the option Code
			for _, ednsOption := range opt.Option {
				if ednsOption.Option() == dns.EDNS0COOKIE {
					opt.Option = append(opt.Option[:pos], opt.Option[pos+1:]...)
					break
				}
				pos++
			}
		}
	}
	str := req.String()
	key := toMd5(str)
	req.Id = id
	return key
}

func generateValidationKey(req *dns.Msg, w dns.ResponseWriter) string {
	newReq := &dns.Msg{}
	newReq.Question = req.Question
	str := newReq.String() + strings.Split(w.RemoteAddr().String(), ":")[0] + w.RemoteAddr().Network()
	key := toMd5(str)
	return key
}

func cookiePresent(req *dns.Msg) bool {
	if len(req.Extra) != 0 {
		for _, extra := range req.Extra {
			// Check if EDNS OPT type
			if extra.Header().Rrtype != dns.TypeOPT {
				continue
			}
			opt := extra.(*dns.OPT)
			// For Each Option Chck the option Code
			for _, ednsOption := range opt.Option {
				if ednsOption.Option() == dns.EDNS0COOKIE {
					return true
				}
			}
			// NOTE: We beleive there won't be multiple OPT
			return false
		}
	}
	return false
}

func validCookie(req *dns.Msg, w dns.ResponseWriter) bool {
	if len(req.Extra) != 0 {
		for _, rr := range req.Extra {
			// Check if EDNS OPT type
			if rr.Header().Rrtype != dns.TypeOPT {
				continue
			}
			// RR is a OPT
			opt := rr.(*dns.OPT)
			// For Each Option Chck the option Code
			for _, ednsOption := range opt.Option {
				if ednsOption.Option() != dns.EDNS0COOKIE {
					continue
				}
				// ednsOption is a COOKIE
				exp_cookie := CLIENTDUMMYCOOKIE + generateServerCookie(CLIENTDUMMYCOOKIE, SERVERSECRET, strings.Split(w.RemoteAddr().String(), ":")[0])
				if exp_cookie != ednsOption.String() {
					return true
				}
			}
			// NOTE: We beleive there won't be multiple OPT
			return false
		}
	}
	return false
}

// We are using FNV64 as described in:
// https://tools.ietf.org/html/draft-eastlake-dnsext-cookies-04#section-4.2
// ServerCookie = FNV-64(Server Secret + Request IP Address + Resolver Cookie)
func generateServerCookie(clientCookie string, serverSecret string, clientIp string) string {
	serverCookie := fnv.New64a()
	clientCookiebyte, err := hex.DecodeString(clientCookie)
	if err != nil {
		return ""
	}
	serverCookie.Write(clientCookiebyte)
	serverCookie.Write([]byte(serverSecret))
	serverCookie.Write([]byte(clientIp))
	cookie := hex.EncodeToString(serverCookie.Sum(nil))
	return cookie
}

func printStats() {
	fmt.Printf("\n\nSIPAHI STAT:\n")
	fmt.Printf("%25.10s |%10.5s \n", "COUNTER", "VALUE")
	fmt.Printf("-------------------------------------------\n")
	fmt.Printf("%25.20s |%10d \n", "Total Req", totalRequestCount)
	fmt.Printf("%25.20s |%10d \n", "Cache Hit", respCacheHitCount)
	fmt.Printf("%25.20s |%10d \n", "Validation Req", valReqCount)
	fmt.Printf("%25.20s |%10d \n", "Validation Err", valErrCount)
	fmt.Printf("%25.20s |%10d \n", "Dns Query", totalDnsQueryCount)
	fmt.Printf("%25.20s |%10d \n", "Dns Failure", failedDnsQueryCount)
	fmt.Printf("%25.20s |%10d \n", "Resolved", resolvedDnsQueryCount)
	fmt.Printf("%25.20s |%10d \n", "NXDomain", nxDomainCount)
	fmt.Printf("%25.20s |%10d \n", "Refused", refusedCount)
	fmt.Printf("%25.20s |%10d \n", "Total Failure", totalErrorCount)
	fmt.Printf("\n")
}

func main() {
	dns.HandleFunc(".", proxyServe)
	defer dns.HandleRemove(".")

	done := make(chan bool, 1)

	tcpServer := &dns.Server{Addr: *local, Net: "tcp"}
	udpServer := &dns.Server{Addr: *local, Net: "udp"}

	go tcpServer.ListenAndServe()
	go udpServer.ListenAndServe()

	fmt.Printf("ready for accept connection (tcp/udp) %s...\n", *local)

	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Printf("Signal received: %d\n", sig)
		tcpServer.Shutdown()
		udpServer.Shutdown()
		done <- true
	}()

	// Wait for signal
	<-done
	fmt.Println("Shutting Down...")

	// print stats for sipahi
	printStats()
}

// This method is invoked whenever a DNS req reaches sipahi
func proxyServe(w dns.ResponseWriter, req *dns.Msg) {
	var (
		reqKey         string
		validationKey  string
		m              *dns.Msg
		err            error
		data           []byte
		id             uint16
		query          []string
		questions      []dns.Question
		actualQuestion []dns.Question
		backupAnswer   []dns.RR
		cachedAns      []dns.RR
		answers        []dns.RR
		r              dns.RR
		reqState       int
		complete       bool
		//rtt            time.Duration
	)

	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
	}()

	// set initial req state
	complete = false
	reqState = FILTER_REQ

	// increase total request count
	atomic.AddUint64(&totalRequestCount, 1)

	// request state wheel
	for !complete {
		// Case to match the exact state of the request
		switch reqState {

		case FILTER_REQ:
			// If its a Response, we treat it as Invalid (DROP)
			if req.MsgHdr.Response == true {
				return
			}

			query = make([]string, len(req.Question))

			// Filter out IPV6 and AAAA Entry from queries (DROP)
			for i, q := range req.Question {
				if q.Qtype != dns.TypeAAAA || *ipv6 {
					questions = append(questions, q)
				}
				query[i] = fmt.Sprintf("(%s %s %s)", q.Name, dns.ClassToString[q.Qclass], dns.TypeToString[q.Qtype])
			}

			// Invalid Question Length (DROP)
			if len(questions) == 0 {
				return
			}

			/* TODO: sipahi should support multiple query but DNS doesn't
			 *       We sould be able to integently Distribute the
			 *       questions to multiple DNSs in different request
			 */
			req.Question = questions

			reqState = PARSE_REQ
			fallthrough

		case PARSE_REQ:
			// generate the validation key and Request Key
			id = req.Id
			req.Id = 0
			// Generate validation key
			validationKey = generateValidationKey(req, w)
			// Generate the request key
			reqKey = generateReqKey(req)
			req.Id = id

			reqState = RESP_CACHE_CHECK
			fallthrough

		case RESP_CACHE_CHECK:
			// If Cache Enable check if we have already cached the content
			if ENCACHE {
				if reply, ok := respcache.Get(reqKey); ok {
					data, _ = reply.([]byte)
				}
				if data != nil && len(data) > 0 {
					m = &dns.Msg{}
					m.Unpack(data)
					m.Id = id
					data, err = m.Pack()
					if err != nil {
						reqState = END
						break
					}
					// increase cache hit
					atomic.AddUint64(&respCacheHitCount, 1)
					reqState = SEND_RESP
					break
				}
			}
			reqState = VALIDATE
			fallthrough

		case VALIDATE:
			// Check if CNAME query of earlier request
			if earlierreq, ok := validitycache.Get(validationKey); ok {
				data, _ = earlierreq.([]byte)
			}
			if data == nil || len(data) == 0 {
				reqState = VALIDITY_CHECK
				break
			}
			// Validate the Request
			m = &dns.Msg{}
			// unpack earlier req
			m.Unpack(data)
			invalidate := false
			reason := ""
			switch {

			/*
			 * NOTE: It was initially assumed that if DNS set the RecursicnAvailable flag as 0, the dns
			 *       resolver mast not ask about recursive query
			 *       although It is found even if the resolver replied recursion is unavialble
			 *       it can ask for recursion; which makes the below condition risky
			 *
			 *       case req.RecursionDesired:
			 *            reason = "Recursion desired"
			 *            invalidate = true
			 */

			/*
			 * TODO: Check if all the question that is asked in req.Question belongs to m.Question
			 *       Reason:
			 *       The order of the question in 2nd query dependent on resolver logic
			 *       Its highly impractical that for a multiple query to check the question one by one
			 */
			case req.Question[0] != m.Question[0]:
				reason = fmt.Sprintf("Questions Doesn't match: %s %s", req.Question[0], m.Question[0])
				invalidate = true

				/* NOTE: We currently validate the cookie by regenerating the server cookie which is dependent
				 *       on the client cookie
				 *       It is assumed from a specific client the client cookie mast be same in consicutive req
				 *       although the behaviour of the client cookie generation is not fully understood
				 *       Currently the client cookie is fixed with a hex(24)
				 */

				/* TODO: Check If cookie is not present although it was present in the initial req, it should
				 *       be invalidated
				 *
				 *       In case no cookie support is revealed from client it will be enforced to have limited
				 *       size otherwise force the remaining to communicate over TCP by sending back responses
				 *       with the TC flag set
				 */
				/*
					case cookiePresent(req):
						if !validCookie(req, w) {
							reason = fmt.Sprintf("Invalid cookie provided")
						}
						invalidate = true*/
			}

			if invalidate {
				// If Invalidated the error is logged for the specific client
				errlog := fmt.Sprintf("Invaid req, incident would be logged, reason: %s", reason)
				err = errors.New(errlog)
				// update val req count
				atomic.AddUint64(&valErrCount, 1)
				reqState = END
				break
			}
			// Before going to ask DNS, map the alias request to its actual Domain
			// TODO: Do it for Each of the Quesions in Req
			//       There should be a CNAME entry in the validity data that maps to actual query

			// Keep a backup of questions for response
			for _, q := range req.Question {
				actualQuestion = append(actualQuestion, q)
			}

			// Keep a backup of questions for response
			for _, a := range m.Answer {
				cachedAns = append(cachedAns, a)
			}

			// MAP Domain from CNAME
			req.Question = resolveDomainFromCname(req.Question, m.Answer)

			/* TODO: Generate the revalidation period as of the TTL
			 *       Current revalidation period is fixed for each request we might want to enforece
			 *       the revalidation period based on the DNS resp ttl
			 */
			validatedRequesterKey := generateValidationKey(req, w)
			validatedcache.Set(validatedRequesterKey, data, time.Second*time.Duration(*revalidation))

			// update val req count
			atomic.AddUint64(&valReqCount, 1)

			reqState = PERFORM_DNS
			break

		case VALIDITY_CHECK:
			// Check if the req is Validated
			if reply, ok := validatedcache.Get(validationKey); ok {
				data, _ = reply.([]byte)
			}
			if data != nil && len(data) > 0 {
				reqState = PERFORM_DNS
				break
			}
			// Send an response with CNAME with recursive unavailable flag set
			// Create resp to client
			m := new(dns.Msg)
			// Generate a reply message based on the request Received
			m.SetReply(req)
			// We do not provide recursive resolution
			m.RecursionAvailable = false
			// We are sending ans
			m.Response = true
			m.Question = nil

			// Generate LDNS Key
			ldns_key := toMd5(w.RemoteAddr().String() + w.RemoteAddr().Network())
			questions = nil
			// Flag to check if validation needed
			validationNeeded := false
			// Populate Upcomiming CNAME req Questions
			for _, q := range req.Question {
				if q.Name == "." {
					aRecord := new(dns.A)
					aRecord.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(*ttl)}
					aRecord.A = net.ParseIP("10.40.221.132")
					r = aRecord
				} else {
					cnRecord := new(dns.CNAME)
					ansCname := ldns_key + "." + q.Name
					cnRecord.Hdr = dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: uint32(*ttl)}
					cnRecord.Target = ansCname
					if err != nil {
						continue
					}
					r = cnRecord

					// Create question that will be store at validity cache
					q.Name = ansCname
					questions = append(questions, q)
					validationNeeded = true
				}
				answers = append(answers, r)
			}

			m.Answer = answers
			m.Question = req.Question
			m.RecursionDesired = req.RecursionDesired
			m.RecursionAvailable = false

			// Set the EDNS cookies
			/*
			 * TODO: We need to check if the client is EDNS otherwise
			 *       we cannot force the EDNS Cookie
			 *       Although it is still not fully understood if the client is
			 *       responsible for initiating edns cookies
			 */
			/*
				o := new(dns.OPT)
				o.Hdr.Name = "."
				o.Hdr.Rrtype = dns.TypeOPT
				e := new(dns.EDNS0_COOKIE)
				e.Code = dns.EDNS0COOKIE
				e.Cookie = CLIENTDUMMYCOOKIE + generateServerCookie(CLIENTDUMMYCOOKIE, SERVERSECRET, strings.Split(w.RemoteAddr().String(), ":")[0])
				o.Option = append(o.Option, e)
				m.Extra = append(m.Extra, o)
			*/
			// If validation needed set the validation cache for future reference
			if validationNeeded {
				req.Question = questions
				// We put the answare (NOTE: Answer section isn't considered for Validation Key generation)
				req.Answer = answers
				req.Opcode = dns.OpcodeQuery
				req.Id = 0

				// generate the validation key
				validationKey = generateValidationKey(req, w)
				req.Id = id
				data, _ = req.Pack()
				// Set cache (We set cache before we write the Response)
				validitycache.Set(validationKey, data, time.Second*time.Duration(*ttl))
			}

			// Write the respose for DNS request
			data, err = m.Pack()
			if err != nil {
				reqState = END
				break
			}
			reqState = SEND_RESP
			break

		case PERFORM_DNS:
			// If a Client is validated Ask the DNSs
			// Currently RR:
			//        which ever gives the Ans First would be selected
			req.RecursionDesired = true

			// Generate the reqKey
			req.Id = 0
			reqKey = generateReqKey(req)
			req.Id = id

			// Request all DNS in round robin fashion
			for _, dnsData := range DNS {
				dns := dnsData[0]
				proto := dnsData[1]
				client := clientUDP
				if proto == "tcp" {
					client = clientTCP
				}
				atomic.AddUint64(&totalDnsQueryCount, 1)
				//m, rtt, err = client.Exchange(req, dns)
				m, _, err = client.Exchange(req, dns)
				if err == nil && len(m.Answer) > 0 {
					break
				}
				atomic.AddUint64(&failedDnsQueryCount, 1)
			}

			if err != nil {
				reqState = END
				break
			}

			// TODO: Check response code for the ans
			responseCode := m.Rcode
			switch responseCode {
			// Query Refused : Refused
			case dns.RcodeRefused:
				atomic.AddUint64(&refusedCount, 1)
				atomic.AddUint64(&totalErrorCount, 1)

			// Non-Existent Domain : NXDomain
			case dns.RcodeNameError:
				atomic.AddUint64(&nxDomainCount, 1)
				atomic.AddUint64(&totalErrorCount, 1)

			// No Error
			case dns.RcodeSuccess:
				atomic.AddUint64(&resolvedDnsQueryCount, 1)
			// Other Error
			default:
				//fmt.Printf("%s\n", dns.RcodeToString[responseCode])
				atomic.AddUint64(&totalErrorCount, 1)
			}

			// TODO: Update RTT debug information
			//fmt.Printf("rtt: %d\n", rtt)

			m.RecursionAvailable = false

			// In the response the Question should have the response asked in the request
			// domain --> <cname>.domian
			// We already took a backup of the req Question earlier
			m.Question = actualQuestion

			// In the response the Answer should have the Question that its asked for
			// domain --> <cname>.domain
			// So we map the domian back to <cname>.domain
			// We need to keep a backup as the Cache would use the actual ans
			backupAnswer = nil
			for _, a := range m.Answer {
				backupAnswer = append(backupAnswer, dns.Copy(a))
			}
			resolveCnameFromDomian(m.Answer, cachedAns)
			// Pack the resp message
			data, err = m.Pack()
			if err != nil {
				reqState = END
				break
			}
			reqState = ADD_RESP_CACHE
			fallthrough

		case ADD_RESP_CACHE:
			if ENCACHE {
				m.Id = 0
				cttl := 0
				if len(m.Answer) > 0 {
					cttl = int(m.Answer[0].Header().Ttl)
					if cttl < 0 {
						cttl = 0
					}
				}
				m.Question = req.Question
				m.Answer = backupAnswer
				rdata, rerr := m.Pack()
				if rerr != nil {
					reqState = END
					break
				}
				// The cache is valid ony for the TTL provided by the actual Server
				respcache.Set(reqKey, rdata, time.Second*time.Duration(cttl))
				m.Id = id
			}
			reqState = SEND_RESP
			fallthrough

		case SEND_RESP:
			_, err = w.Write(data)
			reqState = END
			fallthrough
		case END:
			if err != nil {
				fmt.Printf("id: %5d error: %v %s\n", id, query, err)
			}
			fallthrough
		default:
			complete = true
		}
	}
}
