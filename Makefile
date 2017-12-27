build:
	go get github.com/miekg/dns
	go get github.com/pmylund/go-cache
	go build sipahi.go
clean:
	rm -f sipahi
	rm -rf *.dat
