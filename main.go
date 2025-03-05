package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
)

var (
	targetCIDR  = flag.String("t", "", "CIDR to scan (example: 192.168.0.0/24)")
	listFile    = flag.String("l", "", "File containing a list of CIDRs")
	concurrency = flag.Int("c", 5, "Number of concurrent requests")
	filterRegex = flag.String("f", "", "Regex or string to filter out unwanted domains")
	matchRegex  = flag.String("m", "", "Regex or string to display only domains matching the specified pattern")
	verbose     = flag.Bool("v", false, "Show debug logs")
)

// fetchHostnamesFromShodan retrieves hostnames associated with the given IP from Shodan.
func fetchHostnamesFromShodan(ip string, client *http.Client) []string {
	if *verbose {
		log.Printf("Fetching data for IP: %s\n", ip)
	}
	url := fmt.Sprintf("https://www.shodan.io/host/%s", ip)
	resp, err := client.Get(url)
	if err != nil {
		if *verbose {
			log.Printf("Error fetching data for IP %s: %v\n", ip, err)
		}
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if *verbose {
			log.Printf("Non-200 status code for IP %s: %d\n", ip, resp.StatusCode)
		}
		return nil
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		if *verbose {
			log.Printf("Error parsing HTML for IP %s: %v\n", ip, err)
		}
		return nil
	}

	var hostnames []string
	// Assuming hostnames are constructed using text nodes around <b> tags.
	doc.Find("b").Each(func(i int, s *goquery.Selection) {
		text := s.Text()
		prev := s.Get(0).PrevSibling
		if prev != nil && strings.TrimSpace(prev.Data) != "" {
			domain := strings.TrimSpace(prev.Data) + text
			hostnames = append(hostnames, domain)
		}
	})

	if *verbose && len(hostnames) == 0 {
		log.Printf("No hostnames found for IP %s\n", ip)
	}

	return hostnames
}

// incrementIP increases an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// processCIDR scans all IP addresses in the given CIDR using a worker pool and sends found hostnames to the channel.
func processCIDR(cidr string, ch chan<- string, filter *regexp.Regexp, match *regexp.Regexp, client *http.Client, wg *sync.WaitGroup) {
	defer wg.Done()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing CIDR %s: %v\n", cidr, err)
		return
	}

	// Channel to distribute IP addresses to workers.
	ipChan := make(chan net.IP)
	var localWg sync.WaitGroup

	// Launch a fixed number of workers.
	for i := 0; i < *concurrency; i++ {
		localWg.Add(1)
		go func() {
			defer localWg.Done()
			for ip := range ipChan {
				hostnames := fetchHostnamesFromShodan(ip.String(), client)
				for _, hostname := range hostnames {
					if filter != nil && filter.MatchString(hostname) {
						continue
					}
					if match != nil && !match.MatchString(hostname) {
						continue
					}
					// Send the hostname immediately.
					ch <- hostname
				}
			}
		}()
	}

	// Enqueue IP addresses.
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); {
		// Create a copy of ip because it is mutated in the loop.
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ipChan <- ipCopy
		incrementIP(ip)
	}
	close(ipChan)
	localWg.Wait()
}

// getCIDRList reads CIDRs from a file, flag, or standard input.
func getCIDRList() []string {
	var cidrList []string
	if *listFile != "" {
		file, err := os.Open(*listFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				cidrList = append(cidrList, line)
			}
		}
	} else if *targetCIDR != "" {
		cidrList = append(cidrList, *targetCIDR)
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				cidrList = append(cidrList, line)
			}
		}
	}
	return cidrList
}

// isInputFromPipe checks if data is being piped into stdin.
func isInputFromPipe() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) == 0
}

func main() {
	flag.Parse()

	// Verify that at least one input source is provided.
	if *targetCIDR == "" && *listFile == "" && (os.Stdin == nil || !isInputFromPipe()) {
		fmt.Fprintln(os.Stderr, "Error: You must provide a CIDR with -t, a list of CIDRs with -l, or via stdin.")
		os.Exit(1)
	}

	var filter *regexp.Regexp
	if *filterRegex != "" {
		filter = regexp.MustCompile(*filterRegex)
	}

	var match *regexp.Regexp
	if *matchRegex != "" {
		match = regexp.MustCompile(*matchRegex)
	}

	cidrList := getCIDRList()

	// Channel for results (hostnames) to be printed as soon as they are found.
	ch := make(chan string, *concurrency*10)
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency,
			MaxIdleConnsPerHost: *concurrency,
			IdleConnTimeout:     10 * time.Second,
		},
	}

	// Start processing each CIDR concurrently.
	for _, cidr := range cidrList {
		wg.Add(1)
		go processCIDR(cidr, ch, filter, match, client, &wg)
	}

	// Close the results channel when done.
	go func() {
		wg.Wait()
		close(ch)
	}()

	// Print unique hostnames as they are received.
	uniqueResults := make(map[string]struct{})
	for result := range ch {
		if _, exists := uniqueResults[result]; !exists {
			uniqueResults[result] = struct{}{}
			fmt.Println(result)
		}
	}
}
