package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type fetcher func(url string) []*net.IPNet
type CDN struct {
	url    string
	sender fetcher
}
type Config struct {
	SendRequest []string `yaml:"SendRequest"`
	ReadFileUrl []string `yaml:"ReadFileUrl"`
}

var (
	isSilent, showVersion, activeMode, updateAll, updateRanges bool
	input, output, savePath                                    string
	homeDIR, _                                                 = os.UserHomeDir()
	config                                                     Config
	threads                                                    int
	CDNS                                                       []CDN
	wg                                                         sync.WaitGroup
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	VERSION     = "1.0.31"
)

func main() {
	var allRange []*net.IPNet
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Removing CDN IPs from the list of IP addresses")
	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&input, "subdomains", "s", "", "Input file containing subdomains (use '-' for STDIN)"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&threads, "threads", "t", 10, "Number of threads for concurrent processing"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.BoolVarP(&activeMode, "active", "a", false, "Active mode for check akamai"),
		flagSet.BoolVarP(&updateAll, "update-all", "ua", false, "Update CUT-CDN Data (providers & ranges)"),
		flagSet.BoolVarP(&updateRanges, "update-ranges", "ur", false, "Update CUT-CDN Data (just ranges)"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&output, "output", "o", "CLI", "File to write output to (optional)"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVarP(&isSilent, "silent", "q", false, "Show only subdomains in output"),
		flagSet.BoolVarP(&showVersion, "version", "v", false, "Show version of cut-cdn"),
	)

	_ = flagSet.Parse()
	baseConfig(updateAll, updateRanges)

	if showVersion {
		printText(false, "Current Version: v"+VERSION, "Info")
		os.Exit(0)
	}

	if input == "" {
		printText(isSilent, "Input is empty!\n\n", "Error")
		flag.PrintDefaults()
		os.Exit(1)
	}
	checkUpdate(isSilent)

	printText(isSilent, "Loading All CDN Range", "Info")
	allRange = loadAllCDN()
	printText(isSilent, "All CDN Range Loaded", "Info")

	if output != "CLI" {
		_, err := os.Create(output)
		checkError(err)
	}

	// Read subdomains from file or STDIN
	var subdomains []string
	if input == "-" {
		subdomains = readSubdomainsFromSTDIN()
	} else {
		subdomains = readSubdomainsFromFile(input)
	}

	// Create a buffered channel for subdomains
	subdomainChan := make(chan string, len(subdomains))
	for _, subdomain := range subdomains {
		subdomainChan <- subdomain
	}
	close(subdomainChan)

	// Create a buffered channel for results
	resultChan := make(chan string, len(subdomains))

	// Start worker goroutines
	printText(isSilent, fmt.Sprintf("Starting %d workers for processing", threads), "Info")
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker(allRange, subdomainChan, resultChan)
	}

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Write results to output
	printText(isSilent, "Start Checking Subdomains", "Info")
	if output == "CLI" {
		printText(isSilent, "", "Print")
		printText(isSilent, colorGreen+"[⚡] Subdomains Not Behind CDN ⤵"+colorReset, "Print")
	}

	for result := range resultChan {
		if output == "CLI" {
			fmt.Println(result)
		} else {
			file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY, 0666)
			checkError(err)
			_, err = fmt.Fprintln(file, result)
			checkError(err)
			err = file.Close()
			checkError(err)
		}
	}
}

// Worker function to process subdomains
func worker(allCidr []*net.IPNet, subdomainChan <-chan string, resultChan chan<- string) {
	defer wg.Done()

	for subdomain := range subdomainChan {
		ips, err := net.LookupIP(subdomain)
		if err != nil {
			continue
		}

		isBehindCDN := false
		for _, ip := range ips {
			for _, cidr := range allCidr {
				if cidr.Contains(ip) {
					isBehindCDN = true
					break
				}
			}
			if isBehindCDN {
				break
			}
		}

		if !isBehindCDN {
			resultChan <- subdomain
		}
	}
}

// Read subdomains from a file
func readSubdomainsFromFile(filename string) []string {
	var subdomains []string
	file, err := os.Open(filename)
	checkError(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}
	return subdomains
}

// Read subdomains from STDIN
func readSubdomainsFromSTDIN() []string {
	var subdomains []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}
	return subdomains
}

// createGroup creates a group of flags in the flagSet
func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

// baseConfig sets up the configuration files and directories
func baseConfig(updateAll bool, updateRanges bool) {
	func() {
		if _, err := os.Stat(homeDIR + "/.config"); os.IsNotExist(err) {
			_ = os.Mkdir(homeDIR+"/.config", os.ModePerm)
		}

		if _, err := os.Stat(homeDIR + "/.config/cut-cdn-subdomain"); os.IsNotExist(err) {
			printText(isSilent, "Create Cut-CDN DIR", "Info")
			_ = os.Mkdir(homeDIR+"/.config/cut-cdn-subdomain", os.ModePerm)
		}
	}()

	if updateAll {
		_ = os.Remove(homeDIR + "/.config/cut-cdn-subdomain/providers.yaml")
		_ = os.Remove(homeDIR + "/.config/cut-cdn-subdomain/ranges.txt")
	} else if updateRanges {
		_ = os.Remove(homeDIR + "/.config/cut-cdn-subdomain/ranges.txt")
	}

	func() {
		if _, err := os.Stat(homeDIR + "/.config/cut-cdn-subdomain/providers.yaml"); os.IsNotExist(err) {
			printText(isSilent, "Create Cut-CDN Providers File", "Info")
			_, _ = os.Create(homeDIR + "/.config/cut-cdn-subdomain/providers.yaml")

			req, _ := http.NewRequest("GET", "https://raw.githubusercontent.com/ImAyrix/cut-cdn/master/static/providers.yaml", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0")
			resp, _ := http.Get("https://raw.githubusercontent.com/ImAyrix/cut-cdn/master/static/providers.yaml")

			body, _ := io.ReadAll(resp.Body)
			_ = os.WriteFile(homeDIR+"/.config/cut-cdn-subdomain/providers.yaml", body, 0644)
		}
	}()

	func() {
		if _, err := os.Stat(homeDIR + "/.config/cut-cdn-subdomain/ranges.txt"); os.IsNotExist(err) {
			printText(isSilent, "Create CDN CIDRs File", "Info")
			file, _ := os.Create(homeDIR + "/.config/cut-cdn-subdomain/ranges.txt")
			allRanges := loadAllCDNOnline()
			data := ""
			for _, cidr := range allRanges {
				if !strings.Contains(data, cidr.String()) {
					data += cidr.String() + "\n"
				}
			}
			_, _ = file.WriteString(data)
		}
	}()
}

// printText prints messages to the console with different log levels
func printText(isSilent bool, text string, textType string) {
	if !isSilent {
		switch textType {
		case "Info":
			gologger.Info().Msg(text)
		case "Print":
			gologger.Print().Msg(text)
		case "Error":
			gologger.Error().Msg(text)
		}
	}
}

// checkUpdate checks if a newer version of the program is available
func checkUpdate(isSilent bool) {
	resp, err := http.Get("https://github.com/ImAyrix/cut-cdn")
	checkError(err)

	respByte, err := io.ReadAll(resp.Body)
	checkError(err)
	body := string(respByte)

	re, e := regexp.Compile(`cut-cdn\s+v(\d\.\d\.\d+)`)
	checkError(e)

	if re.FindStringSubmatch(body)[1] != VERSION {
		printText(isSilent, "", "Print")
		printText(isSilent, "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -", "Print")
		printText(isSilent, fmt.Sprintf("|    %v🔥  Please update Cut-CDN!%v                                      |", colorGreen, colorReset), "Print")
		printText(isSilent, "|    💣  Run: go install github.com/ImAyrix/cut-cdn@latest           |", "Print")
		printText(isSilent, "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -", "Print")
		printText(isSilent, "", "Print")
	}
}

// loadAllCDN loads CDN IP ranges from a local file
func loadAllCDN() []*net.IPNet {
	var allRanges []*net.IPNet
	data, err := os.ReadFile(homeDIR + "/.config/cut-cdn-subdomain/ranges.txt")
	checkError(err)

	for _, cidr := range strings.Split(string(data), "\n") {
		if cidr != "" {
			_, cidr, _ := net.ParseCIDR(string(cidr))
			allRanges = append(allRanges, cidr)
		}
	}

	return allRanges
}

// loadAllCDNOnline fetches CDN IP ranges from online sources
func loadAllCDNOnline() []*net.IPNet {
	var (
		allRanges []*net.IPNet
		wg        sync.WaitGroup
	)

	cleanenv.ReadConfig(homeDIR+"/.config/cut-cdn-subdomain/providers.yaml", &config)
	sendReqs := config.SendRequest
	readFiles := config.ReadFileUrl

	for _, v := range sendReqs {
		if v != "" {
			CDNS = append(CDNS, CDN{v, sendRequest})
		}
	}

	for _, v := range readFiles {
		if v != "" {
			CDNS = append(CDNS, CDN{v, readFileUrl})
		}
	}

	cidrChan := make(chan []*net.IPNet, len(CDNS)+1)
	wg.Add(len(CDNS))

	for _, cdn := range CDNS {
		cdn := cdn
		go func() {
			defer wg.Done()
			cidr := cdn.sender(cdn.url)
			cidrChan <- cidr
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		incapsulaIPUrl := "https://my.incapsula.com/api/integration/v1/ips"
		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		resp, err := client.Post(incapsulaIPUrl, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte("resp_format=text")))
		if !checkError(err) {
			body, err := io.ReadAll(resp.Body)
			checkError(err)
			cidr := regexIp(string(body))
			cidrChan <- cidr
		}
	}()

	wg.Wait()
	close(cidrChan)

	for cidr := range cidrChan {
		allRanges = append(allRanges, cidr...)
	}
	return allRanges
}

func sendRequest(url string) []*net.IPNet {
	req, err := http.NewRequest("GET", url, nil)
	checkError(err)

	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0")
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if checkError(err) {
		return []*net.IPNet{}
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		checkError(err)
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	checkError(err)
	return regexIp(string(body))
}

func readFileUrl(url string) []*net.IPNet {
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
		Timeout: 60 * time.Second,
	}

	resp, err := client.Get(url)
	if checkError(err) {
		return []*net.IPNet{}
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		checkError(err)
	}(resp.Body)

	data, err := io.ReadAll(resp.Body)
	checkError(err)
	return regexIp(string(data))
}

func regexIp(body string) []*net.IPNet {
	body = strings.Replace(body, "\\/", "/", -1)
	re, e := regexp.Compile(`(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))`)
	checkError(e)

	var ranges []*net.IPNet
	for _, v := range re.FindAll([]byte(body), -1) {
		_, cidr, err := net.ParseCIDR(string(v))
		checkError(err)
		ranges = append(ranges, cidr)
	}
	return ranges
}

func checkError(e error) bool {
	if e != nil {
		gologger.Error().Msg(e.Error())
		return true
	}
	return false
}
