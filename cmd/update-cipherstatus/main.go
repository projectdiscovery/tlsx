package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/gologger"
)

// stores ciphers with stats ex: "AES128-SHA256": "Weak"
var ciphers map[string]string = map[string]string{}

func main() {
	var cipherfile string
	flag.StringVar(&cipherfile, "out-ciphers", "../../assets/cipherstatus_data.json", "File to write cipher stats")
	flag.Parse()

	// Source:  https://ciphersuite.info/cs/?software=all&singlepage=true&tls=all&page=1
	FetchAndLoadCiphers("https://ciphersuite.info/cs/?singlepage=true")
	FetchAndLoadCiphers("https://ciphersuite.info/cs/?software=gnutls&singlepage=true")
	FetchAndLoadCiphers("https://ciphersuite.info/cs/?software=openssl&singlepage=true")

	bin, err := json.Marshal(ciphers)
	if err != nil {
		gologger.Fatal().Msgf("failed to marshal cipherstats %v", err)
	}
	err = os.WriteFile(cipherfile, bin, 0600)
	if err != nil {
		gologger.Fatal().Msgf("failed to write ciphers to file got %v", err)
	}
	gologger.Print().Msgf("updated cipherstatus.json, total unique ciphers : %v\n", len(ciphers))
}

func FetchAndLoadCiphers(url string) {
	res, err := http.Get(url)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		gologger.Fatal().Msgf("status code error: %d %s", res.StatusCode, res.Status)
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	doc.Find(".long-string").Each(func(i int, s *goquery.Selection) {
		arr := strings.Fields(s.Text())
		if len(arr) > 1 {
			ciphers[strings.ToUpper(arr[1])] = arr[0]
		}
	})
}
