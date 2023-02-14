package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
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
		log.Fatalf("failed to marshal cipherstats %v", err)
	}
	err = os.WriteFile(cipherfile, bin, 0600)
	if err != nil {
		log.Fatalf("failed to write ciphers to file got %v", err)
	}
	log.Printf("updated cipherstatus.json, total unique ciphers : %v\n", len(ciphers))
}

func FetchAndLoadCiphers(url string) {
	res, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		log.Fatalf("status code error: %d %s", res.StatusCode, res.Status)
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}
	doc.Find(".long-string").Each(func(i int, s *goquery.Selection) {
		arr := strings.Fields(s.Text())
		if len(arr) > 1 {
			ciphers[strings.ToUpper(arr[1])] = arr[0]
		}
	})
}
