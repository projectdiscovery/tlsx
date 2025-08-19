package main

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// TestCase represents a single test scenario
type TestCase struct {
	Name        string
	Input       string
	Description string
	Category    string
}

// TestGenerator generates comprehensive test cases for input parsing
type TestGenerator struct {
	cases []TestCase
}

func NewTestGenerator() *TestGenerator {
	return &TestGenerator{cases: make([]TestCase, 0)}
}

func (tg *TestGenerator) addCase(name, input, description, category string) {
	tg.cases = append(tg.cases, TestCase{
		Name:        name,
		Input:       input,
		Description: description,
		Category:    category,
	})
}

// Generate all rigorous test variants
func (tg *TestGenerator) GenerateAll() {
	tg.generateBasicCases()
	tg.generateWhitespaceCases()
	tg.generateCommaCases()
	tg.generateIPCases()
	tg.generatePortCases()
	tg.generateCIDRCases()
	tg.generateUnicodeCases()
	tg.generateMalformedCases()
	tg.generateLargeCases()
	tg.generateSecurityCases()
	tg.generateRealWorldCases()
	tg.generateEdgeCases()
}

func (tg *TestGenerator) generateBasicCases() {
	// Empty and whitespace
	tg.addCase("empty", "", "Empty string", "basic")
	tg.addCase("whitespace_only", "   \t\n  ", "Only whitespace", "basic")
	tg.addCase("single_space", " ", "Single space", "basic")
	
	// Single hosts
	tg.addCase("single_domain", "example.com", "Single domain", "basic")
	tg.addCase("single_subdomain", "sub.example.com", "Single subdomain", "basic")
	tg.addCase("single_deep_subdomain", "a.b.c.d.example.com", "Deep subdomain", "basic")
}

func (tg *TestGenerator) generateWhitespaceCases() {
	// Various whitespace combinations
	tg.addCase("leading_spaces", "  example.com", "Leading spaces", "whitespace")
	tg.addCase("trailing_spaces", "example.com  ", "Trailing spaces", "whitespace")
	tg.addCase("surrounding_spaces", "  example.com  ", "Surrounding spaces", "whitespace")
	tg.addCase("tabs", "\texample.com\t", "Tab characters", "whitespace")
	tg.addCase("mixed_whitespace", " \t example.com \n ", "Mixed whitespace", "whitespace")
	tg.addCase("crlf", "example.com\r\n", "Windows line ending", "whitespace")
	tg.addCase("lf", "example.com\n", "Unix line ending", "whitespace")
	tg.addCase("cr", "example.com\r", "Mac line ending", "whitespace")
}

func (tg *TestGenerator) generateCommaCases() {
	// Comma variations
	tg.addCase("two_hosts", "example.com,google.com", "Two comma-separated hosts", "comma")
	tg.addCase("three_hosts", "example.com,google.com,github.com", "Three comma-separated hosts", "comma")
	tg.addCase("spaces_around_commas", "example.com , google.com , github.com", "Spaces around commas", "comma")
	tg.addCase("trailing_comma", "example.com,google.com,", "Trailing comma", "comma")
	tg.addCase("leading_comma", ",example.com,google.com", "Leading comma", "comma")
	tg.addCase("multiple_commas", "example.com,,,google.com", "Multiple consecutive commas", "comma")
	tg.addCase("only_commas", ",,,", "Only commas", "comma")
	tg.addCase("comma_space_mix", " , example.com , , google.com , ", "Mixed commas and spaces", "comma")
	tg.addCase("many_hosts", strings.Join(generateHosts(50), ","), "50 comma-separated hosts", "comma")
}

func (tg *TestGenerator) generateIPCases() {
	// IPv4 addresses
	tg.addCase("ipv4_single", "192.168.1.1", "Single IPv4", "ip")
	tg.addCase("ipv4_multiple", "192.168.1.1,10.0.0.1,127.0.0.1", "Multiple IPv4", "ip")
	tg.addCase("ipv4_private", "192.168.1.1,172.16.0.1,10.0.0.1", "Private IPv4 ranges", "ip")
	tg.addCase("ipv4_public", "8.8.8.8,1.1.1.1,208.67.222.222", "Public DNS servers", "ip")
	
	// IPv6 addresses
	tg.addCase("ipv6_single", "::1", "IPv6 localhost", "ip")
	tg.addCase("ipv6_multiple", "::1,2001:db8::1,fe80::1", "Multiple IPv6", "ip")
	tg.addCase("ipv6_full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "Full IPv6 address", "ip")
	tg.addCase("ipv6_compressed", "2001:db8:85a3::8a2e:370:7334", "Compressed IPv6", "ip")
	tg.addCase("ipv6_mixed", "192.168.1.1,::1,example.com", "Mixed IPv4, IPv6, domain", "ip")
}

func (tg *TestGenerator) generatePortCases() {
	// Ports with hosts
	tg.addCase("host_with_port", "example.com:443", "Host with port", "port")
	tg.addCase("multiple_ports", "example.com:443,google.com:80,github.com:22", "Multiple hosts with ports", "port")
	tg.addCase("ip_with_port", "192.168.1.1:8080", "IP with port", "port")
	tg.addCase("ipv6_with_port", "[::1]:8080", "IPv6 with port", "port")
	tg.addCase("mixed_ports", "example.com:443,192.168.1.1:8080,[::1]:9000", "Mixed hosts with ports", "port")
}

func (tg *TestGenerator) generateCIDRCases() {
	// CIDR ranges
	tg.addCase("cidr_single", "192.168.1.0/24", "Single CIDR", "cidr")
	tg.addCase("cidr_multiple", "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12", "Multiple CIDRs", "cidr")
	tg.addCase("cidr_ipv6", "2001:db8::/32", "IPv6 CIDR", "cidr")
	tg.addCase("cidr_mixed", "192.168.1.0/24,example.com,2001:db8::/32", "Mixed CIDR and domains", "cidr")
}

func (tg *TestGenerator) generateUnicodeCases() {
	// Unicode and internationalized domains
	tg.addCase("unicode_domains", "例え.com,тест.org,مثال.net", "Unicode domain names", "unicode")
	tg.addCase("punycode", "xn--fsq.com,xn--e1afmkfd.org", "Punycode domains", "unicode")
	tg.addCase("emoji_domain", "💻.ws,🌐.com", "Emoji domains", "unicode")
}

func (tg *TestGenerator) generateMalformedCases() {
	// Malformed inputs that should be handled gracefully
	tg.addCase("double_dots", "example..com", "Double dots in domain", "malformed")
	tg.addCase("leading_dot", ".example.com", "Leading dot", "malformed")
	tg.addCase("trailing_dot", "example.com.", "Trailing dot", "malformed")
	tg.addCase("invalid_chars", "exam<ple>.com", "Invalid characters", "malformed")
	tg.addCase("too_long_label", strings.Repeat("a", 64) + ".com", "Label too long", "malformed")
	tg.addCase("empty_labels", "example..com,test...org", "Empty labels", "malformed")
}

func (tg *TestGenerator) generateLargeCases() {
	// Large input scenarios
	tg.addCase("very_long_domain", strings.Repeat("subdomain.", 20) + "example.com", "Very long domain", "large")
	tg.addCase("max_domain_length", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + ".com", "Maximum domain length", "large")
	tg.addCase("many_subdomains", strings.Join(generateSubdomains(100), ","), "100 subdomains", "large")
	tg.addCase("huge_csv_line", strings.Join(generateHosts(1000), ","), "1000 hosts in CSV", "large")
}

func (tg *TestGenerator) generateSecurityCases() {
	// Security-focused test cases
	tg.addCase("sql_injection", "'; DROP TABLE hosts; --", "SQL injection attempt", "security")
	tg.addCase("xss_attempt", "<script>alert('xss')</script>.com", "XSS attempt", "security")
	tg.addCase("path_traversal", "../../../etc/passwd", "Path traversal", "security")
	tg.addCase("null_bytes", "example.com\x00.evil.com", "Null byte injection", "security")
	tg.addCase("buffer_overflow", strings.Repeat("A", 10000), "Buffer overflow attempt", "security")
}

func (tg *TestGenerator) generateRealWorldCases() {
	// Real-world scenarios from security community
	tg.addCase("bug_bounty_scope", "*.example.com,api.example.com,admin.example.com", "Bug bounty scope", "realworld")
	tg.addCase("cloud_services", "s3.amazonaws.com,storage.googleapis.com,blob.core.windows.net", "Cloud services", "realworld")
	tg.addCase("cdn_endpoints", "cdn.example.com,assets.example.com,static.example.com", "CDN endpoints", "realworld")
	tg.addCase("api_endpoints", "api.v1.example.com,api.v2.example.com,graphql.example.com", "API endpoints", "realworld")
	tg.addCase("internal_ranges", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", "Internal IP ranges", "realworld")
}

func (tg *TestGenerator) generateEdgeCases() {
	// Edge cases that might break parsers
	tg.addCase("single_char", "a", "Single character", "edge")
	tg.addCase("numeric_only", "123", "Numeric only", "edge")
	tg.addCase("hyphen_start", "-example.com", "Hyphen at start", "edge")
	tg.addCase("hyphen_end", "example-.com", "Hyphen at end", "edge")
	tg.addCase("underscore", "sub_domain.example.com", "Underscore in subdomain", "edge")
	tg.addCase("mixed_case", "ExAmPlE.CoM,GOOGLE.COM,github.com", "Mixed case domains", "edge")
}

// Helper functions
func generateHosts(count int) []string {
	hosts := make([]string, count)
	for i := 0; i < count; i++ {
		hosts[i] = fmt.Sprintf("host%d.example.com", i)
	}
	return hosts
}

func generateSubdomains(count int) []string {
	subdomains := make([]string, count)
	for i := 0; i < count; i++ {
		subdomains[i] = fmt.Sprintf("sub%d.example.com", i)
	}
	return subdomains
}

// Output methods
func (tg *TestGenerator) WriteTestFiles() error {
	// Write test cases to files organized by category
	categories := make(map[string][]TestCase)
	for _, tc := range tg.cases {
		categories[tc.Category] = append(categories[tc.Category], tc)
	}
	
	for category, cases := range categories {
		filename := fmt.Sprintf("test_cases_%s.txt", category)
		file, err := os.Create(filename)
		if err != nil {
			return err
		}
		defer file.Close()
		
		for _, tc := range cases {
			fmt.Fprintf(file, "# %s: %s\n%s\n\n", tc.Name, tc.Description, tc.Input)
		}
		fmt.Printf("Generated %d test cases in %s\n", len(cases), filename)
	}
	
	return nil
}

func (tg *TestGenerator) WriteGoTest() error {
	file, err := os.Create("generated_test_cases.go")
	if err != nil {
		return err
	}
	defer file.Close()
	
	fmt.Fprintln(file, "package main")
	fmt.Fprintln(file, "")
	fmt.Fprintln(file, "// Generated test cases for rigorous input validation")
	fmt.Fprintln(file, "var testCases = []struct {")
	fmt.Fprintln(file, "\tname     string")
	fmt.Fprintln(file, "\tinput    string")
	fmt.Fprintln(file, "\tcategory string")
	fmt.Fprintln(file, "}{")
	
	for _, tc := range tg.cases {
		fmt.Fprintf(file, "\t{%q, %q, %q},\n", tc.Name, tc.Input, tc.Category)
	}
	
	fmt.Fprintln(file, "}")
	
	return nil
}

func (tg *TestGenerator) PrintSummary() {
	categories := make(map[string]int)
	for _, tc := range tg.cases {
		categories[tc.Category]++
	}
	
	fmt.Printf("\n=== TEST CASE GENERATION SUMMARY ===\n")
	fmt.Printf("Total test cases: %d\n\n", len(tg.cases))
	
	for category, count := range categories {
		fmt.Printf("%-12s: %d cases\n", category, count)
	}
	
	fmt.Printf("\nTest cases cover:\n")
	fmt.Printf("✓ Basic input validation\n")
	fmt.Printf("✓ Whitespace handling\n") 
	fmt.Printf("✓ Comma-separated parsing\n")
	fmt.Printf("✓ IP address formats\n")
	fmt.Printf("✓ Port specifications\n")
	fmt.Printf("✓ CIDR ranges\n")
	fmt.Printf("✓ Unicode domains\n")
	fmt.Printf("✓ Malformed inputs\n")
	fmt.Printf("✓ Large input scenarios\n")
	fmt.Printf("✓ Security attack vectors\n")
	fmt.Printf("✓ Real-world use cases\n")
	fmt.Printf("✓ Edge cases\n")
}

func main() {
	rand.Seed(time.Now().UnixNano())
	
	fmt.Println("🔧 Generating comprehensive test cases for TLSX input parsing...")
	
	generator := NewTestGenerator()
	generator.GenerateAll()
	
	// Write test files
	if err := generator.WriteTestFiles(); err != nil {
		fmt.Printf("Error writing test files: %v\n", err)
		os.Exit(1)
	}
	
	// Write Go test structure
	if err := generator.WriteGoTest(); err != nil {
		fmt.Printf("Error writing Go test: %v\n", err)
		os.Exit(1)
	}
	
	generator.PrintSummary()
	
	fmt.Println("\n🎯 Test generation complete! Use these files to validate input parsing rigor.")
}
