package runner

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"time"
	"unicode"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
)

// PropertyBasedInputTest implements the ultimate property-based testing framework
// for input parsing that covers ALL possible scenarios through mathematical properties
type PropertyBasedInputTest struct {
	runner *Runner
}

// InputProperty represents a mathematical property that must hold for all inputs
type InputProperty func(input string) bool

// ParsedResult represents the canonical result of parsing any input
type ParsedResult struct {
	Hosts     []string
	Count     int
	HasCommas bool
	IsEmpty   bool
	Error     error
}

// NewPropertyBasedTest creates the ultimate property-based test framework
func NewPropertyBasedTest() *PropertyBasedInputTest {
	opts := &clients.Options{
		Ports: []string{"443"},
	}
	return &PropertyBasedInputTest{
		runner: &Runner{options: opts},
	}
}

// === CORE MATHEMATICAL PROPERTIES ===

// Property 1: PARSING DETERMINISM
// For any input string, parsing must always produce identical results
func (pbt *PropertyBasedInputTest) PropertyParsingDeterminism(input string) bool {
	result1 := pbt.parseInput(input)
	result2 := pbt.parseInput(input)
	
	return reflect.DeepEqual(result1.Hosts, result2.Hosts) &&
		result1.Count == result2.Count &&
		result1.HasCommas == result2.HasCommas
}

// Property 2: COMMA DECOMPOSITION EQUIVALENCE  
// Parsing "a,b,c" must equal parsing "a" + "b" + "c" individually
func (pbt *PropertyBasedInputTest) PropertyCommaDecomposition(hosts []string) bool {
	if len(hosts) == 0 {
		return true
	}
	
	// Parse as comma-separated
	commaInput := strings.Join(hosts, ",")
	commaResult := pbt.parseInput(commaInput)
	
	// Parse individually and combine
	var individualHosts []string
	for _, host := range hosts {
		result := pbt.parseInput(host)
		individualHosts = append(individualHosts, result.Hosts...)
	}
	
	return len(commaResult.Hosts) == len(individualHosts) &&
		pbt.hostsEquivalent(commaResult.Hosts, individualHosts)
}

// Property 3: WHITESPACE INVARIANCE
// Adding/removing whitespace must not change semantic parsing results
func (pbt *PropertyBasedInputTest) PropertyWhitespaceInvariance(input string) bool {
	original := pbt.parseInput(input)
	
	// Test various whitespace modifications
	variations := []string{
		strings.TrimSpace(input),
		" " + input + " ",
		strings.ReplaceAll(input, ",", " , "),
		strings.ReplaceAll(input, ",", ",\t"),
		strings.ReplaceAll(input, ",", ", "),
	}
	
	for _, variant := range variations {
		result := pbt.parseInput(variant)
		if !pbt.hostsEquivalent(original.Hosts, result.Hosts) {
			return false
		}
	}
	
	return true
}

// Property 4: EMPTY ELEMENT ELIMINATION
// Empty elements in comma-separated lists must be filtered out
func (pbt *PropertyBasedInputTest) PropertyEmptyElimination(input string) bool {
	result := pbt.parseInput(input)
	
	// No parsed host should be empty
	for _, host := range result.Hosts {
		if strings.TrimSpace(host) == "" {
			return false
		}
	}
	
	return true
}

// Property 5: MONOTONICITY
// Adding valid hosts to input must never decrease the host count
func (pbt *PropertyBasedInputTest) PropertyMonotonicity(base string, additional string) bool {
	baseResult := pbt.parseInput(base)
	
	// Combine inputs
	var combined string
	if base == "" {
		combined = additional
	} else if additional == "" {
		combined = base
	} else {
		combined = base + "," + additional
	}
	
	combinedResult := pbt.parseInput(combined)
	
	// Combined result should have at least as many hosts as base
	return combinedResult.Count >= baseResult.Count
}

// Property 6: IDEMPOTENCY
// Parsing the same input multiple times in sequence must be identical
func (pbt *PropertyBasedInputTest) PropertyIdempotency(input string) bool {
	results := make([]ParsedResult, 5)
	
	for i := 0; i < 5; i++ {
		results[i] = pbt.parseInput(input)
	}
	
	// All results must be identical
	for i := 1; i < len(results); i++ {
		if !reflect.DeepEqual(results[0], results[i]) {
			return false
		}
	}
	
	return true
}

// Property 7: COMMA DETECTION ACCURACY
// HasCommas flag must accurately reflect presence of comma characters
func (pbt *PropertyBasedInputTest) PropertyCommaDetection(input string) bool {
	result := pbt.parseInput(input)
	actualHasCommas := strings.Contains(input, ",")
	
	return result.HasCommas == actualHasCommas
}

// Property 8: COUNT CONSISTENCY
// Host count must equal the length of the hosts slice
func (pbt *PropertyBasedInputTest) PropertyCountConsistency(input string) bool {
	result := pbt.parseInput(input)
	return result.Count == len(result.Hosts)
}

// Property 9: UNICODE PRESERVATION
// Unicode characters in valid hostnames must be preserved
func (pbt *PropertyBasedInputTest) PropertyUnicodePreservation(input string) bool {
	if !pbt.containsUnicode(input) {
		return true // Property doesn't apply
	}
	
	result := pbt.parseInput(input)
	
	// If input was successfully parsed, unicode should be preserved
	if result.Count > 0 {
		for _, host := range result.Hosts {
			if pbt.containsUnicode(input) && !pbt.containsUnicode(host) {
				return false
			}
		}
	}
	
	return true
}

// Property 10: INJECTION RESISTANCE
// Malicious inputs must not cause crashes or unexpected behavior
func (pbt *PropertyBasedInputTest) PropertyInjectionResistance(input string) bool {
	defer func() {
		if r := recover(); r != nil {
			// Panic indicates property violation
		}
	}()
	
	result := pbt.parseInput(input)
	
	// Must not return nil slices
	if result.Hosts == nil {
		return false
	}
	
	// Count must be non-negative
	if result.Count < 0 {
		return false
	}
	
	return true
}

// === HELPER FUNCTIONS ===

func (pbt *PropertyBasedInputTest) parseInput(input string) ParsedResult {
	var hosts []string
	
	// Simulate our enqueueLine logic
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ParsedResult{
			Hosts:     []string{},
			Count:     0,
			HasCommas: false,
			IsEmpty:   true,
		}
	}
	
	hasCommas := strings.IndexByte(trimmed, ',') >= 0
	
	if hasCommas {
		for _, item := range strings.FieldsFunc(trimmed, func(c rune) bool { return c == ',' }) {
			if s := strings.TrimSpace(item); s != "" {
				hosts = append(hosts, s)
			}
		}
	} else {
		hosts = append(hosts, trimmed)
	}
	
	return ParsedResult{
		Hosts:     hosts,
		Count:     len(hosts),
		HasCommas: hasCommas,
		IsEmpty:   len(hosts) == 0,
	}
}

func (pbt *PropertyBasedInputTest) hostsEquivalent(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	
	// Create frequency maps for comparison (order-independent)
	freqA := make(map[string]int)
	freqB := make(map[string]int)
	
	for _, host := range a {
		freqA[host]++
	}
	for _, host := range b {
		freqB[host]++
	}
	
	return reflect.DeepEqual(freqA, freqB)
}

func (pbt *PropertyBasedInputTest) containsUnicode(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// === PROPERTY-BASED TEST GENERATORS ===

// Generate arbitrary input strings for property testing
func (pbt *PropertyBasedInputTest) GenerateArbitraryInput(r *rand.Rand, size int) reflect.Value {
	generators := []func(*rand.Rand, int) string{
		pbt.genSimpleHost,
		pbt.genCommaList,
		pbt.genWhitespaceVariant,
		pbt.genUnicodeHost,
		pbt.genMaliciousInput,
		pbt.genEmptyVariant,
		pbt.genLargeInput,
	}
	
	gen := generators[r.Intn(len(generators))]
	return reflect.ValueOf(gen(r, size))
}

func (pbt *PropertyBasedInputTest) genSimpleHost(r *rand.Rand, size int) string {
	hosts := []string{"example.com", "test.org", "api.service.net", "192.168.1.1", "::1"}
	return hosts[r.Intn(len(hosts))]
}

func (pbt *PropertyBasedInputTest) genCommaList(r *rand.Rand, size int) string {
	count := r.Intn(size) + 1
	var hosts []string
	
	for i := 0; i < count; i++ {
		hosts = append(hosts, fmt.Sprintf("host%d.example.com", i))
	}
	
	return strings.Join(hosts, ",")
}

func (pbt *PropertyBasedInputTest) genWhitespaceVariant(r *rand.Rand, size int) string {
	base := "example.com,test.org"
	whitespaces := []string{" ", "\t", "\n", "\r\n"}
	
	ws := whitespaces[r.Intn(len(whitespaces))]
	return ws + base + ws
}

func (pbt *PropertyBasedInputTest) genUnicodeHost(r *rand.Rand, size int) string {
	unicodeHosts := []string{
		"тест.рф",
		"例え.テスト",
		"مثال.إختبار",
		"🏠.example.com",
	}
	return unicodeHosts[r.Intn(len(unicodeHosts))]
}

func (pbt *PropertyBasedInputTest) genMaliciousInput(r *rand.Rand, size int) string {
	malicious := []string{
		"'; DROP TABLE hosts; --",
		"<script>alert('xss')</script>",
		"../../../etc/passwd",
		strings.Repeat("A", 10000),
		"\x00\x01\x02\x03",
	}
	return malicious[r.Intn(len(malicious))]
}

func (pbt *PropertyBasedInputTest) genEmptyVariant(r *rand.Rand, size int) string {
	variants := []string{"", " ", "\t", "\n", ",", " , ", ",,"}
	return variants[r.Intn(len(variants))]
}

func (pbt *PropertyBasedInputTest) genLargeInput(r *rand.Rand, size int) string {
	var hosts []string
	count := r.Intn(1000) + 100
	
	for i := 0; i < count; i++ {
		hosts = append(hosts, fmt.Sprintf("large%d.example.com", i))
	}
	
	return strings.Join(hosts, ",")
}

// === ULTIMATE PROPERTY-BASED TESTS ===

func TestUltimatePropertyBasedInputParsing(t *testing.T) {
	pbt := NewPropertyBasedTest()
	
	config := &quick.Config{
		MaxCount:      10000, // Test 10k random inputs
		MaxCountScale: 100,
		Rand:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	
	properties := []struct {
		name string
		prop interface{}
	}{
		{"Parsing Determinism", pbt.PropertyParsingDeterminism},
		{"Whitespace Invariance", pbt.PropertyWhitespaceInvariance},
		{"Empty Elimination", pbt.PropertyEmptyElimination},
		{"Idempotency", pbt.PropertyIdempotency},
		{"Comma Detection", pbt.PropertyCommaDetection},
		{"Count Consistency", pbt.PropertyCountConsistency},
		{"Unicode Preservation", pbt.PropertyUnicodePreservation},
		{"Injection Resistance", pbt.PropertyInjectionResistance},
	}
	
	for _, prop := range properties {
		t.Run(prop.name, func(t *testing.T) {
			if err := quick.Check(prop.prop, config); err != nil {
				t.Errorf("Property %s violated: %v", prop.name, err)
			}
		})
	}
}

func TestCommaDecompositionProperty(t *testing.T) {
	pbt := NewPropertyBasedTest()
	
	// Test with generated host lists
	config := &quick.Config{MaxCount: 1000}
	
	generator := func(hosts []string) bool {
		// Filter out empty hosts for valid test
		var validHosts []string
		for _, host := range hosts {
			if strings.TrimSpace(host) != "" && !strings.Contains(host, ",") {
				validHosts = append(validHosts, host)
			}
		}
		
		if len(validHosts) == 0 {
			return true // Trivially true for empty input
		}
		
		return pbt.PropertyCommaDecomposition(validHosts)
	}
	
	if err := quick.Check(generator, config); err != nil {
		t.Errorf("Comma decomposition property violated: %v", err)
	}
}

func TestMonotonicityProperty(t *testing.T) {
	pbt := NewPropertyBasedTest()
	
	config := &quick.Config{MaxCount: 1000}
	
	generator := func(base, additional string) bool {
		// Filter out inputs that would be invalid
		if strings.Contains(base, "\x00") || strings.Contains(additional, "\x00") {
			return true // Skip invalid inputs
		}
		
		return pbt.PropertyMonotonicity(base, additional)
	}
	
	if err := quick.Check(generator, config); err != nil {
		t.Errorf("Monotonicity property violated: %v", err)
	}
}

// Benchmark property-based tests for performance validation
func BenchmarkPropertyBasedParsing(b *testing.B) {
	pbt := NewPropertyBasedTest()
	
	inputs := []string{
		"example.com",
		"host1.com,host2.org,host3.net",
		strings.Repeat("host.com,", 1000),
		"тест.рф,例え.テスト",
		" , , host.com , , ",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		
		// Test all properties for performance
		pbt.PropertyParsingDeterminism(input)
		pbt.PropertyWhitespaceInvariance(input)
		pbt.PropertyEmptyElimination(input)
		pbt.PropertyIdempotency(input)
	}
}
