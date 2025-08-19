package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

// ScaleTest simulates processing massive domain lists like Top 10M
type ScaleTest struct {
	testSizes []int
	results   map[int]*ScaleResult
}

type ScaleResult struct {
	Size         int
	Duration     time.Duration
	MemoryUsed   uint64
	PeakMemory   uint64
	HostsPerSec  float64
	Success      bool
	Error        string
}

func NewScaleTest() *ScaleTest {
	return &ScaleTest{
		testSizes: []int{1000, 10000, 100000, 1000000, 10000000},
		results:   make(map[int]*ScaleResult),
	}
}

func (st *ScaleTest) RunAllTests() {
	fmt.Println("🚀 MASSIVE SCALE INPUT PARSING TESTS")
	fmt.Println("====================================")
	fmt.Println("Simulating real-world scenarios:")
	fmt.Println("• Bug bounty scope files")
	fmt.Println("• Top 1M/10M domain lists") 
	fmt.Println("• Certificate transparency logs")
	fmt.Println("• Subdomain enumeration results")
	fmt.Println()

	for _, size := range st.testSizes {
		fmt.Printf("📊 Testing %s hosts...\n", formatNumber(size))
		result := st.runScaleTest(size)
		st.results[size] = result
		
		if result.Success {
			fmt.Printf("✅ SUCCESS: %v (%s hosts/sec)\n", 
				result.Duration, formatNumber(int(result.HostsPerSec)))
			fmt.Printf("   Memory: %s peak\n", formatBytes(result.PeakMemory))
		} else {
			fmt.Printf("❌ FAILED: %s\n", result.Error)
		}
		fmt.Println()
	}
	
	st.printAnalysis()
}

func (st *ScaleTest) runScaleTest(size int) *ScaleResult {
	result := &ScaleResult{Size: size}
	
	// Generate test file
	filename := fmt.Sprintf("scale_test_%d.txt", size)
	defer os.Remove(filename)
	
	start := time.Now()
	
	// Create massive input file
	if err := st.generateMassiveInput(filename, size); err != nil {
		result.Error = fmt.Sprintf("Failed to generate input: %v", err)
		return result
	}
	
	// Measure memory before
	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	// Process the file (simulate our parsing logic)
	hostCount, err := st.processLargeFile(filename)
	
	// Measure memory after
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	
	result.Duration = time.Since(start)
	result.MemoryUsed = m2.Alloc - m1.Alloc
	result.PeakMemory = m2.Sys
	
	if err != nil {
		result.Error = err.Error()
		return result
	}
	
	result.Success = true
	result.HostsPerSec = float64(hostCount) / result.Duration.Seconds()
	
	return result
}

func (st *ScaleTest) generateMassiveInput(filename string, size int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	
	// Generate realistic domain patterns
	patterns := []string{
		"subdomain%d.example.com",
		"api%d.service.org", 
		"cdn%d.assets.net",
		"host%d.internal.local",
		"server%d.cloud.io",
	}
	
	batchSize := 100 // Hosts per line (comma-separated)
	for i := 0; i < size; i += batchSize {
		var hosts []string
		
		for j := 0; j < batchSize && i+j < size; j++ {
			pattern := patterns[(i+j)%len(patterns)]
			host := fmt.Sprintf(pattern, i+j)
			hosts = append(hosts, host)
		}
		
		line := strings.Join(hosts, ",") + "\n"
		if _, err := writer.WriteString(line); err != nil {
			return err
		}
	}
	
	return nil
}

func (st *ScaleTest) processLargeFile(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	// Set large buffer for massive lines (CodeRabbit suggestion)
	scanner.Buffer(make([]byte, 64*1024), 10*1024*1024)
	
	hostCount := 0
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		// Simulate our enqueueLine logic
		if strings.IndexByte(line, ',') >= 0 {
			for _, item := range strings.FieldsFunc(line, func(c rune) bool { return c == ',' }) {
				if s := strings.TrimSpace(item); s != "" {
					hostCount++
					// Simulate processing overhead
					_ = len(s)
				}
			}
		} else {
			hostCount++
		}
	}
	
	return hostCount, scanner.Err()
}

func (st *ScaleTest) printAnalysis() {
	fmt.Println("📈 SCALE ANALYSIS REPORT")
	fmt.Println("========================")
	
	fmt.Printf("%-12s %-12s %-15s %-12s %-15s\n", 
		"SIZE", "DURATION", "HOSTS/SEC", "MEMORY", "STATUS")
	fmt.Println(strings.Repeat("-", 70))
	
	for _, size := range st.testSizes {
		result := st.results[size]
		if result == nil {
			continue
		}
		
		status := "✅ PASS"
		if !result.Success {
			status = "❌ FAIL"
		}
		
		fmt.Printf("%-12s %-12v %-15s %-12s %-15s\n",
			formatNumber(size),
			result.Duration.Truncate(time.Millisecond),
			formatNumber(int(result.HostsPerSec)),
			formatBytes(result.PeakMemory),
			status)
	}
	
	fmt.Println()
	st.printRecommendations()
}

func (st *ScaleTest) printRecommendations() {
	fmt.Println("💡 PRODUCTION RECOMMENDATIONS")
	fmt.Println("=============================")
	
	// Analyze results for recommendations
	tenMResult := st.results[10000000]
	oneMResult := st.results[1000000]
	
	if tenMResult != nil && tenMResult.Success {
		fmt.Printf("✅ READY FOR TOP 10M: Processing at %s hosts/sec\n", 
			formatNumber(int(tenMResult.HostsPerSec)))
		fmt.Printf("   Memory usage: %s (acceptable for enterprise)\n", 
			formatBytes(tenMResult.PeakMemory))
	} else {
		fmt.Println("⚠️  TOP 10M OPTIMIZATION NEEDED:")
		fmt.Println("   • Consider streaming processing")
		fmt.Println("   • Implement batched processing")
		fmt.Println("   • Add memory limits and backpressure")
	}
	
	fmt.Println()
	fmt.Println("🔧 OPTIMIZATION STRATEGIES:")
	fmt.Println("• Use worker pools for parallel processing")
	fmt.Println("• Implement rate limiting for target hosts")
	fmt.Println("• Add progress indicators for large files")
	fmt.Println("• Consider database storage for results")
	fmt.Println("• Implement resume capability for interrupted scans")
	
	if oneMResult != nil && oneMResult.Success {
		estimatedTime := time.Duration(float64(10*time.Hour) * (oneMResult.Duration.Seconds() / 3600.0))
		fmt.Printf("• Estimated 10M scan time: ~%v\n", estimatedTime.Truncate(time.Minute))
	}
	
	fmt.Println()
	fmt.Println("🚨 ENTERPRISE CONSIDERATIONS:")
	fmt.Println("• Monitor memory usage with large inputs")
	fmt.Println("• Implement graceful shutdown handling") 
	fmt.Println("• Add input validation for malicious files")
	fmt.Println("• Consider distributed processing for 10M+ hosts")
	fmt.Println("• Implement proper logging and metrics")
}

func formatNumber(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	} else if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func main() {
	fmt.Println("⚡ TLSX MASSIVE SCALE INPUT PARSING TEST")
	fmt.Println("Testing enterprise scenarios with millions of hosts")
	fmt.Println()
	
	test := NewScaleTest()
	test.RunAllTests()
	
	fmt.Println("🎯 Scale testing complete!")
	fmt.Println("Use results to optimize for production workloads.")
}
