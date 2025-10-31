package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// NVD Feed structures (JSON 2.0 format)
type NVDFeed struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Format          string          `json:"format"`
	Version         string          `json:"version"`
	Timestamp       string          `json:"timestamp"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVEData `json:"cve"`
}

type CVEData struct {
	ID           string        `json:"id"`
	Descriptions []Description `json:"descriptions"`
	Published    string        `json:"published"`
	Weaknesses   []Weakness    `json:"weaknesses"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Weakness struct {
	Description []WeaknessDesc `json:"description"`
}

type WeaknessDesc struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

// Training data structure
type TrainingRecord struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CWEs          []string `json:"cwes"`
	AttackVectors []string `json:"attack_vectors"`
	PublishedDate string   `json:"published_date"`
}

// Attack vector mapping
type AttackVectorMapping struct {
	Name        string
	CWEs        []string
	Description string
	Priority    int
}

// Attack vector definitions
var attackVectorMappings = []AttackVectorMapping{
	// Tier 1: Critical (10 vectors)
	{Name: "xss", CWEs: []string{"79", "80", "83"}, Description: "Cross-Site Scripting", Priority: 1},
	{Name: "sql_injection", CWEs: []string{"89"}, Description: "SQL Injection", Priority: 1},
	{Name: "rce", CWEs: []string{"94", "95"}, Description: "Remote Code Execution", Priority: 1},
	{Name: "command_injection", CWEs: []string{"77", "78"}, Description: "OS Command Injection", Priority: 1},
	{Name: "path_traversal", CWEs: []string{"22", "23", "36"}, Description: "Path Traversal", Priority: 1},
	{Name: "ssrf", CWEs: []string{"918"}, Description: "Server-Side Request Forgery", Priority: 1},
	{Name: "deserialization", CWEs: []string{"502"}, Description: "Deserialization Vulnerabilities", Priority: 1},
	{Name: "auth_bypass", CWEs: []string{"287", "288", "290", "302", "306"}, Description: "Authentication Bypass", Priority: 1},
	{Name: "authz_bypass", CWEs: []string{"285", "639"}, Description: "Authorization Bypass", Priority: 1},
	{Name: "file_upload", CWEs: []string{"434"}, Description: "File Upload Vulnerabilities", Priority: 1},

	// Tier 2: High Priority (10 vectors)
	{Name: "csrf", CWEs: []string{"352"}, Description: "Cross-Site Request Forgery", Priority: 2},
	{Name: "xxe", CWEs: []string{"611"}, Description: "XML External Entity", Priority: 2},
	{Name: "ldap_injection", CWEs: []string{"90"}, Description: "LDAP Injection", Priority: 2},
	{Name: "jndi_injection", CWEs: []string{"917"}, Description: "JNDI/Expression Language Injection", Priority: 2},
	{Name: "privilege_escalation", CWEs: []string{"269", "274", "266", "250"}, Description: "Privilege Escalation", Priority: 2},
	{Name: "buffer_overflow", CWEs: []string{"119", "120", "121", "122", "787", "788"}, Description: "Buffer Overflow", Priority: 2},
	{Name: "idor", CWEs: []string{"639", "284"}, Description: "Insecure Direct Object Reference", Priority: 2},
	{Name: "http_desync", CWEs: []string{"444"}, Description: "HTTP Request Smuggling", Priority: 2},
	{Name: "hardcoded_credentials", CWEs: []string{"798", "259", "321"}, Description: "Hard-coded Credentials", Priority: 2},
	{Name: "info_disclosure", CWEs: []string{"200", "209", "213", "215", "532"}, Description: "Information Disclosure", Priority: 2},

	// Tier 3: Medium Priority (15 vectors)
	{Name: "dos", CWEs: []string{"400", "770", "400", "835", "674"}, Description: "Denial of Service", Priority: 3},
	{Name: "nosql_injection", CWEs: []string{"943"}, Description: "NoSQL Injection", Priority: 3},
	{Name: "xpath_injection", CWEs: []string{"643"}, Description: "XPath Injection", Priority: 3},
	{Name: "open_redirect", CWEs: []string{"601"}, Description: "Open Redirect", Priority: 3},
	{Name: "session_fixation", CWEs: []string{"384"}, Description: "Session Fixation", Priority: 3},
	{Name: "crypto_failure", CWEs: []string{"327", "328", "329", "326"}, Description: "Cryptographic Failures", Priority: 3},
	{Name: "integer_overflow", CWEs: []string{"190", "191"}, Description: "Integer Overflow", Priority: 3},
	{Name: "use_after_free", CWEs: []string{"416"}, Description: "Use After Free", Priority: 3},
	{Name: "null_pointer", CWEs: []string{"476"}, Description: "NULL Pointer Dereference", Priority: 3},
	{Name: "format_string", CWEs: []string{"134"}, Description: "Format String Vulnerability", Priority: 3},
	{Name: "email_injection", CWEs: []string{"93"}, Description: "Email Header Injection", Priority: 3},
	{Name: "race_condition", CWEs: []string{"362", "366", "367"}, Description: "Race Condition", Priority: 3},
	{Name: "ssti", CWEs: []string{"1336"}, Description: "Server-Side Template Injection", Priority: 3},
	{Name: "input_validation", CWEs: []string{"20", "1284"}, Description: "Improper Input Validation", Priority: 3},
	{Name: "code_injection", CWEs: []string{"94", "95"}, Description: "Code Injection", Priority: 3},
}

// Build CWE to attack vector mapping
func buildCWEMap() map[string][]string {
	cweMap := make(map[string][]string)
	for _, mapping := range attackVectorMappings {
		for _, cwe := range mapping.CWEs {
			cweMap[cwe] = append(cweMap[cwe], mapping.Name)
		}
	}
	return cweMap
}

// Download and decompress gzipped feed
func downloadFeed(url string) (*NVDFeed, error) {
	fmt.Printf("  Downloading: %s\n", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Decompress gzip
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("gzip decompression failed: %w", err)
	}
	defer gzReader.Close()

	// Parse JSON
	var feed NVDFeed
	if err := json.NewDecoder(gzReader).Decode(&feed); err != nil {
		return nil, fmt.Errorf("JSON parsing failed: %w", err)
	}

	fmt.Printf("  Loaded %d vulnerabilities\n", len(feed.Vulnerabilities))

	return &feed, nil
}

// Extract CWE IDs from vulnerability
func extractCWEs(vuln Vulnerability) []string {
	var cwes []string
	for _, weakness := range vuln.CVE.Weaknesses {
		for _, desc := range weakness.Description {
			// Extract CWE number from "CWE-XXX" format
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweNum := strings.TrimPrefix(desc.Value, "CWE-")
				cwes = append(cwes, cweNum)
			}
		}
	}
	return cwes
}

// Map CWEs to attack vectors
func mapToAttackVectors(cwes []string, cweMap map[string][]string) []string {
	vectorSet := make(map[string]bool)
	for _, cwe := range cwes {
		if vectors, ok := cweMap[cwe]; ok {
			for _, v := range vectors {
				vectorSet[v] = true
			}
		}
	}

	var vectors []string
	for v := range vectorSet {
		vectors = append(vectors, v)
	}
	return vectors
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("Phase 1: NVD Feed Collection & Preparation for Naive Bayes")
	fmt.Println("=================================================================\n")

	// Configuration
	year := 2024
	outputFile := "training_data.json"

	// NVD JSON 2.0 feed URL
	feedURL := fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)

	// Try 2.0 format first
	feedURL = fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-%d.json.gz", year)

	// Build CWE mapping
	cweMap := buildCWEMap()
	fmt.Printf("Loaded %d attack vector categories\n", len(attackVectorMappings))
	fmt.Printf("Mapped %d unique CWE IDs\n\n", len(cweMap))

	fmt.Printf("Downloading NVD feed for year %d...\n", year)

	// Download feed
	feed, err := downloadFeed(feedURL)
	if err != nil {
		fmt.Printf("Error downloading feed: %v\n", err)
		fmt.Println("\nTrying alternative URL format...")

		// Try alternative URL (1.1 format)
		feedURL = fmt.Sprintf("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.gz", year)
		feed, err = downloadFeed(feedURL)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("\nProcessing vulnerabilities...")

	// Process vulnerabilities
	var trainingData []TrainingRecord
	totalProcessed := 0
	totalWithVectors := 0

	for i, vuln := range feed.Vulnerabilities {
		totalProcessed++

		if (i+1)%1000 == 0 {
			fmt.Printf("  Processed %d/%d CVEs (%d with attack vectors)\n", i+1, len(feed.Vulnerabilities), totalWithVectors)
		}

		// Extract English description
		var description string
		for _, desc := range vuln.CVE.Descriptions {
			if desc.Lang == "en" {
				description = desc.Value
				break
			}
		}

		if description == "" {
			continue
		}

		// Extract CWEs
		cwes := extractCWEs(vuln)
		if len(cwes) == 0 {
			continue
		}

		// Map to attack vectors
		vectors := mapToAttackVectors(cwes, cweMap)
		if len(vectors) == 0 {
			continue
		}

		totalWithVectors++

		// Create training record
		trainingData = append(trainingData, TrainingRecord{
			CVEID:         vuln.CVE.ID,
			Description:   description,
			CWEs:          cwes,
			AttackVectors: vectors,
			PublishedDate: vuln.CVE.Published,
		})
	}

	fmt.Printf("  Processed %d/%d CVEs (%d with attack vectors)\n\n", totalProcessed, len(feed.Vulnerabilities), totalWithVectors)

	// Save training data
	fmt.Println("=================================================================")
	fmt.Printf("Collection complete!\n")
	fmt.Printf("  Total CVEs processed: %d\n", totalProcessed)
	fmt.Printf("  CVEs with attack vectors: %d\n", totalWithVectors)
	fmt.Printf("  Saving to: %s\n\n", outputFile)

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(trainingData); err != nil {
		fmt.Printf("Error writing training data: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Training data saved successfully!\n")

	// Show attack vector distribution
	vectorCounts := make(map[string]int)
	for _, record := range trainingData {
		for _, vector := range record.AttackVectors {
			vectorCounts[vector]++
		}
	}

	fmt.Println("=================================================================")
	fmt.Println("Attack Vector Distribution:")
	fmt.Println("=================================================================")
	for _, mapping := range attackVectorMappings {
		if count, ok := vectorCounts[mapping.Name]; ok {
			fmt.Printf("  %-30s: %5d CVEs\n", mapping.Description, count)
		}
	}

	fmt.Println("\nPhase 1 complete! Ready for Phase 2 (Naive Bayes training)")
}
