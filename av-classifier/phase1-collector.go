package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// NVD API structures
type NVDResponse struct {
	ResultsPerPage  int             `json:"resultsPerPage"`
	StartIndex      int             `json:"startIndex"`
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CVE CVEItem `json:"cve"`
}

type CVEItem struct {
	ID           string        `json:"id"`
	Descriptions []Description `json:"descriptions"`
	Weaknesses   []Weakness    `json:"weaknesses,omitempty"`
	Published    string        `json:"published"`
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

// Training data structures
type TrainingRecord struct {
	CVEID         string   `json:"cve_id"`
	Description   string   `json:"description"`
	CWEs          []string `json:"cwes"`
	AttackVectors []string `json:"attack_vectors"`
	PublishedDate string   `json:"published_date"`
}

type AttackVectorMapping struct {
	Name        string   `json:"name"`
	CWEs        []string `json:"cwes"`
	Description string   `json:"description"`
	Priority    int      `json:"priority"` // 1=Critical, 2=High, 3=Medium
}

// Attack vector definitions
var attackVectorMappings = []AttackVectorMapping{
	// Tier 1 - Critical
	{Name: "xss", CWEs: []string{"79", "80", "83", "87"}, Description: "Cross-Site Scripting", Priority: 1},
	{Name: "sql_injection", CWEs: []string{"89"}, Description: "SQL Injection", Priority: 1},
	{Name: "rce", CWEs: []string{"94", "95", "96"}, Description: "Remote Code Execution", Priority: 1},
	{Name: "command_injection", CWEs: []string{"78", "77"}, Description: "OS Command Injection", Priority: 1},
	{Name: "path_traversal", CWEs: []string{"22", "23", "36", "73"}, Description: "Path Traversal", Priority: 1},
	{Name: "ssrf", CWEs: []string{"918"}, Description: "Server-Side Request Forgery", Priority: 1},
	{Name: "deserialization", CWEs: []string{"502"}, Description: "Deserialization Vulnerabilities", Priority: 1},
	{Name: "auth_bypass", CWEs: []string{"287", "288", "290", "306", "384"}, Description: "Authentication Bypass", Priority: 1},
	{Name: "authz_bypass", CWEs: []string{"862", "863", "284", "285"}, Description: "Authorization Bypass", Priority: 1},
	{Name: "file_upload", CWEs: []string{"434", "616"}, Description: "File Upload Vulnerabilities", Priority: 1},

	// Tier 2 - High Priority
	{Name: "csrf", CWEs: []string{"352"}, Description: "Cross-Site Request Forgery", Priority: 2},
	{Name: "xxe", CWEs: []string{"611", "827"}, Description: "XML External Entity", Priority: 2},
	{Name: "ldap_injection", CWEs: []string{"90"}, Description: "LDAP Injection", Priority: 2},
	{Name: "jndi_injection", CWEs: []string{"917"}, Description: "JNDI/Expression Language Injection", Priority: 2},
	{Name: "privilege_escalation", CWEs: []string{"269", "250", "266", "274"}, Description: "Privilege Escalation", Priority: 2},
	{Name: "buffer_overflow", CWEs: []string{"787", "119", "120", "121", "122", "125"}, Description: "Buffer Overflow", Priority: 2},
	{Name: "idor", CWEs: []string{"639"}, Description: "Insecure Direct Object Reference", Priority: 2},
	{Name: "http_desync", CWEs: []string{"444"}, Description: "HTTP Request Smuggling", Priority: 2},
	{Name: "hardcoded_credentials", CWEs: []string{"798", "259", "321"}, Description: "Hard-coded Credentials", Priority: 2},
	{Name: "info_disclosure", CWEs: []string{"200", "209", "215", "532", "538"}, Description: "Information Disclosure", Priority: 2},

	// Tier 3 - Medium Priority
	{Name: "dos", CWEs: []string{"400", "770", "399", "404"}, Description: "Denial of Service", Priority: 3},
	{Name: "nosql_injection", CWEs: []string{"943"}, Description: "NoSQL Injection", Priority: 3},
	{Name: "xpath_injection", CWEs: []string{"643"}, Description: "XPath Injection", Priority: 3},
	{Name: "open_redirect", CWEs: []string{"601"}, Description: "Open Redirect", Priority: 3},
	{Name: "session_fixation", CWEs: []string{"384"}, Description: "Session Fixation", Priority: 3},
	{Name: "crypto_failure", CWEs: []string{"327", "328", "329", "330", "326"}, Description: "Cryptographic Failures", Priority: 3},
	{Name: "integer_overflow", CWEs: []string{"190", "191"}, Description: "Integer Overflow", Priority: 3},
	{Name: "use_after_free", CWEs: []string{"416"}, Description: "Use After Free", Priority: 3},
	{Name: "null_pointer", CWEs: []string{"476"}, Description: "NULL Pointer Dereference", Priority: 3},
	{Name: "format_string", CWEs: []string{"134"}, Description: "Format String Vulnerability", Priority: 3},
	{Name: "email_injection", CWEs: []string{"93"}, Description: "Email Header Injection", Priority: 3},
	{Name: "race_condition", CWEs: []string{"362", "367"}, Description: "Race Condition", Priority: 3},
	{Name: "ssti", CWEs: []string{"94"}, Description: "Server-Side Template Injection", Priority: 3},
	{Name: "input_validation", CWEs: []string{"20"}, Description: "Improper Input Validation", Priority: 3},
}

// Create CWE to attack vector lookup map
func buildCWEMap() map[string][]string {
	cweMap := make(map[string][]string)
	for _, mapping := range attackVectorMappings {
		for _, cwe := range mapping.CWEs {
			cweMap[cwe] = append(cweMap[cwe], mapping.Name)
		}
	}
	return cweMap
}

// Fetch CVEs from NVD API
func fetchCVEs(startDate, endDate string, startIndex int, apiKey string) (*NVDResponse, error) {
	baseURL := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s&startIndex=%d&resultsPerPage=%d",
		baseURL, startDate, endDate, startIndex, 2000)

	client := &http.Client{Timeout: 60 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Add API key if provided
	if apiKey != "" {
		req.Header.Add("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var nvdResp NVDResponse
	if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
		return nil, err
	}

	return &nvdResp, nil
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

// Get English description
func getEnglishDescription(descriptions []Description) string {
	for _, desc := range descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("Phase 1: NVD Data Collection & Preparation for Naive Bayes")
	fmt.Println("=================================================================\n")

	// Configuration
	startDate := "2024-01-01T00:00:00.000"
	endDate := "2024-12-31T23:59:59.999"
	apiKey := os.Getenv("NVD_API_KEY") // Optional: set NVD_API_KEY environment variable
	outputFile := "training_data.json"

	if apiKey == "" {
		fmt.Println("⚠️  No API key found. Using rate limit: 5 requests per 30 seconds")
		fmt.Println("   Set NVD_API_KEY environment variable for 50 requests per 30 seconds\n")
	} else {
		fmt.Println("✓ API key found. Using rate limit: 50 requests per 30 seconds\n")
	}

	// Build CWE mapping
	cweMap := buildCWEMap()
	fmt.Printf("✓ Loaded %d attack vector categories\n", len(attackVectorMappings))
	fmt.Printf("✓ Mapped %d unique CWE IDs\n\n", len(cweMap))

	// Collect training data
	var trainingData []TrainingRecord
	startIndex := 0
	totalProcessed := 0
	totalWithVectors := 0

	// Rate limiting
	requestDelay := 6 * time.Second // 5 requests per 30 seconds
	if apiKey != "" {
		requestDelay = 600 * time.Millisecond // 50 requests per 30 seconds
	}

	fmt.Println("Starting data collection from NVD...")
	fmt.Printf("Date range: %s to %s\n\n", startDate, endDate)

	for {
		fmt.Printf("Fetching CVEs (startIndex=%d)...\n", startIndex)

		resp, err := fetchCVEs(startDate, endDate, startIndex, apiKey)
		if err != nil {
			fmt.Printf("Error fetching data: %v\n", err)
			break
		}

		fmt.Printf("  Retrieved %d CVEs (Total in NVD: %d)\n", len(resp.Vulnerabilities), resp.TotalResults)

		// Process each CVE
		for _, vuln := range resp.Vulnerabilities {
			totalProcessed++

			cwes := extractCWEs(vuln)
			if len(cwes) == 0 {
				continue // Skip CVEs without CWE mappings
			}

			vectors := mapToAttackVectors(cwes, cweMap)
			if len(vectors) == 0 {
				continue // Skip CVEs that don't map to our attack vectors
			}

			totalWithVectors++

			record := TrainingRecord{
				CVEID:         vuln.CVE.ID,
				Description:   getEnglishDescription(vuln.CVE.Descriptions),
				CWEs:          cwes,
				AttackVectors: vectors,
				PublishedDate: vuln.CVE.Published,
			}

			trainingData = append(trainingData, record)
		}

		fmt.Printf("  Processed: %d | With attack vectors: %d\n\n", totalProcessed, totalWithVectors)

		// Check if we've retrieved all results
		if startIndex+len(resp.Vulnerabilities) >= resp.TotalResults {
			break
		}

		startIndex += len(resp.Vulnerabilities)

		// Rate limiting delay
		time.Sleep(requestDelay)
	}

	// Save training data
	fmt.Println("=================================================================")
	fmt.Printf("Collection complete!\n")
	fmt.Printf("  Total CVEs processed: %d\n", totalProcessed)
	fmt.Printf("  CVEs with attack vectors: %d\n", totalWithVectors)
	fmt.Printf("  Saving to: %s\n\n", outputFile)

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf(" Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(trainingData); err != nil {
		fmt.Printf("Error writing JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ Training data saved successfully!")

	// Print statistics by attack vector
	vectorCounts := make(map[string]int)
	for _, record := range trainingData {
		for _, vector := range record.AttackVectors {
			vectorCounts[vector]++
		}
	}

	fmt.Println("\n=================================================================")
	fmt.Println("Attack Vector Distribution:")
	fmt.Println("=================================================================")
	for _, mapping := range attackVectorMappings {
		count := vectorCounts[mapping.Name]
		if count > 0 {
			fmt.Printf("  %-25s: %5d CVEs (Priority %d)\n", mapping.Description, count, mapping.Priority)
		}
	}

	fmt.Println("\n✓ Phase 1 complete! Ready for Phase 2 (Naive Bayes training)")
}
