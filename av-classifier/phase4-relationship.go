package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// NVD API structures
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// CWE Hierarchy structures
type CWEInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Abstraction   string   `json:"abstraction"`
	Parents       []string `json:"parents"`
	Children      []string `json:"children"`
	AttackVectors []string `json:"attack_vectors"`
}

type CWEHierarchy struct {
	CWEs                map[string]*CWEInfo `json:"cwes"`
	AttackVectorMapping map[string][]string `json:"attack_vector_mapping"` // Forward: AttackVector -> CWE IDs
	CWEToVectorMapping  map[string][]string // Reverse: CWE ID -> AttackVectors (built from data)
}

// Naive Bayes model structures (matching trainer output)
type AttackVectorModel struct {
	AttackVectors   []string                      `json:"attack_vectors"`
	VectorPriors    map[string]float64            `json:"vector_priors"`
	WordGivenVector map[string]map[string]float64 `json:"word_given_vector"`
	WordCounts      map[string]map[string]int     `json:"word_counts"`
	TotalWords      map[string]int                `json:"total_words"`
	Vocabulary      []string                      `json:"vocabulary"`
	TotalDocuments  int                           `json:"total_documents"`
	VectorDocCounts map[string]int                `json:"vector_doc_counts"`
}

// Classification result
type ClassificationResult struct {
	Vector      string  `json:"vector"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Confidence  string  `json:"confidence"`
	Source      string  `json:"source"` // "cwe_hierarchy", "naive_bayes", or "hybrid"
}

// CAPEC structures
type CAPECData struct {
	CAPECID         string   `json:"capec_id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	RelatedCWEs     []string `json:"related_cwes"`
	TypicalSeverity string   `json:"typical_severity"`
}

// CWE to CAPEC relationships
type RelationshipsDB struct {
	CWEToCapec    map[string][]string `json:"cwe_to_capec"`
	CapecToCWE    map[string][]string `json:"capec_to_cwe"`
	CapecToAttack map[string][]string `json:"capec_to_attack"`
	AttackToCapec map[string][]string `json:"attack_to_capec"`
}

// CAPEC ranking result
type CAPECResult struct {
	CAPECID     string  `json:"capec_id"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Confidence  string  `json:"confidence"`
}

// ScoredCWE represents a CWE with its relevance score
type ScoredCWE struct {
	ID    string
	Score float64
}

// PatternRule represents a pattern matching rule for attack vector detection
type PatternRule struct {
	Keywords    []string `json:"keywords"`
	Specificity float64  `json:"specificity"`
	Boost       float64  `json:"boost"`
	Support     int      `json:"support"`
}

// PatternTaxonomy contains pattern rules for all attack vectors
type PatternTaxonomy struct {
	Patterns map[string][]PatternRule `json:"patterns"` // attack_vector -> rules
}

// normalizeAttackVector converts "Path Traversal" to "path_traversal"
func normalizeAttackVector(av string) string {
	// Convert to lowercase and replace spaces with underscores
	return strings.ToLower(strings.ReplaceAll(av, " ", "_"))
}

var (
	cveID           string
	cveDesc         string
	cweIDs          string
	topN            int
	showDetails     bool
	capecDB         map[string]CAPECData
	relationshipsDB *RelationshipsDB
)

func main() {
	flag.StringVar(&cveID, "cve", "", "CVE ID (e.g., 'CVE-2021-44228')")
	flag.StringVar(&cveDesc, "description", "", "CVE description text (alternative to -cve)")
	flag.StringVar(&cveDesc, "d", "", "CVE description text (shorthand)")
	flag.StringVar(&cweIDs, "cwes", "", "Comma-separated CWE IDs (e.g., '94,502,20')")
	flag.StringVar(&cweIDs, "c", "", "Comma-separated CWE IDs (shorthand)")
	flag.IntVar(&topN, "top", 3, "Number of top results to return")
	flag.BoolVar(&showDetails, "verbose", false, "Show detailed classification process")
	flag.BoolVar(&showDetails, "v", false, "Show detailed classification process (shorthand)")
	flag.Parse()

	if cveID == "" && cveDesc == "" {
		fmt.Println("Usage:")
		fmt.Println("  phase3-classifier -cve CVE-2021-44228 [-top 3] [-verbose]")
		fmt.Println("  phase3-classifier -description \"CVE description\" [-cwes \"94,502\"] [-top 3] [-verbose]")
		fmt.Println("\nExamples:")
		fmt.Println("  phase3-classifier -cve CVE-2021-44228")
		fmt.Println("  phase3-classifier -d \"allows remote attackers to execute arbitrary code via JNDI\" -c \"502,917\"")
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println("Hybrid CWE + Naive Bayes Attack Vector Classifier")
	fmt.Println("=================================================================\n")

	// If CVE ID is provided, fetch from NVD
	var cwes []string
	if cveID != "" {
		if showDetails {
			fmt.Printf("Fetching CVE data from NVD API for %s...\n", cveID)
		}

		description, cweList, err := fetchCVEFromNVD(cveID)
		if err != nil {
			fmt.Printf("Error fetching CVE data: %v\n", err)
			os.Exit(1)
		}

		cveDesc = description
		cwes = cweList

		fmt.Printf("CVE ID: %s\n", cveID)
		fmt.Printf("Description: %s\n", cveDesc)
		if len(cwes) > 0 {
			fmt.Printf("CWE IDs: %s\n\n", strings.Join(cwes, ", "))
		} else {
			fmt.Println("CWE IDs: (none found)\n")
		}
	} else {
		// Parse CWE IDs from command line
		if cweIDs != "" {
			cwes = strings.Split(strings.ReplaceAll(cweIDs, " ", ""), ",")
			// Clean CWE IDs (remove "CWE-" prefix if present)
			for i, cwe := range cwes {
				cwes[i] = strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
			}
		}
	}

	// Load CWE hierarchy
	if showDetails {
		fmt.Println("Loading CWE hierarchy...")
	}
	hierarchy, err := loadCWEHierarchy("resources/cwe_hierarchy.json")
	if err != nil {
		fmt.Printf("Error loading CWE hierarchy: %v\n", err)
		fmt.Println("Run 'cwe-builder' first to generate resources/cwe_hierarchy.json")
		os.Exit(1)
	}
	if showDetails {
		fmt.Printf("Loaded %d CWEs\n\n", len(hierarchy.CWEs))
	}

	// Load Naive Bayes model
	if showDetails {
		fmt.Println("Loading Naive Bayes model...")
	}
	model, err := loadNaiveBayesModel("resources/naive_bayes_model.json")
	if err != nil {
		fmt.Printf("Error loading Naive Bayes model: %v\n", err)
		fmt.Println("Run 'trainer' first to generate resources/naive_bayes_model.json")
		os.Exit(1)
	}
	if showDetails {
		fmt.Printf("Loaded model with %d attack vectors\n", len(model.VectorPriors))
	}

	// Load pattern taxonomy
	var patternTaxonomy *PatternTaxonomy
	if _, err := os.Stat("resources/pattern_taxonomy.json"); err == nil {
		patternTaxonomy, err = loadPatternTaxonomy("resources/pattern_taxonomy.json")
		if err != nil && showDetails {
			fmt.Printf("Warning: Failed to load pattern taxonomy: %v\n", err)
		} else if showDetails {
			fmt.Printf("Pattern taxonomy loaded: %d attack vectors\n", len(patternTaxonomy.Patterns))
		}
	}

	// Load CAPEC and Relationships DBs
	if _, err := os.Stat("resources/capec_db.json"); err == nil {
		err = loadCAPECDB("resources/capec_db.json")
		if err != nil {
			fmt.Printf("Error loading CAPEC DB: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Warning: resources/capec_db.json not found. CAPEC mapping will be skipped.")
	}

	if _, err := os.Stat("resources/relationships_db.json"); err == nil {
		err = loadRelationshipsDB("resources/relationships_db.json")
		if err != nil {
			fmt.Printf("Error loading Relationships DB: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Warning: resources/relationships_db.json not found. CAPEC mapping will be skipped.")
	}

	if showDetails {
		fmt.Println()
	}

	// Classify
	results := classifyHybrid(cveDesc, cwes, hierarchy, model, patternTaxonomy, topN, showDetails)

	// Display results
	fmt.Println("\n=================================================================")
	fmt.Println("Classification Results:")
	fmt.Println("=================================================================\n")

	for i, result := range results {
		fmt.Printf("%d. %s\n", i+1, result.Name)
		fmt.Printf("   Probability: %.2f%% (%s confidence)\n", result.Probability*100, result.Confidence)
		fmt.Printf("   Source: %s\n", result.Source)
		if i < len(results)-1 {
			fmt.Println()
		}
	}

	// CAPEC Ranking
	// Get CWEs from the top classified attack vector (not from CVE's CWE list)
	var attackVectorCWEs []string
	if len(results) > 0 {
		// Get the top classified attack vector
		topVector := results[0].Vector

		if showDetails {
			fmt.Printf("\n[DEBUG] Top classified vector: '%s'\n", topVector)

			// Debug: Print the actual mappings for the relevant vectors
			if ptCWEs, exists := hierarchy.AttackVectorMapping["Path Traversal"]; exists {
				fmt.Printf("[DEBUG] AttackVectorMapping['Path Traversal']: %v\n", ptCWEs)
			}
			if ssrfCWEs, exists := hierarchy.AttackVectorMapping["Server-Side Request Forgery"]; exists {
				fmt.Printf("[DEBUG] AttackVectorMapping['Server-Side Request Forgery']: %v\n", ssrfCWEs)
			}

			fmt.Printf("[DEBUG] Available attack vector mappings: ")
			count := 0
			for avKey := range hierarchy.AttackVectorMapping {
				if count < 5 {
					fmt.Printf("%s ", avKey)
					count++
				}
			}
			fmt.Println()
		}

		// Look up CWEs associated with this attack vector
		// Normalize the vector name to match data format (e.g., "Path Traversal" -> "path_traversal")
		normalizedVector := normalizeAttackVector(topVector)

		if showDetails {
			fmt.Printf("\n[DEBUG] Looking up CWEs for classified vector: '%s'\n", topVector)
			fmt.Printf("[DEBUG] Normalized to: '%s'\n", normalizedVector)
			fmt.Printf("[DEBUG] Available mappings in hierarchy: %d\n", len(hierarchy.AttackVectorMapping))
			// Show all available attack vector keys
			fmt.Printf("[DEBUG] Available attack vector keys (first 10): ")
			count := 0
			for av := range hierarchy.AttackVectorMapping {
				if count < 10 {
					fmt.Printf("'%s' ", av)
					count++
				}
			}
			fmt.Println()
		}

		if vectorCWEs, exists := hierarchy.AttackVectorMapping[normalizedVector]; exists {
			// Fallback 1: Use data-driven mapping, selecting the first (most relevant) CWE
			if len(vectorCWEs) > 0 {
				attackVectorCWEs = []string{vectorCWEs[0]}
				if showDetails {
					fmt.Printf("[DEBUG] Data-driven mapping used: '%s' (normalized: '%s') maps to CWEs: %v\n", topVector, normalizedVector, vectorCWEs)
					fmt.Printf("[DEBUG] Selecting only the first CWE: %s\n", attackVectorCWEs[0])
				}
			} else {
				if showDetails {
					fmt.Printf("[DEBUG] Attack vector '%s' maps to an empty CWE list\n", topVector)
				}
			}
		} else {
			if showDetails {
				fmt.Printf("[DEBUG] No CWE mapping found for attack vector '%s'\n", topVector)
				fmt.Printf("[DEBUG] Falling back to top-ranked CWE from CVE data\n")
			}
			// Fallback: use top-ranked CWE from CVE's CWE list (deduplicated)
			topCWEs := rankCWEsByRelevance(cwes, cveDesc, hierarchy, 1)
			if len(topCWEs) > 0 {
				attackVectorCWEs = []string{topCWEs[0]}
				if showDetails {
					fmt.Printf("[DEBUG] Using top CWE: %s\n", topCWEs[0])
				}
			}
		}
	}

	if len(attackVectorCWEs) > 0 {
		fmt.Println("\n=================================================================")
		fmt.Println("CWE-to-CAPEC Relationship Mapping")
		fmt.Println("=================================================================\n")

		for _, cweID := range attackVectorCWEs {
			// Use two-layer filtering and ranking (top 5 CAPECs)
			// Get classified vector and pattern taxonomy
			classifiedVector := ""
			if len(results) > 0 {
				classifiedVector = results[0].Vector
			}

			var patternMap map[string][]PatternRule
			if patternTaxonomy != nil {
				patternMap = patternTaxonomy.Patterns
			} else {
				patternMap = make(map[string][]PatternRule)
			}

			capecResults := getCAPECsForCWEWithFiltering(cweID, cveDesc, classifiedVector, patternMap, 5)

			cweInfo, exists := hierarchy.CWEs[cweID]
			cweName := "Unknown CWE"
			if exists && cweInfo != nil {
				cweName = cweInfo.Name
			}

			fmt.Printf("CWE-%s: %s\n", cweID, cweName)
			if len(capecResults) == 0 {
				fmt.Println("  No direct CAPEC relationships found.")
			} else {
				for i, capec := range capecResults {
					fmt.Printf("  %d. CAPEC-%s: %s (Relevance: %.0f%%, Source: %s)\n",
						i+1, capec.CAPECID, capec.Name, capec.Probability*100, capec.Confidence)
				}
			}
			fmt.Println()
		}
	}
}

// Layer 1: Filter out strongly unrelated CAPECs
func filterUnrelatedCAPECs(capecs []CAPECData, cveDescription string) []CAPECData {
	descLower := strings.ToLower(cveDescription)

	// Define protocol/technology-specific keywords that indicate strong mismatch
	protocolFilters := map[string][]string{
		"ldap":      {"ldap", "directory", "active directory", "ad"},
		"smtp":      {"smtp", "email", "mail server", "sendmail"},
		"imap":      {"imap", "email", "mail"},
		"sql":       {"sql", "database", "mysql", "postgresql", "oracle", "mssql"},
		"xml":       {"xml", "soap", "wsdl"},
		"xpath":     {"xpath", "xml"},
		"dns":       {"dns", "domain name"},
		"ntp":       {"ntp", "time server"},
		"snmp":      {"snmp", "network management"},
		"bluetooth": {"bluetooth", "ble"},
		"nfc":       {"nfc", "near field"},
		"usb":       {"usb", "universal serial bus"},
	}

	var filtered []CAPECData

	for _, capec := range capecs {
		capecNameLower := strings.ToLower(capec.Name)
		capecDescLower := strings.ToLower(capec.Description)

		// Check if CAPEC is protocol-specific
		isProtocolSpecific := false
		mismatchedProtocol := ""

		for protocol, keywords := range protocolFilters {
			// Check if CAPEC name/description mentions this protocol
			capecMentionsProtocol := false
			for _, keyword := range []string{protocol} {
				if strings.Contains(capecNameLower, keyword) || strings.Contains(capecDescLower, keyword) {
					capecMentionsProtocol = true
					break
				}
			}

			if capecMentionsProtocol {
				isProtocolSpecific = true

				// Check if CVE description mentions any related keywords
				cveMentionsProtocol := false
				for _, keyword := range keywords {
					if strings.Contains(descLower, keyword) {
						cveMentionsProtocol = true
						break
					}
				}

				if !cveMentionsProtocol {
					mismatchedProtocol = protocol
					break
				}
			}
		}

		// If protocol-specific CAPEC doesn't match CVE context, filter it out
		if isProtocolSpecific && mismatchedProtocol != "" {
			if showDetails {
				fmt.Printf("  [FILTER] Removing CAPEC-%s (%s) - %s-specific, not in CVE\n",
					capec.CAPECID, capec.Name, mismatchedProtocol)
			}
			continue
		}

		filtered = append(filtered, capec)
	}

	return filtered
}

// Layer 2: Rank CAPECs by relevance using pattern taxonomy
func rankCAPECsByRelevance(capecs []CAPECData, cveDescription string, classifiedVector string, patternTaxonomy map[string][]PatternRule) []CAPECResult {
	descLower := strings.ToLower(cveDescription)

	var results []CAPECResult

	for _, capec := range capecs {
		capecNameLower := strings.ToLower(capec.Name)
		capecDescLower := strings.ToLower(capec.Description)
		capecText := capecNameLower + " " + capecDescLower

		// Start with base score
		relevanceScore := 30.0 // Base score for all CAPECs that passed filtering

		// 1. Check if CAPEC name directly matches classified attack vector
		if strings.Contains(capecNameLower, strings.ToLower(classifiedVector)) {
			relevanceScore += 40.0
			if showDetails {
				fmt.Printf("    [RANK] CAPEC-%s: +40 (name matches vector '%s')\n", capec.CAPECID, classifiedVector)
			}
		}

		// 2. Use pattern taxonomy to score CAPEC relevance
		if patterns, exists := patternTaxonomy[classifiedVector]; exists {
			for _, pattern := range patterns {
				matchCount := 0
				for _, keyword := range pattern.Keywords {
					if strings.Contains(capecText, strings.ToLower(keyword)) {
						matchCount++
					}
				}

				// If CAPEC matches pattern keywords, add score based on pattern boost
				if matchCount > 0 {
					patternScore := (float64(matchCount) / float64(len(pattern.Keywords))) * pattern.Boost * 0.5
					relevanceScore += patternScore
					if showDetails && patternScore > 5 {
						fmt.Printf("    [RANK] CAPEC-%s: +%.1f (pattern match: %d/%d keywords)\n",
							capec.CAPECID, patternScore, matchCount, len(pattern.Keywords))
					}
				}
			}
		}

		// 3. Check for important CVE keywords in CAPEC
		importantKeywords := []string{"command", "injection", "execute", "arbitrary", "code", "exploit", "vulnerability"}
		keywordMatches := 0
		for _, keyword := range importantKeywords {
			if strings.Contains(descLower, keyword) && strings.Contains(capecText, keyword) {
				keywordMatches++
			}
		}
		if keywordMatches > 0 {
			keywordScore := float64(keywordMatches) * 3.0
			relevanceScore += keywordScore
			if showDetails {
				fmt.Printf("    [RANK] CAPEC-%s: +%.1f (keyword matches: %d)\n", capec.CAPECID, keywordScore, keywordMatches)
			}
		}

		// 4. Bonus for generic attack patterns (always relevant)
		genericPatterns := []string{"injection", "command", "code execution", "exploit"}
		for _, pattern := range genericPatterns {
			if strings.Contains(capecNameLower, pattern) {
				relevanceScore += 10.0
				if showDetails {
					fmt.Printf("    [RANK] CAPEC-%s: +10 (generic pattern: %s)\n", capec.CAPECID, pattern)
				}
				break
			}
		}

		// 5. Severity alignment bonus
		if capec.TypicalSeverity == "High" || capec.TypicalSeverity == "Very High" {
			if strings.Contains(descLower, "critical") || strings.Contains(descLower, "execute") || strings.Contains(descLower, "arbitrary") {
				relevanceScore += 5.0
			}
		}

		// Cap at 100%
		if relevanceScore > 100.0 {
			relevanceScore = 100.0
		}

		// Determine confidence level
		confidence := "low"
		if relevanceScore >= 70.0 {
			confidence = "high"
		} else if relevanceScore >= 50.0 {
			confidence = "medium"
		}

		if showDetails {
			fmt.Printf("    [RANK] CAPEC-%s: Final score = %.1f%% (%s confidence)\n", capec.CAPECID, relevanceScore, confidence)
		}

		results = append(results, CAPECResult{
			CAPECID:     capec.CAPECID,
			Name:        capec.Name,
			Probability: relevanceScore / 100.0,
			Confidence:  confidence,
		})
	}

	// Sort by relevance score (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results
}

// Get CAPECs for a CWE with two-layer filtering and ranking
func getCAPECsForCWEWithFiltering(cweID string, cveDescription string, classifiedVector string, patternTaxonomy map[string][]PatternRule, topN int) []CAPECResult {
	if relationshipsDB == nil || capecDB == nil {
		if showDetails {
			fmt.Printf("  [DEBUG] getCAPECsForCWEWithFiltering(%s): relationshipsDB or capecDB is nil\n", cweID)
		}
		return nil
	}

	// Try to find CAPECs using the CWE ID as-is first
	capecIDs, exists := relationshipsDB.CWEToCapec[cweID]
	if showDetails {
		fmt.Printf("  [DEBUG] Lookup '%s': found=%v\n", cweID, exists)
	}

	// If not found, try with "CWE-" prefix
	if !exists {
		capecIDs, exists = relationshipsDB.CWEToCapec["CWE-"+cweID]
		if showDetails {
			fmt.Printf("  [DEBUG] Lookup 'CWE-%s': found=%v\n", cweID, exists)
		}
	}

	// If still not found, try without "CWE-" prefix (in case it was provided with prefix)
	if !exists && strings.HasPrefix(cweID, "CWE-") {
		stripped := strings.TrimPrefix(cweID, "CWE-")
		capecIDs, exists = relationshipsDB.CWEToCapec[stripped]
		if showDetails {
			fmt.Printf("  [DEBUG] Lookup '%s': found=%v\n", stripped, exists)
		}
	}

	if !exists {
		if showDetails {
			fmt.Printf("  [DEBUG] No CAPEC mappings found for CWE %s in any format\n", cweID)
		}
		return nil
	}

	if showDetails {
		fmt.Printf("  [DEBUG] Found %d CAPEC IDs for CWE %s: %v\n", len(capecIDs), cweID, capecIDs)
	}

	// Collect all CAPEC data objects
	var capecDataList []CAPECData
	for _, capecID := range capecIDs {
		if capec, exists := capecDB[capecID]; exists {
			capecDataList = append(capecDataList, capec)
		}
	}

	if len(capecDataList) == 0 {
		return nil
	}

	if showDetails {
		fmt.Printf("  [LAYER 1] Starting with %d CAPECs before filtering\n", len(capecDataList))
	}

	// Layer 1: Filter out strongly unrelated CAPECs
	filteredCAPECs := filterUnrelatedCAPECs(capecDataList, cveDescription)

	if showDetails {
		fmt.Printf("  [LAYER 1] %d CAPECs remaining after filtering\n", len(filteredCAPECs))
	}

	if len(filteredCAPECs) == 0 {
		if showDetails {
			fmt.Printf("  [WARNING] All CAPECs filtered out, using original list\n")
		}
		filteredCAPECs = capecDataList
	}

	// Layer 2: Rank by relevance
	if showDetails {
		fmt.Printf("  [LAYER 2] Ranking %d CAPECs by relevance\n", len(filteredCAPECs))
	}

	rankedResults := rankCAPECsByRelevance(filteredCAPECs, cveDescription, classifiedVector, patternTaxonomy)

	// Take top N
	if len(rankedResults) > topN {
		rankedResults = rankedResults[:topN]
	}

	return rankedResults
}

func getCAPECsForCWE(cweID string) []CAPECResult {
	if relationshipsDB == nil || capecDB == nil {
		if showDetails {
			fmt.Printf("  [DEBUG] getCAPECsForCWE(%s): relationshipsDB or capecDB is nil\n", cweID)
		}
		return nil
	}

	// Try to find CAPECs using the CWE ID as-is first
	capecIDs, exists := relationshipsDB.CWEToCapec[cweID]
	if showDetails {
		fmt.Printf("  [DEBUG] Lookup '%s': found=%v\n", cweID, exists)
	}

	// If not found, try with "CWE-" prefix
	if !exists {
		capecIDs, exists = relationshipsDB.CWEToCapec["CWE-"+cweID]
		if showDetails {
			fmt.Printf("  [DEBUG] Lookup 'CWE-%s': found=%v\n", cweID, exists)
		}
	}

	// If still not found, try without "CWE-" prefix (in case it was provided with prefix)
	if !exists && strings.HasPrefix(cweID, "CWE-") {
		stripped := strings.TrimPrefix(cweID, "CWE-")
		capecIDs, exists = relationshipsDB.CWEToCapec[stripped]
		if showDetails {
			fmt.Printf("  [DEBUG] Lookup '%s': found=%v\n", stripped, exists)
		}
	}

	if !exists {
		if showDetails {
			fmt.Printf("  [DEBUG] No CAPEC mappings found for CWE %s in any format\n", cweID)
		}
		return nil
	}

	if showDetails {
		fmt.Printf("  [DEBUG] Found %d CAPEC IDs for CWE %s: %v\n", len(capecIDs), cweID, capecIDs)
		fmt.Printf("  [DEBUG] capecDB has %d entries\n", len(capecDB))
	}

	// Collect all CAPEC data objects
	var capecDataList []CAPECData
	for _, capecID := range capecIDs {
		if capec, exists := capecDB[capecID]; exists {
			capecDataList = append(capecDataList, capec)
		}
	}

	if len(capecDataList) == 0 {
		return nil
	}

	if showDetails {
		fmt.Printf("  [DEBUG] Collected %d CAPECs for filtering\n", len(capecDataList))
	}

	// This function needs CVE description, so it will be called from the main function
	// For now, return all CAPECs with simple scoring
	var results []CAPECResult
	for _, capec := range capecDataList {
		results = append(results, CAPECResult{
			CAPECID:     capec.CAPECID,
			Name:        capec.Name,
			Probability: 1.0,
			Confidence:  "Direct CWE Mapping",
		})
	}

	// Sort by CAPEC ID for stable output
	sort.Slice(results, func(i, j int) bool {
		return results[i].CAPECID < results[j].CAPECID
	})

	return results
}

func loadRelationshipsDB(path string) error {
	fmt.Print("Loading relationships DB...")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Try snake_case format first (feeds-updater.go output)
	type RelationshipsSnakeCase struct {
		CWEToCapec    map[string][]string `json:"cwe_to_capec"`
		CapecToCWE    map[string][]string `json:"capec_to_cwe"`
		CapecToAttack map[string][]string `json:"capec_to_attack"`
		AttackToCapec map[string][]string `json:"attack_to_capec"`
	}

	var snakeDB RelationshipsSnakeCase
	err = json.Unmarshal(data, &snakeDB)
	if err == nil && len(snakeDB.CWEToCapec) > 0 {
		// Successfully loaded snake_case format
		relationshipsDB = &RelationshipsDB{
			CWEToCapec:    snakeDB.CWEToCapec,
			CapecToCWE:    snakeDB.CapecToCWE,
			CapecToAttack: snakeDB.CapecToAttack,
			AttackToCapec: snakeDB.AttackToCapec,
		}
		fmt.Printf(" ✓ (snake_case format, %d CWE mappings)\n", len(relationshipsDB.CWEToCapec))
		if showDetails {
			fmt.Printf("  Sample CWE IDs in database: ")
			count := 0
			for cweID := range relationshipsDB.CWEToCapec {
				if count < 5 {
					fmt.Printf("%s ", cweID)
					count++
				}
			}
			fmt.Println()
		}
		return nil
	}

	// Try PascalCase format (legacy format)
	type RelationshipsPascalCase struct {
		CWEToCapec    map[string][]string `json:"CWEToCapec"`
		CapecToCWE    map[string][]string `json:"CapecToCWE"`
		CapecToAttack map[string][]string `json:"CapecToAttack"`
		AttackToCapec map[string][]string `json:"AttackToCapec"`
	}

	var pascalDB RelationshipsPascalCase
	err = json.Unmarshal(data, &pascalDB)
	if err == nil && len(pascalDB.CWEToCapec) > 0 {
		// Successfully loaded PascalCase format
		relationshipsDB = &RelationshipsDB{
			CWEToCapec:    pascalDB.CWEToCapec,
			CapecToCWE:    pascalDB.CapecToCWE,
			CapecToAttack: pascalDB.CapecToAttack,
			AttackToCapec: pascalDB.AttackToCapec,
		}
		fmt.Printf(" ✓ (PascalCase format, %d CWE mappings)\n", len(relationshipsDB.CWEToCapec))
		if showDetails {
			fmt.Printf("  Sample CWE IDs in database: ")
			count := 0
			for cweID := range relationshipsDB.CWEToCapec {
				if count < 5 {
					fmt.Printf("%s ", cweID)
					count++
				}
			}
			fmt.Println()
		}
		return nil
	}

	return fmt.Errorf("failed to parse relationships DB in either snake_case or PascalCase format")
}

func loadCAPECDB(path string) error {
	fmt.Print("Loading CAPEC DB...")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	// Try to unmarshal as array first
	var capecs []CAPECData
	err = json.Unmarshal(data, &capecs)
	if err == nil && len(capecs) > 0 {
		// Successfully loaded array format
		capecDB = make(map[string]CAPECData)
		for _, capec := range capecs {
			capecDB[capec.CAPECID] = capec
		}
		fmt.Printf(" ✓ (%d CAPECs loaded, array format)\n", len(capecDB))
		if showDetails {
			fmt.Printf("  Sample CAPEC IDs in database: ")
			count := 0
			for capecID := range capecDB {
				if count < 5 {
					fmt.Printf("%s ", capecID)
					count++
				}
			}
			fmt.Println()
		}
		return nil
	}

	// Try to unmarshal as object with "capecs" key
	var capecObj struct {
		CAPECs []CAPECData `json:"capecs"`
	}
	err = json.Unmarshal(data, &capecObj)
	if err == nil && len(capecObj.CAPECs) > 0 {
		// Successfully loaded object with array format
		capecDB = make(map[string]CAPECData)
		for _, capec := range capecObj.CAPECs {
			capecDB[capec.CAPECID] = capec
		}
		fmt.Printf(" ✓ (%d CAPECs loaded, object+array format)\n", len(capecDB))
		if showDetails {
			fmt.Printf("  Sample CAPEC IDs in database: ")
			count := 0
			for capecID := range capecDB {
				if count < 5 {
					fmt.Printf("%s ", capecID)
					count++
				}
			}
			fmt.Println()
		}
		return nil
	}

	// Try to unmarshal as map with CAPEC IDs as keys (feeds-updater.go format)
	type CAPECEntry struct {
		Name               string   `json:"name"`
		Description        string   `json:"description"`
		RelatedWeaknesses  []string `json:"relatedWeaknesses"`
		TypicalSeverity    string   `json:"typicalSeverity"`
		LikelihoodOfAttack string   `json:"likelihoodOfAttack"`
	}

	var capecMap map[string]CAPECEntry
	err = json.Unmarshal(data, &capecMap)
	if err == nil && len(capecMap) > 0 {
		// Successfully loaded map format (CAPEC IDs as keys)
		capecDB = make(map[string]CAPECData)
		for capecID, entry := range capecMap {
			capecDB[capecID] = CAPECData{
				CAPECID:         capecID,
				Name:            entry.Name,
				Description:     entry.Description,
				RelatedCWEs:     entry.RelatedWeaknesses,
				TypicalSeverity: entry.TypicalSeverity,
			}
		}
		fmt.Printf(" ✓ (%d CAPECs loaded, map format)\n", len(capecDB))
		if showDetails {
			fmt.Printf("  Sample CAPEC IDs in database: ")
			count := 0
			for capecID := range capecDB {
				if count < 5 {
					fmt.Printf("%s ", capecID)
					count++
				}
			}
			fmt.Println()
		}
		return nil
	}

	return fmt.Errorf("failed to parse CAPEC DB (tried array, object+array, and map formats)")
}

func fetchCVEFromNVD(cveID string) (string, []string, error) {
	// Normalize CVE ID
	cveID = strings.ToUpper(cveID)
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	// Build NVD API URL
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Make request
	resp, err := client.Get(url)
	if err != nil {
		return "", nil, fmt.Errorf("HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read response: %v", err)
	}

	// Parse JSON
	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return "", nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return "", nil, fmt.Errorf("CVE not found in NVD")
	}

	cve := nvdResp.Vulnerabilities[0].CVE

	// Extract description (prefer English)
	description := ""
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}
	if description == "" && len(cve.Descriptions) > 0 {
		description = cve.Descriptions[0].Value
	}

	// Extract CWE IDs
	var cweList []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			// CWE IDs are in format "CWE-123"
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweID := strings.TrimPrefix(desc.Value, "CWE-")
				cweList = append(cweList, cweID)
			}
		}
	}

	return description, cweList, nil
}

// rankCWEsByRelevance scores and ranks CWEs based on their relevance to the CVE description
// Returns the top N CWEs sorted by relevance score (descending)
func rankCWEsByRelevance(cweIDs []string, description string, hierarchy *CWEHierarchy, topN int) []string {
	if len(cweIDs) == 0 {
		return []string{}
	}

	// Score each CWE
	scoredCWEs := []ScoredCWE{}
	descLower := strings.ToLower(description)

	for _, cweID := range cweIDs {
		score := scoreCWERelevance(cweID, descLower, hierarchy)
		scoredCWEs = append(scoredCWEs, ScoredCWE{
			ID:    cweID,
			Score: score,
		})
	}

	// Sort by score (descending)
	sort.Slice(scoredCWEs, func(i, j int) bool {
		return scoredCWEs[i].Score > scoredCWEs[j].Score
	})

	// Take top N
	resultCount := topN
	if len(scoredCWEs) < topN {
		resultCount = len(scoredCWEs)
	}

	result := make([]string, resultCount)
	for i := 0; i < resultCount; i++ {
		result[i] = scoredCWEs[i].ID
	}

	return result
}

// scoreCWERelevance calculates a relevance score for a CWE based on the CVE description
func scoreCWERelevance(cweID string, descLower string, hierarchy *CWEHierarchy) float64 {
	cwe, exists := hierarchy.CWEs[cweID]
	if !exists {
		return 0.0
	}

	score := 0.0
	cweName := strings.ToLower(cwe.Name)

	// 1. Base keyword matching
	keywords := extractCWEKeywords(cweName)
	for _, keyword := range keywords {
		if len(keyword) < 3 {
			continue
		}
		if strings.Contains(descLower, keyword) {
			score += 10.0
		}
	}

	// 2. Priority boost for critical CWEs
	priorityCWEs := map[string]float64{
		"502": 50.0, "78": 45.0, "79": 40.0, "89": 45.0, "94": 45.0,
		"77": 40.0, "22": 35.0, "434": 35.0, "611": 35.0, "918": 40.0,
		"917": 40.0, "119": 30.0, "787": 30.0, "416": 30.0, "352": 25.0,
		"306": 25.0, "862": 25.0,
	}
	if boost, exists := priorityCWEs[cweID]; exists {
		score += boost
	}

	// 3. Pattern-based boosting
	if containsAnyPattern(descLower, []string{"deserializ", "jndi", "ldap", "lookup", "unmarsh", "pickle"}) {
		if cweID == "502" {
			score += 100.0
		}
		if cweID == "917" {
			score += 50.0
		}
	}

	if containsAnyPattern(descLower, []string{"inject", "execut", "eval", "code execution"}) {
		if containsAnyPattern(descLower, []string{"code", "arbitrary"}) && cweID == "94" {
			score += 80.0
		}
		if containsAnyPattern(descLower, []string{"command", "shell", "os"}) && (cweID == "78" || cweID == "77") {
			score += 80.0
		}
	}

	if containsAnyPattern(descLower, []string{"sql", "database", "query"}) && cweID == "89" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"xss", "cross-site scripting", "script injection"}) && cweID == "79" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"path traversal", "directory traversal", "../", "..\\", "path manipulation"}) && cweID == "22" {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"ssrf", "server-side request", "internal request", "url fetch"}) && cweID == "918" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"xxe", "xml external entity", "xml injection"}) && cweID == "611" {
		score += 100.0
	}

	if containsAnyPattern(descLower, []string{"buffer overflow", "buffer overrun", "heap overflow", "stack overflow"}) && (cweID == "119" || cweID == "787") {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"authentication bypass", "auth bypass", "without authentication"}) && cweID == "306" {
		score += 80.0
	}

	if containsAnyPattern(descLower, []string{"authorization bypass", "privilege escalation", "unauthorized access"}) && (cweID == "862" || cweID == "269") {
		score += 80.0
	}

	// 4. Penalty for generic CWEs
	genericCWEs := map[string]float64{
		"20": -20.0, "400": -15.0, "703": -20.0, "707": -20.0,
	}
	if penalty, exists := genericCWEs[cweID]; exists {
		score += penalty
	}

	// 5. Boost for CWEs with attack vector mappings
	if len(cwe.AttackVectors) > 0 {
		score += float64(len(cwe.AttackVectors)) * 5.0
	}

	if score < 0 {
		score = 0
	}

	return score
}

// extractCWEKeywords extracts meaningful keywords from CWE name
func extractCWEKeywords(text string) []string {
	stopWords := map[string]bool{
		"improper": true, "insufficient": true, "incorrect": true,
		"missing": true, "lack": true, "inadequate": true,
		"the": true, "of": true, "in": true, "to": true, "for": true,
		"and": true, "or": true, "a": true, "an": true,
	}

	re := regexp.MustCompile(`[^a-z0-9]+`)
	words := re.Split(text, -1)

	keywords := []string{}
	for _, word := range words {
		if len(word) >= 3 && !stopWords[word] {
			keywords = append(keywords, word)
		}
	}

	return keywords
}

// containsAnyPattern checks if the text contains any of the patterns
func containsAnyPattern(text string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(text, pattern) {
			return true
		}
	}
	return false
}

func classifyHybrid(description string, cweIDs []string, hierarchy *CWEHierarchy, model *AttackVectorModel, patternTaxonomy *PatternTaxonomy, topN int, verbose bool) []ClassificationResult {
	// Step 1: Rank CWEs by relevance and select top 2
	rankedCWEs := rankCWEsByRelevance(cweIDs, description, hierarchy, 2)

	if verbose && len(cweIDs) > 0 {
		fmt.Printf("\nCWE Ranking (top 2 of %d):\n", len(cweIDs))
		for i, cweID := range rankedCWEs {
			if cwe, exists := hierarchy.CWEs[cweID]; exists {
				score := scoreCWERelevance(cweID, strings.ToLower(description), hierarchy)
				fmt.Printf("  %d. CWE-%s: %s (score: %.1f)\n", i+1, cweID, cwe.Name, score)
			}
		}
	}

	// Step 2: Get candidate attack vectors from top 2 CWEs only
	candidates := getCandidatesFromCWEs(rankedCWEs, hierarchy, verbose)

	// Step 3: Apply Naive Bayes
	if len(candidates) > 0 {
		if verbose {
			fmt.Printf("\nApplying Naive Bayes to %d candidate attack vectors...\n", len(candidates))
		}
		// Classify only among candidates
		results := classifyNaiveBayes(description, model, candidates, patternTaxonomy, verbose)

		// Filter out 0.00% probability results
		filteredResults := []ClassificationResult{}
		for _, result := range results {
			if result.Probability >= 0.0001 { // Filter out essentially zero probabilities
				filteredResults = append(filteredResults, result)
			}
		}
		results = filteredResults

		// Take top N
		if len(results) > topN {
			results = results[:topN]
		}

		// Mark as hybrid
		for i := range results {
			results[i].Source = "hybrid (CWE + Naive Bayes)"
		}

		return results
	} else {
		if verbose {
			fmt.Println("\nNo CWE IDs provided or no mappings found. Falling back to full Naive Bayes...")
		}
		// Fallback: classify among all vectors
		results := classifyNaiveBayes(description, model, nil, patternTaxonomy, verbose)

		// Filter out 0.00% probability results
		filteredResults := []ClassificationResult{}
		for _, result := range results {
			if result.Probability >= 0.0001 { // Filter out essentially zero probabilities
				filteredResults = append(filteredResults, result)
			}
		}
		results = filteredResults

		// Take top N
		if len(results) > topN {
			results = results[:topN]
		}

		// Mark as naive bayes only
		for i := range results {
			results[i].Source = "naive_bayes (no CWE data)"
		}

		return results
	}
}

func getCandidatesFromCWEs(cweIDs []string, hierarchy *CWEHierarchy, verbose bool) map[string]bool {
	candidates := make(map[string]bool)

	if len(cweIDs) == 0 {
		return candidates
	}

	if verbose {
		fmt.Printf("\nExtracting candidate attack vectors from %d CWE IDs...\n", len(cweIDs))
	}

	for _, cweID := range cweIDs {
		// Get CWE info
		cwe, exists := hierarchy.CWEs[cweID]
		if !exists {
			if verbose {
				fmt.Printf("  CWE-%s: not found in hierarchy\n", cweID)
			}
			continue
		}

		if verbose {
			fmt.Printf("  CWE-%s (%s):\n", cweID, cwe.Name)
		}

		// Level 0: Direct mapping
		if len(cwe.AttackVectors) > 0 {
			for _, vector := range cwe.AttackVectors {
				candidates[vector] = true
				if verbose {
					fmt.Printf("    [Level 0] %s\n", vector)
				}
			}
		}

		// Level 1: Parent mappings
		for _, parentID := range cwe.Parents {
			parent, exists := hierarchy.CWEs[parentID]
			if !exists {
				continue
			}

			if len(parent.AttackVectors) > 0 {
				for _, vector := range parent.AttackVectors {
					if !candidates[vector] {
						candidates[vector] = true
						if verbose {
							fmt.Printf("    [Level 1 - CWE-%s] %s\n", parentID, vector)
						}
					}
				}
			}

			// Level 2: Grandparent mappings
			for _, grandparentID := range parent.Parents {
				grandparent, exists := hierarchy.CWEs[grandparentID]
				if !exists {
					continue
				}

				if len(grandparent.AttackVectors) > 0 {
					for _, vector := range grandparent.AttackVectors {
						if !candidates[vector] {
							candidates[vector] = true
							if verbose {
								fmt.Printf("    [Level 2 - CWE-%s] %s\n", grandparentID, vector)
							}
						}
					}
				}
			}
		}
	}

	if verbose {
		fmt.Printf("\nTotal candidate attack vectors: %d\n", len(candidates))
	}

	return candidates
}

func classifyNaiveBayes(description string, model *AttackVectorModel, candidates map[string]bool, patternTaxonomy *PatternTaxonomy, verbose bool) []ClassificationResult {
	// Tokenize description
	tokens := tokenize(description)

	// Calculate log probabilities for each vector
	scores := make(map[string]float64)

	for vector := range model.VectorPriors {
		// Skip if not in candidates (if candidates are specified)
		if candidates != nil && len(candidates) > 0 && !candidates[vector] {
			continue
		}

		// Start with prior (log probability)
		logProb := math.Log(model.VectorPriors[vector])

		// Add word probabilities
		for _, word := range tokens {
			if prob, exists := model.WordGivenVector[vector][word]; exists {
				logProb += math.Log(prob)
			}
		}

		scores[vector] = logProb
	}

	// Debug: Show raw Naive Bayes scores
	if verbose {
		fmt.Println("\n  [Naive Bayes Raw Scores - Log Probabilities]:")
		for vector, score := range scores {
			fmt.Printf("    %s: %.2f\n", vector, score)
		}
	}

	// Apply data-driven pattern boosting (Layer 3)
	if patternTaxonomy != nil {
		descLower := strings.ToLower(description)

		// Get candidate vectors as slice
		candidateVectors := make([]string, 0, len(candidates))
		for vector := range candidates {
			candidateVectors = append(candidateVectors, vector)
		}

		patternBoosts := scorePatternMatches(descLower, candidateVectors, patternTaxonomy)

		// Apply boosts to scores
		for vector, boost := range patternBoosts {
			if _, exists := scores[vector]; exists {
				scores[vector] += boost
				if verbose {
					fmt.Printf("  [Pattern Boost] %s: +%.1f\n", vector, boost)
				}
			}
		}
	}

	// Convert to probabilities and sort
	results := make([]ClassificationResult, 0, len(scores))

	// Find max log prob for normalization
	maxLogProb := math.Inf(-1)
	for _, logProb := range scores {
		if logProb > maxLogProb {
			maxLogProb = logProb
		}
	}

	// Convert to probabilities
	sumProb := 0.0
	probs := make(map[string]float64)
	for vector, logProb := range scores {
		prob := math.Exp(logProb - maxLogProb)
		probs[vector] = prob
		sumProb += prob
	}

	// Normalize and create results
	for vector, prob := range probs {
		normalizedProb := prob / sumProb

		confidence := "low"
		if normalizedProb >= 0.7 {
			confidence = "high"
		} else if normalizedProb >= 0.4 {
			confidence = "medium"
		}

		results = append(results, ClassificationResult{
			Vector:      vector,
			Name:        getVectorName(vector),
			Probability: normalizedProb,
			Confidence:  confidence,
		})
	}

	// Sort by probability (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results
}

func getVectorName(vector string) string {
	vectorNames := map[string]string{
		"xss":                  "Cross-Site Scripting",
		"sql_injection":        "SQL Injection",
		"rce":                  "Remote Code Execution",
		"command_injection":    "OS Command Injection",
		"path_traversal":       "Path Traversal",
		"ssrf":                 "Server-Side Request Forgery",
		"deserialization":      "Deserialization Vulnerabilities",
		"auth_bypass":          "Authentication Bypass",
		"authz_bypass":         "Authorization Bypass",
		"file_upload":          "File Upload Vulnerabilities",
		"csrf":                 "Cross-Site Request Forgery",
		"xxe":                  "XML External Entity",
		"ldap_injection":       "LDAP Injection",
		"jndi_injection":       "JNDI/Expression Language Injection",
		"privilege_escalation": "Privilege Escalation",
		"buffer_overflow":      "Buffer Overflow",
		"idor":                 "Insecure Direct Object Reference",
		"http_desync":          "HTTP Request Smuggling",
		"hardcoded_creds":      "Hard-coded Credentials",
		"info_disclosure":      "Information Disclosure",
		"dos":                  "Denial of Service",
		"nosql_injection":      "NoSQL Injection",
		"xpath_injection":      "XPath Injection",
		"open_redirect":        "Open Redirect",
		"session_fixation":     "Session Fixation",
		"crypto_failure":       "Cryptographic Failures",
		"integer_overflow":     "Integer Overflow",
		"use_after_free":       "Use After Free",
		"null_pointer":         "NULL Pointer Dereference",
		"format_string":        "Format String Vulnerability",
		"email_injection":      "Email Header Injection",
		"race_condition":       "Race Condition",
		"ssti":                 "Server-Side Template Injection",
		"input_validation":     "Improper Input Validation",
		"code_injection":       "Code Injection",
	}

	if name, exists := vectorNames[vector]; exists {
		return name
	}
	return vector // Return ID if no mapping found
}

func tokenize(text string) []string {
	// Convert to lowercase
	text = strings.ToLower(text)

	// Remove version numbers
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")

	// Remove CVE IDs
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extract words
	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

	// Filter stopwords (comprehensive list matching trainer)
	stopwords := map[string]bool{
		// Common English stopwords
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
		"shall": true, "into": true, "through": true, "during": true, "before": true,
		"after": true, "above": true, "below": true, "between": true, "under": true,
		"again": true, "further": true, "then": true, "once": true, "here": true,
		"there": true, "when": true, "where": true, "why": true, "how": true,
		"all": true, "both": true, "each": true, "few": true, "more": true,
		"most": true, "other": true, "some": true, "such": true, "only": true,
		"own": true, "same": true, "than": true, "too": true, "very": true,
		"just": true, "also": true, "any": true, "these": true, "those": true,
		"what": true, "which": true, "who": true, "whom": true, "whose": true,
		"out": true, "off": true, "over": true, "down": true, "does": true,
		"did": true, "doing": true, "nor": true, "about": true, "against": true,
		"because": true, "until": true, "while": true, "upon": true, "within": true,

		// Security-specific generic terms
		"vulnerability": true, "vulnerabilities": true, "vulnerable": true,
		"issue": true, "issues": true, "flaw": true, "flaws": true,
		"product": true, "products": true, "component": true, "components": true,
		"application": true, "applications": true, "software": true,
		"version": true, "versions": true, "release": true, "releases": true,
		"fix": true, "fixed": true, "resolved": true, "patch": true, "patched": true,
		"attacker": true, "attackers": true, "user": true, "users": true,
		"access": true, "system": true, "systems": true,
		"data": true, "code": true, "file": true, "files": true,
		"found": true, "used": true, "use": true, "uses": true, "using": true,
		"allows": true, "allow": true, "via": true,
		"perform": true, "execute": true, "run": true, "process": true,
		"obtain": true, "gain": true, "achieve": true, "lead": true, "leads": true,
		"function": true, "functions": true, "method": true, "methods": true,
		"value": true, "values": true, "parameter": true, "parameters": true,
		"request": true, "requests": true, "response": true, "responses": true,
		"certain": true, "specific": true, "particular": true, "multiple": true,
		"various": true, "related": true, "associated": true, "affected": true,
		"improper": true, "insufficient": true, "incorrect": true, "invalid": true,
		"due": true, "lack": true, "missing": true, "without": true,
		"cause": true, "causes": true, "caused": true, "result": true, "results": true,
		"resulting": true, "leading": true, "enable": true, "enabled": true,
		"make": true, "makes": true, "made": true, "making": true,
		"contain": true, "contains": true, "containing": true, "included": true,
		"including": true, "present": true, "exists": true, "existing": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

func loadCWEHierarchy(filename string) (*CWEHierarchy, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var hierarchy CWEHierarchy
	if err := json.Unmarshal(data, &hierarchy); err != nil {
		return nil, err
	}

	// Build forward mapping (AttackVector -> CWE IDs) if not present
	if hierarchy.AttackVectorMapping == nil || len(hierarchy.AttackVectorMapping) == 0 {
		hierarchy.AttackVectorMapping = make(map[string][]string)

		if showDetails {
			fmt.Println("[DEBUG] Building forward AttackVector->CWE mapping from CWE attack_vectors...")
		}

		// Build from CWE attack_vectors field
		for cweID, cweInfo := range hierarchy.CWEs {
			if cweInfo != nil {
				for _, av := range cweInfo.AttackVectors {
					hierarchy.AttackVectorMapping[av] = append(hierarchy.AttackVectorMapping[av], cweID)
				}
			}
		}

		if showDetails {
			fmt.Printf("[DEBUG] Built %d attack vector mappings\n", len(hierarchy.AttackVectorMapping))
			// Show a sample of the mappings
			count := 0
			for av, cweIDs := range hierarchy.AttackVectorMapping {
				if count < 5 {
					fmt.Printf("[DEBUG]   '%s' -> %v\n", av, cweIDs)
					count++
				}
			}
		}
	}

	return &hierarchy, nil
}

func loadNaiveBayesModel(filename string) (*AttackVectorModel, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var model AttackVectorModel
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, err
	}

	return &model, nil
}

// Load pattern taxonomy from JSON file
func loadPatternTaxonomy(filename string) (*PatternTaxonomy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var taxonomy PatternTaxonomy
	if err := json.Unmarshal(data, &taxonomy); err != nil {
		return nil, err
	}

	return &taxonomy, nil
}

// Score pattern matches for each candidate vector
func scorePatternMatches(description string, candidates []string, taxonomy *PatternTaxonomy) map[string]float64 {
	boosts := make(map[string]float64)

	// For each candidate vector
	for _, vector := range candidates {
		patterns, exists := taxonomy.Patterns[vector]
		if !exists {
			continue
		}

		totalBoost := 0.0

		// Check each pattern rule for this vector
		for _, pattern := range patterns {
			// Check if all keywords in the pattern are present
			allMatch := true
			for _, keyword := range pattern.Keywords {
				if !strings.Contains(description, keyword) {
					allMatch = false
					break
				}
			}

			if allMatch {
				// Pattern matched! Apply boost
				totalBoost += pattern.Boost
			}
		}

		// Store total boost for this vector
		if totalBoost > 0 {
			boosts[vector] = totalBoost
		}
	}

	return boosts
}

// Load CAPEC data from JSON file
func loadCAPECData(filename string) ([]CAPECData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var capecs []CAPECData
	if err := json.Unmarshal(data, &capecs); err != nil {
		return nil, err
	}

	return capecs, nil
}

// Load CWE to CAPEC relationships
func loadRelationships(filename string) (*RelationshipsDB, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var rels RelationshipsDB
	if err := json.Unmarshal(data, &rels); err != nil {
		return nil, err
	}

	return &rels, nil
}

// Get candidate CAPECs from best CWEs
func getCandidateCAPECsFromCWEs(cweIDs []string, relationships *RelationshipsDB, verbose bool) map[string]bool {
	candidates := make(map[string]bool)

	if verbose {
		fmt.Printf("\nGetting candidate CAPECs from %d best CWEs...\n", len(cweIDs))
	}

	for _, cweID := range cweIDs {
		cweKey := "CWE-" + cweID
		if capecs, exists := relationships.CWEToCapec[cweKey]; exists {
			for _, capecID := range capecs {
				candidates[capecID] = true
			}
			if verbose {
				fmt.Printf("  %s → %d CAPECs\n", cweKey, len(capecs))
			}
		}
	}

	if verbose {
		fmt.Printf("Total candidate CAPECs: %d\n", len(candidates))
	}

	return candidates
}

// Classify CAPECs using Naive Bayes (simple overlap scoring)
func classifyNaiveBayesCAPEC(description string, candidates []CAPECData) []CAPECResult {
	// Tokenize description
	tokens := tokenize(description)
	descSet := make(map[string]bool)
	for _, token := range tokens {
		descSet[token] = true
	}

	// Calculate scores for each candidate CAPEC
	var results []CAPECResult

	for _, capec := range candidates {
		// Tokenize CAPEC description and name
		capecText := capec.Description + " " + capec.Name
		capecTokens := tokenize(capecText)

		// Calculate overlap
		overlap := 0
		capecSet := make(map[string]bool)
		for _, token := range capecTokens {
			capecSet[token] = true
			if descSet[token] {
				overlap++
			}
		}

		// Calculate probability (Jaccard similarity)
		union := len(descSet) + len(capecSet) - overlap
		probability := float64(overlap) / float64(union+1)

		// Boost if severity is high
		if capec.TypicalSeverity == "High" || capec.TypicalSeverity == "Very High" {
			probability *= 1.2
		}

		// Determine confidence
		confidence := "low"
		if probability > 0.15 {
			confidence = "high"
		} else if probability > 0.08 {
			confidence = "medium"
		}

		results = append(results, CAPECResult{
			CAPECID:     capec.CAPECID,
			Name:        capec.Name,
			Probability: probability,
			Confidence:  confidence,
		})
	}

	// Sort by probability (descending)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Probability > results[j].Probability
	})

	return results
}

// Rank CAPECs based on best CWEs
func rankCAPECs(description string, bestCWEs []string, capecData []CAPECData, relationships *RelationshipsDB, topN int, verbose bool) []CAPECResult {
	// Step 1: Get candidate CAPECs from best CWEs only
	candidateCAPECs := getCandidateCAPECsFromCWEs(bestCWEs, relationships, verbose)

	if len(candidateCAPECs) == 0 {
		if verbose {
			fmt.Println("No CAPECs found for the given CWEs")
		}
		return []CAPECResult{}
	}

	// Step 2: Filter CAPEC data to candidates only
	var candidates []CAPECData
	for _, capec := range capecData {
		if candidateCAPECs[capec.CAPECID] {
			candidates = append(candidates, capec)
		}
	}

	if verbose {
		fmt.Printf("Ranking %d candidate CAPECs...\n", len(candidates))
	}

	// Step 3: Rank using Naive Bayes
	results := classifyNaiveBayesCAPEC(description, candidates)

	// Step 4: Take top N
	if len(results) > topN {
		results = results[:topN]
	}

	return results
}
