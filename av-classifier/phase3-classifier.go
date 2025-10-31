package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
)

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
	AttackVectorMapping map[string][]string `json:"attack_vector_mapping"`
}

// Naive Bayes model structures
type AttackVectorModel struct {
	Vocabulary        map[string]bool               `json:"vocabulary"`
	VectorPriors      map[string]float64            `json:"vector_priors"`
	WordProbabilities map[string]map[string]float64 `json:"word_probabilities"`
	VectorNames       map[string]string             `json:"vector_names"`
}

// Classification result
type ClassificationResult struct {
	Vector      string  `json:"vector"`
	Name        string  `json:"name"`
	Probability float64 `json:"probability"`
	Confidence  string  `json:"confidence"`
	Source      string  `json:"source"` // "cwe_hierarchy", "naive_bayes", or "hybrid"
}

var (
	cveDesc     string
	cweIDs      string
	topN        int
	showDetails bool
)

func main() {
	flag.StringVar(&cveDesc, "description", "", "CVE description text")
	flag.StringVar(&cveDesc, "d", "", "CVE description text (shorthand)")
	flag.StringVar(&cweIDs, "cwes", "", "Comma-separated CWE IDs (e.g., '94,502,20')")
	flag.StringVar(&cweIDs, "c", "", "Comma-separated CWE IDs (shorthand)")
	flag.IntVar(&topN, "top", 3, "Number of top results to return")
	flag.BoolVar(&showDetails, "verbose", false, "Show detailed classification process")
	flag.BoolVar(&showDetails, "v", false, "Show detailed classification process (shorthand)")
	flag.Parse()

	if cveDesc == "" {
		fmt.Println("Usage: hybrid-classifier -description \"CVE description\" [-cwes \"94,502\"] [-top 3] [-verbose]")
		fmt.Println("\nExample:")
		fmt.Println("  hybrid-classifier -d \"allows remote attackers to execute arbitrary code via JNDI\" -c \"502,917\"")
		os.Exit(1)
	}

	fmt.Println("=================================================================")
	fmt.Println("Hybrid CWE + Naive Bayes Attack Vector Classifier")
	fmt.Println("=================================================================\n")

	// Load CWE hierarchy
	if showDetails {
		fmt.Println("Loading CWE hierarchy...")
	}
	hierarchy, err := loadCWEHierarchy("cwe_hierarchy.json")
	if err != nil {
		fmt.Printf("Error loading CWE hierarchy: %v\n", err)
		fmt.Println("Run 'cwe-hierarchy-builder' first to generate cwe_hierarchy.json")
		os.Exit(1)
	}
	if showDetails {
		fmt.Printf("Loaded %d CWEs\n\n", len(hierarchy.CWEs))
	}

	// Load Naive Bayes model
	if showDetails {
		fmt.Println("Loading Naive Bayes model...")
	}
	model, err := loadNaiveBayesModel("attack_vector_model.json")
	if err != nil {
		fmt.Printf("Error loading Naive Bayes model: %v\n", err)
		fmt.Println("Run 'trainer' first to generate attack_vector_model.json")
		os.Exit(1)
	}
	if showDetails {
		fmt.Printf("Loaded model with %d attack vectors\n\n", len(model.VectorPriors))
	}

	// Parse CWE IDs
	var cwes []string
	if cweIDs != "" {
		cwes = strings.Split(strings.ReplaceAll(cweIDs, " ", ""), ",")
		// Clean CWE IDs (remove "CWE-" prefix if present)
		for i, cwe := range cwes {
			cwes[i] = strings.TrimPrefix(strings.ToUpper(cwe), "CWE-")
		}
	}

	// Classify
	results := classifyHybrid(cveDesc, cwes, hierarchy, model, topN, showDetails)

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
}

func classifyHybrid(description string, cweIDs []string, hierarchy *CWEHierarchy, model *AttackVectorModel, topN int, verbose bool) []ClassificationResult {
	// Step 1: Get candidate attack vectors from CWE hierarchy
	candidates := getCandidatesFromCWEs(cweIDs, hierarchy, verbose)

	// Step 2: Apply Naive Bayes
	if len(candidates) > 0 {
		if verbose {
			fmt.Printf("\nApplying Naive Bayes to %d candidate attack vectors...\n", len(candidates))
		}
		// Classify only among candidates
		results := classifyNaiveBayes(description, model, candidates)

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
		results := classifyNaiveBayes(description, model, nil)

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

func classifyNaiveBayes(description string, model *AttackVectorModel, candidates map[string]bool) []ClassificationResult {
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
			if prob, exists := model.WordProbabilities[vector][word]; exists {
				logProb += math.Log(prob)
			}
		}

		scores[vector] = logProb
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
			Name:        model.VectorNames[vector],
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

	// Filter stopwords (simplified list)
	stopwords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"vulnerability": true, "issue": true, "allows": true, "via": true,
		"user": true, "attacker": true, "version": true, "versions": true,
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
