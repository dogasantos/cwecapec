package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	CAPECXMLURL = "https://capec.mitre.org/data/xml/capec_latest.xml"
)

// CAPEC XML structures
type CAPECCatalog struct {
	XMLName        xml.Name        `xml:"Attack_Pattern_Catalog"`
	AttackPatterns []AttackPattern `xml:"Attack_Patterns>Attack_Pattern"`
}

type AttackPattern struct {
	ID                 string             `xml:"ID,attr"`
	Name               string             `xml:"Name,attr"`
	Abstraction        string             `xml:"Abstraction,attr"`
	Status             string             `xml:"Status,attr"`
	Description        Description        `xml:"Description"`
	LikelihoodOfAttack LikelihoodOfAttack `xml:"Likelihood_Of_Attack"`
	TypicalSeverity    string             `xml:"Typical_Severity"`
	RelatedWeaknesses  []RelatedWeakness  `xml:"Related_Weaknesses>Related_Weakness"`
	Prerequisites      []Prerequisite     `xml:"Prerequisites>Prerequisite"`
	Taxonomy_Mappings  []TaxonomyMapping  `xml:"Taxonomy_Mappings>Taxonomy_Mapping"`
}

type Description struct {
	Summary string `xml:"Summary"`
	Text    string `xml:",chardata"`
}

type LikelihoodOfAttack struct {
	Text string `xml:",chardata"`
}

type RelatedWeakness struct {
	CWEID string `xml:"CWE_ID,attr"`
}

type Prerequisite struct {
	Text string `xml:",chardata"`
}

type TaxonomyMapping struct {
	TaxonomyName string `xml:"Taxonomy_Name,attr"`
	EntryID      string `xml:"Entry_ID,attr"`
	EntryName    string `xml:"Entry_Name,attr"`
}

// Output structure for training
type CAPECTrainingData struct {
	CAPECID            string   `json:"capec_id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	LikelihoodOfAttack string   `json:"likelihood_of_attack"`
	TypicalSeverity    string   `json:"typical_severity"`
	RelatedCWEs        []string `json:"related_cwes"`
	Prerequisites      []string `json:"prerequisites"`
	AttackTechniques   []string `json:"attack_techniques"`
}

func main() {
	outputFile := flag.String("o", "capec_training_data.json", "Output JSON file")
	flag.Parse()

	fmt.Println("=================================================================")
	fmt.Println("CAPEC Training Data Collector")
	fmt.Println("=================================================================")

	// Download CAPEC XML
	fmt.Printf("\nDownloading CAPEC data from %s...\n", CAPECXMLURL)
	xmlData, err := downloadCAPECXML()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error downloading CAPEC XML: %v\n", err)
		os.Exit(1)
	}

	// Parse XML
	fmt.Println("Parsing CAPEC XML...")
	catalog, err := parseCAPECXML(xmlData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing CAPEC XML: %v\n", err)
		os.Exit(1)
	}

	// Convert to training data
	fmt.Println("Converting to training data format...")
	trainingData := convertToTrainingData(catalog)

	// Filter and validate
	validData := filterValidCAPECs(trainingData)
	fmt.Printf("Collected %d valid CAPECs (filtered from %d total)\n", len(validData), len(trainingData))

	// Save to JSON
	fmt.Printf("Saving to %s...\n", *outputFile)
	if err := saveJSON(validData, *outputFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving JSON: %v\n", err)
		os.Exit(1)
	}

	// Print statistics
	printStatistics(validData)

	fmt.Println("\n✓ CAPEC training data collection complete!")
}

func downloadCAPECXML() ([]byte, error) {
	client := &http.Client{
		Timeout: 120 * time.Second,
	}

	resp, err := client.Get(CAPECXMLURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func parseCAPECXML(xmlData []byte) (*CAPECCatalog, error) {
	var catalog CAPECCatalog
	if err := xml.Unmarshal(xmlData, &catalog); err != nil {
		return nil, err
	}
	return &catalog, nil
}

func fetchDescriptionFromWeb(capecID string) string {
	// Fetch description from MITRE CAPEC website
	url := fmt.Sprintf("https://capec.mitre.org/data/definitions/%s.html", capecID)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	// Simple extraction: find text between description tags
	// This is a simplified approach - in production, use proper HTML parsing
	html := string(body)

	// Look for the description paragraph
	start := strings.Index(html, "<div id=\"Description\"")
	if start == -1 {
		return ""
	}

	// Find the next paragraph after Description heading
	pStart := strings.Index(html[start:], "<p>")
	if pStart == -1 {
		return ""
	}
	pStart += start

	pEnd := strings.Index(html[pStart:], "</p>")
	if pEnd == -1 {
		return ""
	}
	pEnd += pStart

	desc := html[pStart+3 : pEnd]

	// Remove HTML tags
	desc = strings.ReplaceAll(desc, "<br/>", " ")
	desc = strings.ReplaceAll(desc, "<br>", " ")

	// Simple tag removal (not perfect but good enough)
	for strings.Contains(desc, "<") {
		tagStart := strings.Index(desc, "<")
		tagEnd := strings.Index(desc[tagStart:], ">")
		if tagEnd == -1 {
			break
		}
		desc = desc[:tagStart] + desc[tagStart+tagEnd+1:]
	}

	return strings.TrimSpace(desc)
}

func convertToTrainingData(catalog *CAPECCatalog) []CAPECTrainingData {
	var trainingData []CAPECTrainingData

	for _, ap := range catalog.AttackPatterns {
		// Extract description
		description := strings.TrimSpace(ap.Description.Summary)
		if description == "" {
			description = strings.TrimSpace(ap.Description.Text)
		}

		// If still no description, fetch from MITRE website
		if description == "" || len(description) < 20 {
			fmt.Printf("  Fetching description for CAPEC-%s from website...\n", ap.ID)
			webDesc := fetchDescriptionFromWeb(ap.ID)
			if webDesc != "" {
				description = webDesc
			}
		}

		// Extract related CWEs
		var relatedCWEs []string
		for _, rw := range ap.RelatedWeaknesses {
			if rw.CWEID != "" {
				relatedCWEs = append(relatedCWEs, rw.CWEID)
			}
		}

		// Extract prerequisites
		var prerequisites []string
		for _, prereq := range ap.Prerequisites {
			text := strings.TrimSpace(prereq.Text)
			if text != "" {
				prerequisites = append(prerequisites, text)
			}
		}

		// Extract ATT&CK techniques
		var attackTechniques []string
		for _, mapping := range ap.Taxonomy_Mappings {
			if strings.Contains(strings.ToLower(mapping.TaxonomyName), "attack") {
				if mapping.EntryID != "" {
					attackTechniques = append(attackTechniques, mapping.EntryID)
				}
			}
		}

		trainingData = append(trainingData, CAPECTrainingData{
			CAPECID:            ap.ID,
			Name:               ap.Name,
			Description:        description,
			LikelihoodOfAttack: strings.TrimSpace(ap.LikelihoodOfAttack.Text),
			TypicalSeverity:    ap.TypicalSeverity,
			RelatedCWEs:        relatedCWEs,
			Prerequisites:      prerequisites,
			AttackTechniques:   attackTechniques,
		})
	}

	return trainingData
}

func filterValidCAPECs(data []CAPECTrainingData) []CAPECTrainingData {
	var valid []CAPECTrainingData

	for _, capec := range data {
		// Filter criteria (relaxed to include all CAPECs):
		// 1. Must have a description
		// 2. Description must be at least 20 characters (reduced from 50)
		if capec.Description != "" && len(capec.Description) >= 20 {
			valid = append(valid, capec)
		}
	}

	return valid
}

func saveJSON(data []CAPECTrainingData, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func printStatistics(data []CAPECTrainingData) {
	fmt.Println("\n=================================================================")
	fmt.Println("Statistics:")
	fmt.Println("=================================================================")

	totalCWEs := 0
	totalPrereqs := 0
	totalAttack := 0
	likelihoodCounts := make(map[string]int)
	severityCounts := make(map[string]int)

	for _, capec := range data {
		totalCWEs += len(capec.RelatedCWEs)
		totalPrereqs += len(capec.Prerequisites)
		totalAttack += len(capec.AttackTechniques)

		if capec.LikelihoodOfAttack != "" {
			likelihoodCounts[capec.LikelihoodOfAttack]++
		}
		if capec.TypicalSeverity != "" {
			severityCounts[capec.TypicalSeverity]++
		}
	}

	fmt.Printf("Total CAPECs: %d\n", len(data))
	fmt.Printf("Total CWE relationships: %d\n", totalCWEs)
	fmt.Printf("Total prerequisites: %d\n", totalPrereqs)
	fmt.Printf("Total ATT&CK mappings: %d\n", totalAttack)

	fmt.Println("\nLikelihood of Attack distribution:")
	for likelihood, count := range likelihoodCounts {
		fmt.Printf("  %s: %d\n", likelihood, count)
	}

	fmt.Println("\nTypical Severity distribution:")
	for severity, count := range severityCounts {
		fmt.Printf("  %s: %d\n", severity, count)
	}
}
