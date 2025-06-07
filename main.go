package main

import (
	"archive/zip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/xuri/excelize/v2"
)

// Constants and file paths
const (
	CWEZipURL               = "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
	CWEJSONPath             = "resources/cwe_db.json"
	CAPECZipURL             = "https://capec.mitre.org/data/archive/capec_latest.zip"
	CAPECJSONPath           = "resources/capec_db.json"
	TechniquesJSONPath      = "resources/techniques_db.json"
	EnterpriseTechniquesX   = "https://attack.mitre.org/docs/enterprise-attack-v17.1/enterprise-attack-v17.1-techniques.xlsx"
	MobileTechniquesX       = "https://attack.mitre.org/docs/mobile-attack-v17.1/mobile-attack-v17.1-techniques.xlsx"
	ICSTechniquesX          = "https://attack.mitre.org/docs/ics-attack-v17.1/ics-attack-v17.1-techniques.xlsx"
	// Column indices in the MITRE ATT&CK spreadsheets (0-based)
	EnterpriseColumnIdx = 9  // 10th column (J)
	MobileColumnIdx     = 10 // 11th column (K)
	ICSColumnIdx        = 9  // 10th column (J)
)

func main() {
	// Ensure the "resources" directory exists
	if err := os.MkdirAll("resources", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating resources directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[1/3] Downloading and processing CWE...")
	if err := processCWE(); err != nil {
		fmt.Fprintf(os.Stderr, "CWE processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[2/3] Downloading and processing CAPEC...")
	if err := processCAPEC(); err != nil {
		fmt.Fprintf(os.Stderr, "CAPEC processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[3/3] Downloading and processing Techniques...")
	if err := processTechniques(); err != nil {
		fmt.Fprintf(os.Stderr, "Techniques processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("All data successfully updated in resources/*.json")
}

// -------------------- CWE Processing --------------------

// Structures to unmarshal CWE XML
type CWECatalog struct {
	XMLName    xml.Name   `xml:"Weakness_Catalog"`
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"`
}

type Weakness struct {
	ID                    string                    `xml:"ID,attr"`
	RelatedWeaknesses     *RelatedWeaknessesBlock   `xml:"Related_Weaknesses"`
	RelatedAttackPatterns *RelatedAttackPatternsBlock `xml:"Related_Attack_Patterns"`
}

type RelatedWeaknessesBlock struct {
	Items []RelatedWeakness `xml:"Related_Weakness"`
}

type RelatedWeakness struct {
	Nature string `xml:"Nature,attr"`
	ViewID string `xml:"View_ID,attr"`
	CWEID  string `xml:"CWE_ID,attr"`
}

type RelatedAttackPatternsBlock struct {
	Items []RelatedAttackPattern `xml:"Related_Attack_Pattern"`
}

type RelatedAttackPattern struct {
	CAPECID string `xml:"CAPEC_ID,attr"`
}

func processCWE() error {
	// 1. Download ZIP
	resp, err := http.Get(CWEZipURL)
	if err != nil {
		return fmt.Errorf("failed to GET CWE ZIP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code downloading CWE: %d", resp.StatusCode)
	}

	zipFilePath := "cwec_latest.xml.zip"
	outZip, err := os.Create(zipFilePath)
	if err != nil {
		return fmt.Errorf("unable to create ZIP file: %w", err)
	}
	if _, err := io.Copy(outZip, resp.Body); err != nil {
		outZip.Close()
		return fmt.Errorf("error writing ZIP file: %w", err)
	}
	outZip.Close()

	// 2. Unzip and find XML
	xmlFilename, err := unzipAndFind(zipFilePath, `cwec_v\d+\.\d+\.xml`)
	if err != nil {
		return fmt.Errorf("failed to unzip CWE: %w", err)
	}
	// Clean up ZIP
	os.Remove(zipFilePath)

	// 3. Parse XML
	xmlData, err := ioutil.ReadFile(xmlFilename)
	if err != nil {
		return fmt.Errorf("failed to read extracted CWE XML: %w", err)
	}
	var catalog CWECatalog
	if err := xml.Unmarshal(xmlData, &catalog); err != nil {
		os.Remove(xmlFilename)
		return fmt.Errorf("error unmarshaling CWE XML: %w", err)
	}
	// Remove XML file after parsing
	os.Remove(xmlFilename)

	// 4. Build JSON structure
	type CWEInfo struct {
		ChildOf               []string `json:"ChildOf"`
		RelatedAttackPatterns []string `json:"RelatedAttackPatterns"`
	}
	results := make(map[string]CWEInfo, len(catalog.Weaknesses))

	for _, w := range catalog.Weaknesses {
		childSet := make(map[string]struct{})
		if w.RelatedWeaknesses != nil {
			for _, rw := range w.RelatedWeaknesses.Items {
				if rw.Nature == "ChildOf" && rw.ViewID == "1000" {
					childSet[rw.CWEID] = struct{}{}
				}
			}
		}

		attackSet := make(map[string]struct{})
		if w.RelatedAttackPatterns != nil {
			for _, ap := range w.RelatedAttackPatterns.Items {
				attackSet[ap.CAPECID] = struct{}{}
			}
		}

		// Convert sets to slices
		childSlice := make([]string, 0, len(childSet))
		for cid := range childSet {
			childSlice = append(childSlice, cid)
		}
		attackSlice := make([]string, 0, len(attackSet))
		for capid := range attackSet {
			attackSlice = append(attackSlice, capid)
		}

		results[w.ID] = CWEInfo{
			ChildOf:               childSlice,
			RelatedAttackPatterns: attackSlice,
		}
	}

	// 5. Write JSON to file
	outFile, err := os.Create(CWEJSONPath)
	if err != nil {
		return fmt.Errorf("unable to create CWE JSON file: %w", err)
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("error writing CWE JSON: %w", err)
	}

	return nil
}

func unzipAndFind(zipPath, pattern string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("opening zip: %w", err)
	}
	defer r.Close()

	re := regexp.MustCompile(pattern)
	for _, f := range r.File {
		if re.MatchString(f.Name) {
			rc, err := f.Open()
			if err != nil {
				return "", fmt.Errorf("opening file in zip: %w", err)
			}
			defer rc.Close()

			outFile, err := os.Create(f.Name)
			if err != nil {
				return "", fmt.Errorf("creating extracted file: %w", err)
			}
			if _, err := io.Copy(outFile, rc); err != nil {
				outFile.Close()
				return "", fmt.Errorf("writing extracted file: %w", err)
			}
			outFile.Close()
			return f.Name, nil
		}
	}
	return "", fmt.Errorf("no file matching pattern %q found in ZIP", pattern)
}

// -------------------- CAPEC Processing --------------------

// ---- Comprehensive structs for parsing detailed CAPEC XML ----

type CAPECCatalog struct {
	XMLName        xml.Name       `xml:"Attack_Pattern_Catalog"`
	AttackPatterns []CAPECPattern `xml:"Attack_Patterns>Attack_Pattern"`
}

// CAPECPattern maps to the full <Attack_Pattern> element in the XML
type CAPECPattern struct {
	ID                    string                     `xml:"ID,attr"`
	Name                  string                     `xml:"Name,attr"`
	Description           string                     `xml:"Description"`
	LikelihoodOfAttack    string                     `xml:"Likelihood_Of_Attack"`
	TypicalSeverity       string                     `xml:"Typical_Severity"`
	RelatedAttackPatterns *XMLRelatedAttackPatterns  `xml:"Related_Attack_Patterns"`
	ExecutionFlow         *XMLExecutionFlow          `xml:"Execution_Flow"`
	Prerequisites         *XMLPrerequisites          `xml:"Prerequisites"`
	SkillsRequired        *XMLSkillsRequired         `xml:"Skills_Required"`
	Consequences          *XMLConsequences           `xml:"Consequences"`
	RelatedWeaknesses     *XMLRelatedWeaknesses      `xml:"Related_Weaknesses"`
	TaxonomyMappings      *XMLTaxonomyMappings       `xml:"Taxonomy_Mappings"`
}

type XMLRelatedAttackPatterns struct {
	Patterns []XMLRelatedAttackPattern `xml:"Related_Attack_Pattern"`
}
type XMLRelatedAttackPattern struct {
	Nature  string `xml:"Nature,attr"`
	CAPECID string `xml:"CAPEC_ID,attr"`
}

type XMLExecutionFlow struct {
	Steps []XMLAttackStep `xml:"Attack_Step"`
}
type XMLAttackStep struct {
	Step        string   `xml:"Step"`
	Phase       string   `xml:"Phase"`
	Description string   `xml:"Description"`
	Techniques  []string `xml:"Technique"`
}

type XMLPrerequisites struct {
	Items []string `xml:"Prerequisite"`
}

type XMLSkillsRequired struct {
	Skills []XMLSkill `xml:"Skill"`
}
type XMLSkill struct {
	Level   string `xml:"Level,attr"`
	Content string `xml:",chardata"`
}

type XMLConsequences struct {
	Items []XMLConsequence `xml:"Consequence"`
}
type XMLConsequence struct {
	Scopes  []string `xml:"Scope"`
	Impacts []string `xml:"Impact"`
}

type XMLRelatedWeaknesses struct {
	Weaknesses []XMLRelatedWeakness `xml:"Related_Weakness"`
}
type XMLRelatedWeakness struct {
	CWEID string `xml:"CWE_ID,attr"`
}

type XMLTaxonomyMappings struct {
	Mappings []XMLTaxonomyMapping `xml:"Taxonomy_Mapping"`
}
type XMLTaxonomyMapping struct {
	TaxonomyName string `xml:"Taxonomy_Name,attr"`
	EntryID      string `xml:"Entry_ID"`
}

// ---- Structs for the final, detailed JSON output ----

type CAPECInfo struct {
	Name                  string                       `json:"name"`
	Description           string                       `json:"description,omitempty"`
	LikelihoodOfAttack    string                       `json:"likelihoodOfAttack,omitempty"`
	TypicalSeverity       string                       `json:"typicalSeverity,omitempty"`
	RelatedAttackPatterns []RelatedAttackPatternInfo   `json:"relatedAttackPatterns,omitempty"`
	ExecutionFlow         []ExecutionStepInfo          `json:"executionFlow,omitempty"`
	Prerequisites         []string                     `json:"prerequisites,omitempty"`
	SkillsRequired        []SkillInfo                  `json:"skillsRequired,omitempty"`
	Consequences          []ConsequenceInfo            `json:"consequences,omitempty"`
	RelatedWeaknesses     []string                     `json:"relatedWeaknesses,omitempty"`
	MitreAttack           []string                     `json:"mitreAttack,omitempty"`
}

type RelatedAttackPatternInfo struct {
	Nature  string `json:"nature"`
	CAPECID string `json:"capecId"`
}

type ExecutionStepInfo struct {
	Step        string   `json:"step"`
	Phase       string   `json:"phase"`
	Description string   `json:"description"`
	Techniques  []string `json:"techniques"`
}

type SkillInfo struct {
	Level   string `json:"level"`
	Details string `json:"details"`
}

type ConsequenceInfo struct {
	Scopes  []string `json:"scopes"`
	Impacts []string `json:"impacts"`
}

func processCAPEC() error {
	// 1. Download and Unzip
	resp, err := http.Get(CAPECZipURL)
	if err != nil {
		return fmt.Errorf("failed to GET CAPEC ZIP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code downloading CAPEC: %d", resp.StatusCode)
	}

	zipFilePath := "capec_latest.zip"
	outZip, err := os.Create(zipFilePath)
	if err != nil {
		return fmt.Errorf("unable to create CAPEC ZIP file: %w", err)
	}
	if _, err := io.Copy(outZip, resp.Body); err != nil {
		outZip.Close()
		return fmt.Errorf("error writing CAPEC ZIP file: %w", err)
	}
	outZip.Close()

	xmlFilename, err := unzipAndFind(zipFilePath, `capec_v\d+\.\d+\.xml`)
	if err != nil {
		os.Remove(zipFilePath)
		return fmt.Errorf("failed to unzip CAPEC: %w", err)
	}
	os.Remove(zipFilePath)

	// 2. Parse XML into the comprehensive structs
	xmlData, err := ioutil.ReadFile(xmlFilename)
	if err != nil {
		os.Remove(xmlFilename)
		return fmt.Errorf("failed to read extracted CAPEC XML: %w", err)
	}

	var catalog CAPECCatalog
	if err := xml.Unmarshal(xmlData, &catalog); err != nil {
		os.Remove(xmlFilename)
		return fmt.Errorf("error unmarshaling CAPEC XML: %w", err)
	}
	os.Remove(xmlFilename)

	// 3. Build the detailed JSON structure from parsed XML
	results := make(map[string]CAPECInfo, len(catalog.AttackPatterns))

	for _, pattern := range catalog.AttackPatterns {
		// --- Convert Mitre ATT&CK Techniques ---
		var mitreAttackIDs []string
		if pattern.TaxonomyMappings != nil {
			for _, mapping := range pattern.TaxonomyMappings.Mappings {
				if mapping.TaxonomyName == "ATTACK" && mapping.EntryID != "" {
					mitreAttackIDs = append(mitreAttackIDs, "T"+mapping.EntryID)
				}
			}
		}

		// --- Convert Related Attack Patterns ---
		var relatedPatterns []RelatedAttackPatternInfo
		if pattern.RelatedAttackPatterns != nil {
			for _, p := range pattern.RelatedAttackPatterns.Patterns {
				relatedPatterns = append(relatedPatterns, RelatedAttackPatternInfo{
					Nature:  p.Nature,
					CAPECID: p.CAPECID,
				})
			}
		}

		// --- Convert Execution Flow ---
		var executionFlow []ExecutionStepInfo
		if pattern.ExecutionFlow != nil {
			for _, step := range pattern.ExecutionFlow.Steps {
				executionFlow = append(executionFlow, ExecutionStepInfo{
					Step:        step.Step,
					Phase:       step.Phase,
					Description: step.Description,
					Techniques:  step.Techniques,
				})
			}
		}

		// --- Convert Skills Required ---
		var skills []SkillInfo
		if pattern.SkillsRequired != nil {
			for _, skill := range pattern.SkillsRequired.Skills {
				skills = append(skills, SkillInfo{
					Level:   skill.Level,
					Details: strings.TrimSpace(skill.Content),
				})
			}
		}

		// --- Convert Consequences ---
		var consequences []ConsequenceInfo
		if pattern.Consequences != nil {
			for _, con := range pattern.Consequences.Items {
				consequences = append(consequences, ConsequenceInfo{
					Scopes:  con.Scopes,
					Impacts: con.Impacts,
				})
			}
		}

		// --- Convert Related Weaknesses ---
		var relatedWeaknesses []string
		if pattern.RelatedWeaknesses != nil {
			for _, w := range pattern.RelatedWeaknesses.Weaknesses {
				if w.CWEID != "" {
					relatedWeaknesses = append(relatedWeaknesses, w.CWEID)
				}
			}
		}

		// --- Convert Prerequisites ---
		var prerequisites []string
		if pattern.Prerequisites != nil {
			prerequisites = pattern.Prerequisites.Items
		}

		// --- Assemble final CAPECInfo object ---
		info := CAPECInfo{
			Name:                  pattern.Name,
			Description:           pattern.Description,
			LikelihoodOfAttack:    pattern.LikelihoodOfAttack,
			TypicalSeverity:       pattern.TypicalSeverity,
			RelatedAttackPatterns: relatedPatterns,
			ExecutionFlow:         executionFlow,
			Prerequisites:         prerequisites,
			SkillsRequired:        skills,
			Consequences:          consequences,
			RelatedWeaknesses:     relatedWeaknesses,
			MitreAttack:           mitreAttackIDs,
		}

		results[pattern.ID] = info
	}

	// 4. Write final JSON to file
	outFile, err := os.Create(CAPECJSONPath)
	if err != nil {
		return fmt.Errorf("unable to create CAPEC JSON file: %w", err)
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		return fmt.Errorf("error writing CAPEC JSON: %w", err)
	}

	return nil
}

// -------------------- Techniques Processing --------------------

func processTechniques() error {
	combined := make(map[string][]string)

	// Enterprise
	if entMap, err := downloadTechSheet(EnterpriseTechniquesX, EnterpriseColumnIdx); err != nil {
		return fmt.Errorf("enterprise techniques download error: %w", err)
	} else {
		for k, v := range entMap {
			combined[k] = v
		}
	}

	// Mobile
	if mobMap, err := downloadTechSheet(MobileTechniquesX, MobileColumnIdx); err != nil {
		return fmt.Errorf("mobile techniques download error: %w", err)
	} else {
		for k, v := range mobMap {
			combined[k] = v
		}
	}

	// ICS
	if icsMap, err := downloadTechSheet(ICSTechniquesX, ICSColumnIdx); err != nil {
		return fmt.Errorf("ICS techniques download error: %w", err)
	} else {
		for k, v := range icsMap {
			combined[k] = v
		}
	}

	// Write to JSON
	outFile, err := os.Create(TechniquesJSONPath)
	if err != nil {
		return fmt.Errorf("unable to create techniques JSON file: %w", err)
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(combined); err != nil {
		return fmt.Errorf("error writing techniques JSON: %w", err)
	}

	return nil
}

func downloadTechSheet(url string, colIdx int) (map[string][]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET error: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d while downloading %s", resp.StatusCode, url)
	}

	// Open the XLSX directly from the response body
	f, err := excelize.OpenReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to open XLSX from %s: %w", url, err)
	}
	defer f.Close()

	// Use the first sheet
	sheets := f.GetSheetList()
	if len(sheets) == 0 {
		return nil, fmt.Errorf("no sheets found in XLSX %s", url)
	}
	sheetName := sheets[0]

	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, fmt.Errorf("failed to get rows from sheet %s: %w", sheetName, err)
	}

	result := make(map[string][]string)
	// Skip header row (index 0), iterate data rows
	for i := 1; i < len(rows); i++ {
		row := rows[i]
		if len(row) == 0 {
			continue
		}
		techID := strings.TrimSpace(row[0])
		if techID == "" {
			continue
		}
		if colIdx >= len(row) {
			// No data in that column for this row
			result[techID] = []string{}
			continue
		}
		cell := strings.TrimSpace(row[colIdx])
		if cell == "" {
			result[techID] = []string{}
			continue
		}
		parts := strings.Split(cell, ",")
		for j := range parts {
			parts[j] = strings.TrimSpace(parts[j])
		}
		result[techID] = parts
	}

	return result, nil
}
