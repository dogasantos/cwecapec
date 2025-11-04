package main

import (
	"archive/zip"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Constants and file paths
const (
	// CWE
	CWEZipURL   = "http://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
	CWEJSONPath = "resources/cwe_db.json"

	// CAPEC
	CAPECZipURL   = "https://capec.mitre.org/data/archive/capec_latest.zip"
	CAPECJSONPath = "resources/capec_db.json"

	// MITRE ATT&CK STIX 2.1 (version-agnostic URLs)
	EnterpriseAttackURL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
	MobileAttackURL     = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json"
	ICSAttackURL        = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json"

	// Output paths
	TechniquesJSONPath    = "resources/attack_techniques_db.json"
	GroupsJSONPath        = "resources/attack_groups_db.json"
	SoftwareJSONPath      = "resources/attack_software_db.json"
	MitigationsJSONPath   = "resources/attack_mitigations_db.json"
	RelationshipsJSONPath = "resources/relationships_db.json"
	MetadataJSONPath      = "resources/metadata.json"
)

func main() {
	// Ensure the "resources" directory exists
	if err := os.MkdirAll("resources", 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating resources directory: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[1/4] Downloading and processing CWE...")
	cweData, err := processCWE()
	if err != nil {
		fmt.Fprintf(os.Stderr, "CWE processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[2/4] Downloading and processing CAPEC...")
	capecData, err := processCAPEC()
	if err != nil {
		fmt.Fprintf(os.Stderr, "CAPEC processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[3/4] Downloading and processing MITRE ATT&CK...")
	attackData, err := processAttack()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ATT&CK processing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("[4/4] Building relationship mappings...")
	if err := buildRelationships(cweData, capecData, attackData); err != nil {
		fmt.Fprintf(os.Stderr, "Relationship building failed: %v\n", err)
		os.Exit(1)
	}

	// Write metadata
	if err := writeMetadata(); err != nil {
		fmt.Fprintf(os.Stderr, "Metadata writing failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("✓ All data successfully updated in resources/*.json")
}

// -------------------- CWE Processing --------------------

type CWECatalog struct {
	XMLName    xml.Name   `xml:"Weakness_Catalog"`
	Version    string     `xml:"Version,attr"`
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"`
}

type Weakness struct {
	ID                    string                      `xml:"ID,attr"`
	Name                  string                      `xml:"Name,attr"`
	RelatedWeaknesses     *RelatedWeaknessesBlock     `xml:"Related_Weaknesses"`
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

type CWEInfo struct {
	Name                  string   `json:"name"`
	ChildOf               []string `json:"childOf"`
	RelatedAttackPatterns []string `json:"relatedAttackPatterns"`
}

type CWEData struct {
	Version string             `json:"-"`
	CWEs    map[string]CWEInfo `json:"-"`
}

func processCWE() (*CWEData, error) {
	// Download ZIP
	resp, err := httpGet(CWEZipURL)
	if err != nil {
		return nil, fmt.Errorf("failed to GET CWE ZIP: %w", err)
	}
	defer resp.Body.Close()

	zipFilePath := "cwec_latest.xml.zip"
	if err := downloadFile(zipFilePath, resp.Body); err != nil {
		return nil, err
	}
	defer os.Remove(zipFilePath)

	// Unzip and find XML
	xmlFilename, err := unzipAndFind(zipFilePath, `cwec_v\d+\.\d+\.xml`)
	if err != nil {
		return nil, fmt.Errorf("failed to unzip CWE: %w", err)
	}
	defer os.Remove(xmlFilename)

	// Parse XML
	xmlData, err := os.ReadFile(xmlFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read extracted CWE XML: %w", err)
	}

	var catalog CWECatalog
	if err := xml.Unmarshal(xmlData, &catalog); err != nil {
		return nil, fmt.Errorf("error unmarshaling CWE XML: %w", err)
	}

	// Build JSON structure
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

		results[w.ID] = CWEInfo{
			Name:                  w.Name,
			ChildOf:               setToSlice(childSet),
			RelatedAttackPatterns: setToSlice(attackSet),
		}
	}

	// Write JSON to file
	if err := writeJSON(CWEJSONPath, results); err != nil {
		return nil, err
	}

	return &CWEData{Version: catalog.Version, CWEs: results}, nil
}

// -------------------- CAPEC Processing --------------------

type CAPECCatalog struct {
	XMLName        xml.Name       `xml:"Attack_Pattern_Catalog"`
	Version        string         `xml:"Version,attr"`
	AttackPatterns []CAPECPattern `xml:"Attack_Patterns>Attack_Pattern"`
}

type CAPECPattern struct {
	ID                    string                    `xml:"ID,attr"`
	Name                  string                    `xml:"Name,attr"`
	Description           string                    `xml:"Description"`
	LikelihoodOfAttack    string                    `xml:"Likelihood_Of_Attack"`
	TypicalSeverity       string                    `xml:"Typical_Severity"`
	RelatedAttackPatterns *XMLRelatedAttackPatterns `xml:"Related_Attack_Patterns"`
	ExecutionFlow         *XMLExecutionFlow         `xml:"Execution_Flow"`
	Prerequisites         *XMLPrerequisites         `xml:"Prerequisites"`
	SkillsRequired        *XMLSkillsRequired        `xml:"Skills_Required"`
	Consequences          *XMLConsequences          `xml:"Consequences"`
	RelatedWeaknesses     *XMLRelatedWeaknesses     `xml:"Related_Weaknesses"`
	TaxonomyMappings      *XMLTaxonomyMappings      `xml:"Taxonomy_Mappings"`
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

type CAPECInfo struct {
	Name                  string                     `json:"name"`
	Description           string                     `json:"description,omitempty"`
	LikelihoodOfAttack    string                     `json:"likelihoodOfAttack,omitempty"`
	TypicalSeverity       string                     `json:"typicalSeverity,omitempty"`
	RelatedAttackPatterns []RelatedAttackPatternInfo `json:"relatedAttackPatterns,omitempty"`
	ExecutionFlow         []ExecutionStepInfo        `json:"executionFlow,omitempty"`
	Prerequisites         []string                   `json:"prerequisites,omitempty"`
	SkillsRequired        []SkillInfo                `json:"skillsRequired,omitempty"`
	Consequences          []ConsequenceInfo          `json:"consequences,omitempty"`
	RelatedWeaknesses     []string                   `json:"relatedWeaknesses,omitempty"`
	MitreAttack           []string                   `json:"mitreAttack,omitempty"`
}

type RelatedAttackPatternInfo struct {
	Nature  string `json:"nature"`
	CAPECID string `json:"capecId"`
}

type ExecutionStepInfo struct {
	Step        string   `json:"step"`
	Phase       string   `json:"phase"`
	Description string   `json:"description"`
	Techniques  []string `json:"techniques,omitempty"`
}

type SkillInfo struct {
	Level       string `json:"level"`
	Description string `json:"description"`
}

type ConsequenceInfo struct {
	Scopes  []string `json:"scopes"`
	Impacts []string `json:"impacts"`
}

type CAPECData struct {
	Version string               `json:"-"`
	CAPECs  map[string]CAPECInfo `json:"-"`
}

func processCAPEC() (*CAPECData, error) {
	// Download ZIP
	resp, err := httpGet(CAPECZipURL)
	if err != nil {
		return nil, fmt.Errorf("failed to GET CAPEC ZIP: %w", err)
	}
	defer resp.Body.Close()

	zipFilePath := "capec_latest.zip"
	if err := downloadFile(zipFilePath, resp.Body); err != nil {
		return nil, err
	}
	defer os.Remove(zipFilePath)

	// Unzip and find XML
	xmlFilename, err := unzipAndFind(zipFilePath, `capec_v\d+\.\d+\.xml`)
	if err != nil {
		return nil, fmt.Errorf("failed to unzip CAPEC: %w", err)
	}
	defer os.Remove(xmlFilename)

	// Parse XML
	xmlData, err := os.ReadFile(xmlFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read extracted CAPEC XML: %w", err)
	}

	var catalog CAPECCatalog
	if err := xml.Unmarshal(xmlData, &catalog); err != nil {
		return nil, fmt.Errorf("error unmarshaling CAPEC XML: %w", err)
	}

	// Build JSON structure
	results := make(map[string]CAPECInfo, len(catalog.AttackPatterns))

	for _, p := range catalog.AttackPatterns {
		info := CAPECInfo{
			Name:               p.Name,
			Description:        cleanText(p.Description),
			LikelihoodOfAttack: p.LikelihoodOfAttack,
			TypicalSeverity:    p.TypicalSeverity,
		}

		// Related attack patterns
		if p.RelatedAttackPatterns != nil {
			for _, rap := range p.RelatedAttackPatterns.Patterns {
				info.RelatedAttackPatterns = append(info.RelatedAttackPatterns, RelatedAttackPatternInfo{
					Nature:  rap.Nature,
					CAPECID: rap.CAPECID,
				})
			}
		}

		// Execution flow
		if p.ExecutionFlow != nil {
			for _, step := range p.ExecutionFlow.Steps {
				info.ExecutionFlow = append(info.ExecutionFlow, ExecutionStepInfo{
					Step:        step.Step,
					Phase:       step.Phase,
					Description: cleanText(step.Description),
					Techniques:  step.Techniques,
				})
			}
		}

		// Prerequisites
		if p.Prerequisites != nil {
			info.Prerequisites = p.Prerequisites.Items
		}

		// Skills required
		if p.SkillsRequired != nil {
			for _, skill := range p.SkillsRequired.Skills {
				info.SkillsRequired = append(info.SkillsRequired, SkillInfo{
					Level:       skill.Level,
					Description: cleanText(skill.Content),
				})
			}
		}

		// Consequences
		if p.Consequences != nil {
			for _, cons := range p.Consequences.Items {
				info.Consequences = append(info.Consequences, ConsequenceInfo{
					Scopes:  cons.Scopes,
					Impacts: cons.Impacts,
				})
			}
		}

		// Related weaknesses (CWE)
		if p.RelatedWeaknesses != nil {
			for _, rw := range p.RelatedWeaknesses.Weaknesses {
				info.RelatedWeaknesses = append(info.RelatedWeaknesses, rw.CWEID)
			}
		}

		// MITRE ATT&CK mappings
		if p.TaxonomyMappings != nil {
			for _, tm := range p.TaxonomyMappings.Mappings {
				// Check for "ATTACK" taxonomy (note: no & symbol)
				if tm.TaxonomyName == "ATTACK" || strings.Contains(tm.TaxonomyName, "ATT&CK") {
					// Convert Entry_ID to ATT&CK technique ID format (add T prefix)
					techID := "T" + tm.EntryID
					info.MitreAttack = append(info.MitreAttack, techID)
				}
			}
		}

		results[p.ID] = info
	}

	// Write JSON to file
	if err := writeJSON(CAPECJSONPath, results); err != nil {
		return nil, err
	}

	return &CAPECData{Version: catalog.Version, CAPECs: results}, nil
}

// -------------------- MITRE ATT&CK Processing (STIX 2.1) --------------------

type STIXBundle struct {
	Type    string       `json:"type"`
	ID      string       `json:"id"`
	Objects []STIXObject `json:"objects"`
}

type STIXObject struct {
	Type               string                 `json:"type"`
	ID                 string                 `json:"id"`
	Name               string                 `json:"name,omitempty"`
	Description        string                 `json:"description,omitempty"`
	ExternalReferences []ExternalReference    `json:"external_references,omitempty"`
	KillChainPhases    []KillChainPhase       `json:"kill_chain_phases,omitempty"`
	XMitrePlatforms    []string               `json:"x_mitre_platforms,omitempty"`
	XMitreTactics      []string               `json:"x_mitre_tactics,omitempty"`
	XMitreDataSources  []string               `json:"x_mitre_data_sources,omitempty"`
	XMitreShortName    string                 `json:"x_mitre_shortname,omitempty"`
	Aliases            []string               `json:"aliases,omitempty"`
	SourceRef          string                 `json:"source_ref,omitempty"`
	TargetRef          string                 `json:"target_ref,omitempty"`
	RelationshipType   string                 `json:"relationship_type,omitempty"`
	XMitreVersion      string                 `json:"x_mitre_version,omitempty"`
	RawData            map[string]interface{} `json:"-"`
}

type ExternalReference struct {
	SourceName  string `json:"source_name"`
	ExternalID  string `json:"external_id,omitempty"`
	URL         string `json:"url,omitempty"`
	Description string `json:"description,omitempty"`
}

type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

type TechniqueInfo struct {
	Name              string   `json:"name"`
	Description       string   `json:"description,omitempty"`
	Tactics           []string `json:"tactics,omitempty"`
	Platforms         []string `json:"platforms,omitempty"`
	DataSources       []string `json:"dataSources,omitempty"`
	Mitigations       []string `json:"mitigations,omitempty"`
	RelatedTechniques []string `json:"relatedTechniques,omitempty"`
	Groups            []string `json:"groups,omitempty"`
	Software          []string `json:"software,omitempty"`
	URL               string   `json:"url,omitempty"`
}

type GroupInfo struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases,omitempty"`
	Description string   `json:"description,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	Software    []string `json:"software,omitempty"`
	URL         string   `json:"url,omitempty"`
}

type SoftwareInfo struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	Groups      []string `json:"groups,omitempty"`
	URL         string   `json:"url,omitempty"`
}

type MitigationInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Techniques  []string `json:"techniques,omitempty"`
	URL         string   `json:"url,omitempty"`
}

type AttackData struct {
	Techniques  map[string]TechniqueInfo
	Groups      map[string]GroupInfo
	Software    map[string]SoftwareInfo
	Mitigations map[string]MitigationInfo
}

func processAttack() (*AttackData, error) {
	data := &AttackData{
		Techniques:  make(map[string]TechniqueInfo),
		Groups:      make(map[string]GroupInfo),
		Software:    make(map[string]SoftwareInfo),
		Mitigations: make(map[string]MitigationInfo),
	}

	// Process all three domains
	domains := []struct {
		name string
		url  string
	}{
		{"Enterprise", EnterpriseAttackURL},
		{"Mobile", MobileAttackURL},
		{"ICS", ICSAttackURL},
	}

	for _, domain := range domains {
		fmt.Printf("  - Processing %s ATT&CK...\n", domain.name)
		if err := processAttackDomain(domain.url, data); err != nil {
			return nil, fmt.Errorf("%s ATT&CK error: %w", domain.name, err)
		}
	}

	// Write output files
	if err := writeJSON(TechniquesJSONPath, data.Techniques); err != nil {
		return nil, err
	}
	if err := writeJSON(GroupsJSONPath, data.Groups); err != nil {
		return nil, err
	}
	if err := writeJSON(SoftwareJSONPath, data.Software); err != nil {
		return nil, err
	}
	if err := writeJSON(MitigationsJSONPath, data.Mitigations); err != nil {
		return nil, err
	}

	return data, nil
}

func processAttackDomain(url string, data *AttackData) error {
	// Download STIX bundle
	resp, err := httpGet(url)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	var bundle STIXBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return fmt.Errorf("failed to parse STIX JSON: %w", err)
	}

	// First pass: collect all objects
	objectMap := make(map[string]STIXObject)
	for _, obj := range bundle.Objects {
		objectMap[obj.ID] = obj
	}

	// Second pass: process objects and build relationships
	relationships := []STIXObject{}

	for _, obj := range bundle.Objects {
		switch obj.Type {
		case "attack-pattern":
			processTechnique(obj, data)
		case "intrusion-set":
			processGroup(obj, data)
		case "malware", "tool":
			processSoftware(obj, data)
		case "course-of-action":
			processMitigation(obj, data)
		case "relationship":
			relationships = append(relationships, obj)
		}
	}

	// Third pass: apply relationships
	for _, rel := range relationships {
		applyRelationship(rel, data, objectMap)
	}

	return nil
}

func processTechnique(obj STIXObject, data *AttackData) {
	extID := getExternalID(obj.ExternalReferences)
	if extID == "" {
		return
	}

	tactics := []string{}
	for _, kcp := range obj.KillChainPhases {
		tactics = append(tactics, kcp.PhaseName)
	}

	url := getURL(obj.ExternalReferences)

	if existing, ok := data.Techniques[extID]; ok {
		// Merge data from multiple domains
		existing.Tactics = mergeUnique(existing.Tactics, tactics)
		existing.Platforms = mergeUnique(existing.Platforms, obj.XMitrePlatforms)
		existing.DataSources = mergeUnique(existing.DataSources, obj.XMitreDataSources)
		data.Techniques[extID] = existing
	} else {
		data.Techniques[extID] = TechniqueInfo{
			Name:        obj.Name,
			Description: cleanText(obj.Description),
			Tactics:     tactics,
			Platforms:   obj.XMitrePlatforms,
			DataSources: obj.XMitreDataSources,
			URL:         url,
		}
	}
}

func processGroup(obj STIXObject, data *AttackData) {
	extID := getExternalID(obj.ExternalReferences)
	if extID == "" {
		return
	}

	url := getURL(obj.ExternalReferences)

	if _, ok := data.Groups[extID]; !ok {
		data.Groups[extID] = GroupInfo{
			Name:        obj.Name,
			Aliases:     obj.Aliases,
			Description: cleanText(obj.Description),
			URL:         url,
		}
	}
}

func processSoftware(obj STIXObject, data *AttackData) {
	extID := getExternalID(obj.ExternalReferences)
	if extID == "" {
		return
	}

	url := getURL(obj.ExternalReferences)

	if _, ok := data.Software[extID]; !ok {
		data.Software[extID] = SoftwareInfo{
			Name:        obj.Name,
			Type:        obj.Type,
			Description: cleanText(obj.Description),
			URL:         url,
		}
	}
}

func processMitigation(obj STIXObject, data *AttackData) {
	extID := getExternalID(obj.ExternalReferences)
	if extID == "" {
		return
	}

	url := getURL(obj.ExternalReferences)

	if _, ok := data.Mitigations[extID]; !ok {
		data.Mitigations[extID] = MitigationInfo{
			Name:        obj.Name,
			Description: cleanText(obj.Description),
			URL:         url,
		}
	}
}

func applyRelationship(rel STIXObject, data *AttackData, objectMap map[string]STIXObject) {
	sourceObj, sourceOK := objectMap[rel.SourceRef]
	targetObj, targetOK := objectMap[rel.TargetRef]

	if !sourceOK || !targetOK {
		return
	}

	sourceID := getExternalID(sourceObj.ExternalReferences)
	targetID := getExternalID(targetObj.ExternalReferences)

	if sourceID == "" || targetID == "" {
		return
	}

	switch rel.RelationshipType {
	case "uses":
		if sourceObj.Type == "intrusion-set" && targetObj.Type == "attack-pattern" {
			// Group uses technique
			if group, ok := data.Groups[sourceID]; ok {
				group.Techniques = appendUnique(group.Techniques, targetID)
				data.Groups[sourceID] = group
			}
			if tech, ok := data.Techniques[targetID]; ok {
				tech.Groups = appendUnique(tech.Groups, sourceID)
				data.Techniques[targetID] = tech
			}
		} else if sourceObj.Type == "intrusion-set" && (targetObj.Type == "malware" || targetObj.Type == "tool") {
			// Group uses software
			if group, ok := data.Groups[sourceID]; ok {
				group.Software = appendUnique(group.Software, targetID)
				data.Groups[sourceID] = group
			}
			if soft, ok := data.Software[targetID]; ok {
				soft.Groups = appendUnique(soft.Groups, sourceID)
				data.Software[targetID] = soft
			}
		} else if (sourceObj.Type == "malware" || sourceObj.Type == "tool") && targetObj.Type == "attack-pattern" {
			// Software uses technique
			if soft, ok := data.Software[sourceID]; ok {
				soft.Techniques = appendUnique(soft.Techniques, targetID)
				data.Software[sourceID] = soft
			}
			if tech, ok := data.Techniques[targetID]; ok {
				tech.Software = appendUnique(tech.Software, sourceID)
				data.Techniques[targetID] = tech
			}
		}
	case "mitigates":
		if sourceObj.Type == "course-of-action" && targetObj.Type == "attack-pattern" {
			// Mitigation mitigates technique
			if mit, ok := data.Mitigations[sourceID]; ok {
				mit.Techniques = appendUnique(mit.Techniques, targetID)
				data.Mitigations[sourceID] = mit
			}
			if tech, ok := data.Techniques[targetID]; ok {
				tech.Mitigations = appendUnique(tech.Mitigations, sourceID)
				data.Techniques[targetID] = tech
			}
		}
	case "subtechnique-of":
		if sourceObj.Type == "attack-pattern" && targetObj.Type == "attack-pattern" {
			// Technique is subtechnique of another
			if tech, ok := data.Techniques[sourceID]; ok {
				tech.RelatedTechniques = appendUnique(tech.RelatedTechniques, targetID)
				data.Techniques[sourceID] = tech
			}
		}
	}
}

// -------------------- Relationship Building --------------------

type RelationshipsDB struct {
	CWEToCapec    map[string][]string `json:"cwe_to_capec"`
	CapecToCWE    map[string][]string `json:"capec_to_cwe"`
	CapecToAttack map[string][]string `json:"capec_to_attack"`
	AttackToCapec map[string][]string `json:"attack_to_capec"`
}

func buildRelationships(cweData *CWEData, capecData *CAPECData, attackData *AttackData) error {
	db := RelationshipsDB{
		CWEToCapec:    make(map[string][]string),
		CapecToCWE:    make(map[string][]string),
		CapecToAttack: make(map[string][]string),
		AttackToCapec: make(map[string][]string),
	}

	// Build CWE → CAPEC mapping
	for cweID, cweInfo := range cweData.CWEs {
		if len(cweInfo.RelatedAttackPatterns) > 0 {
			db.CWEToCapec[cweID] = cweInfo.RelatedAttackPatterns
		}
	}

	// Build CAPEC → CWE and CAPEC → ATT&CK mappings
	for capecID, capecInfo := range capecData.CAPECs {
		if len(capecInfo.RelatedWeaknesses) > 0 {
			db.CapecToCWE[capecID] = capecInfo.RelatedWeaknesses
		}
		if len(capecInfo.MitreAttack) > 0 {
			db.CapecToAttack[capecID] = capecInfo.MitreAttack
			// Build reverse mapping
			for _, techID := range capecInfo.MitreAttack {
				db.AttackToCapec[techID] = appendUnique(db.AttackToCapec[techID], capecID)
			}
		}
	}

	return writeJSON(RelationshipsJSONPath, db)
}

// -------------------- Metadata --------------------

type Metadata struct {
	UpdatedAt    string `json:"updated_at"`
	CWEVersion   string `json:"cwe_version,omitempty"`
	CAPECVersion string `json:"capec_version,omitempty"`
}

func writeMetadata() error {
	meta := Metadata{
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	return writeJSON(MetadataJSONPath, meta)
}

// -------------------- Utility Functions --------------------

func httpGet(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status code %d for %s", resp.StatusCode, url)
	}
	return resp, nil
}

func downloadFile(filepath string, body io.Reader) error {
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("unable to create file: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, body); err != nil {
		return fmt.Errorf("error writing file: %w", err)
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

func writeJSON(filepath string, data interface{}) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("unable to create JSON file %s: %w", filepath, err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return fmt.Errorf("error writing JSON to %s: %w", filepath, err)
	}
	return nil
}

func cleanText(s string) string {
	// Remove excessive whitespace
	s = strings.TrimSpace(s)
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	return s
}

func setToSlice(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	slice := make([]string, 0, len(set))
	for k := range set {
		slice = append(slice, k)
	}
	return slice
}

func appendUnique(slice []string, item string) []string {
	for _, existing := range slice {
		if existing == item {
			return slice
		}
	}
	return append(slice, item)
}

func mergeUnique(slice1, slice2 []string) []string {
	result := make([]string, len(slice1))
	copy(result, slice1)
	for _, item := range slice2 {
		found := false
		for _, existing := range result {
			if existing == item {
				found = true
				break
			}
		}
		if !found {
			result = append(result, item)
		}
	}
	return result
}

func getExternalID(refs []ExternalReference) string {
	for _, ref := range refs {
		if ref.SourceName == "mitre-attack" || ref.SourceName == "capec" || ref.SourceName == "cwe" {
			if ref.ExternalID != "" {
				return ref.ExternalID
			}
		}
	}
	return ""
}

func getURL(refs []ExternalReference) string {
	for _, ref := range refs {
		if ref.SourceName == "mitre-attack" || ref.SourceName == "capec" || ref.SourceName == "cwe" {
			if ref.URL != "" {
				return ref.URL
			}
		}
	}
	return ""
}
