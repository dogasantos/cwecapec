package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// CWE XML structures
type WeaknessCatalog struct {
	XMLName    xml.Name   `xml:"Weakness_Catalog"`
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"`
	Categories []Category `xml:"Categories>Category"`
}

type Weakness struct {
	ID                string         `xml:"ID,attr"`
	Name              string         `xml:"Name,attr"`
	Abstraction       string         `xml:"Abstraction,attr"`
	Description       string         `xml:"Description"`
	RelatedWeaknesses []Relationship `xml:"Related_Weaknesses>Related_Weakness"`
}

type Category struct {
	ID            string         `xml:"ID,attr"`
	Name          string         `xml:"Name,attr"`
	Relationships []Relationship `xml:"Relationships>Has_Member"`
}

type Relationship struct {
	Nature string `xml:"Nature,attr"`
	CWEID  string `xml:"CWE_ID,attr"`
	ViewID string `xml:"View_ID,attr"`
}

// Output structures
type CWEInfo struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Abstraction   string   `json:"abstraction"`
	Parents       []string `json:"parents"`        // Direct parents (ChildOf)
	Children      []string `json:"children"`       // Direct children (ParentOf)
	AttackVectors []string `json:"attack_vectors"` // Mapped attack vectors
}

type CWEHierarchy struct {
	CWEs                map[string]*CWEInfo `json:"cwes"`
	AttackVectorMapping map[string][]string `json:"attack_vector_mapping"` // CWE ID -> attack vectors
}

// CWE to Attack Vector mapping
var cweToAttackVector = map[string][]string{
	// Injection family
	"74":   {"injection"},                     // Injection (parent)
	"77":   {"command_injection"},             // Command Injection
	"78":   {"command_injection"},             // OS Command Injection
	"79":   {"xss"},                           // Cross-Site Scripting
	"89":   {"sql_injection"},                 // SQL Injection
	"90":   {"ldap_injection"},                // LDAP Injection
	"91":   {"xml_injection", "xxe"},          // XML Injection
	"93":   {"crlf_injection", "http_desync"}, // CRLF Injection
	"94":   {"code_injection", "rce"},         // Code Injection
	"95":   {"code_injection", "rce"},         // Eval Injection
	"96":   {"code_injection"},                // Static Code Injection
	"98":   {"file_upload", "rce"},            // PHP File Inclusion
	"99":   {"rce"},                           // Resource Injection
	"113":  {"http_desync"},                   // HTTP Response Splitting
	"917":  {"jndi_injection", "rce"},         // Expression Language Injection
	"943":  {"nosql_injection"},               // NoSQL Injection
	"1336": {"ssti"},                          // Template Injection

	// Path Traversal
	"22": {"path_traversal"}, // Path Traversal
	"23": {"path_traversal"}, // Relative Path Traversal
	"36": {"path_traversal"}, // Absolute Path Traversal
	"73": {"path_traversal"}, // External Control of File Name

	// Authentication & Authorization
	"287": {"auth_bypass"},                     // Improper Authentication
	"288": {"auth_bypass"},                     // Authentication Bypass
	"290": {"auth_bypass"},                     // Authentication Bypass by Spoofing
	"294": {"auth_bypass", "session_fixation"}, // Authentication Bypass by Capture-replay
	"295": {"auth_bypass", "crypto_failure"},   // Improper Certificate Validation
	"306": {"auth_bypass"},                     // Missing Authentication
	"307": {"auth_bypass"},                     // Improper Restriction of Excessive Authentication Attempts
	"285": {"authz_bypass"},                    // Improper Authorization
	"284": {"authz_bypass"},                    // Improper Access Control
	"862": {"authz_bypass"},                    // Missing Authorization
	"639": {"authz_bypass"},                    // Authorization Bypass Through User-Controlled Key
	"425": {"authz_bypass"},                    // Direct Request
	"863": {"idor"},                            // Incorrect Authorization

	// CSRF & Session
	"352": {"csrf"},             // Cross-Site Request Forgery
	"346": {"csrf"},             // Origin Validation Error
	"384": {"session_fixation"}, // Session Fixation
	"472": {"session_fixation"}, // External Control of Assumed-Immutable Web Parameter
	"613": {"session_fixation"}, // Insufficient Session Expiration

	// Information Disclosure
	"200": {"info_disclosure"}, // Exposure of Sensitive Information
	"201": {"info_disclosure"}, // Insertion of Sensitive Information Into Sent Data
	"209": {"info_disclosure"}, // Generation of Error Message Containing Sensitive Information
	"213": {"info_disclosure"}, // Exposure of Sensitive Information Due to Incompatible Policies
	"215": {"info_disclosure"}, // Insertion of Sensitive Information Into Debugging Code
	"359": {"info_disclosure"}, // Exposure of Private Personal Information
	"532": {"info_disclosure"}, // Insertion of Sensitive Information into Log File
	"538": {"info_disclosure"}, // Insertion of Sensitive Information into Externally-Accessible File

	// Deserialization
	"502": {"deserialization", "rce"}, // Deserialization of Untrusted Data

	// File Upload
	"434": {"file_upload", "rce"}, // Unrestricted Upload of File with Dangerous Type
	"616": {"file_upload"},        // Incomplete Identification of Uploaded File Variables

	// SSRF
	"918": {"ssrf"}, // Server-Side Request Forgery

	// XXE
	"611": {"xxe"}, // Improper Restriction of XML External Entity Reference
	"827": {"xxe"}, // Improper Control of Document Type Definition

	// Open Redirect
	"601": {"open_redirect"}, // URL Redirection to Untrusted Site

	// Cryptographic Failures
	"327": {"crypto_failure"},        // Use of a Broken or Risky Cryptographic Algorithm
	"328": {"crypto_failure"},        // Use of Weak Hash
	"330": {"crypto_failure"},        // Use of Insufficiently Random Values
	"331": {"crypto_failure"},        // Insufficient Entropy
	"326": {"crypto_failure"},        // Inadequate Encryption Strength
	"321": {"hardcoded_credentials"}, // Use of Hard-coded Cryptographic Key

	// Hard-coded Credentials
	"259": {"hardcoded_credentials"}, // Use of Hard-coded Password
	"798": {"hardcoded_credentials"}, // Use of Hard-coded Credentials

	// Buffer Overflow
	"119": {"buffer_overflow", "rce"}, // Improper Restriction of Operations within the Bounds of a Memory Buffer
	"120": {"buffer_overflow"},        // Buffer Copy without Checking Size of Input
	"121": {"buffer_overflow"},        // Stack-based Buffer Overflow
	"122": {"buffer_overflow"},        // Heap-based Buffer Overflow
	"125": {"buffer_overflow"},        // Out-of-bounds Read
	"787": {"buffer_overflow", "rce"}, // Out-of-bounds Write

	// Integer Overflow
	"190": {"integer_overflow"}, // Integer Overflow or Wraparound
	"191": {"integer_overflow"}, // Integer Underflow

	// Use After Free
	"416": {"use_after_free", "rce"}, // Use After Free
	"415": {"use_after_free"},        // Double Free

	// NULL Pointer
	"476": {"null_pointer"}, // NULL Pointer Dereference
	"690": {"null_pointer"}, // Unchecked Return Value to NULL Pointer Dereference

	// Format String
	"134": {"format_string", "rce"}, // Use of Externally-Controlled Format String

	// Race Condition
	"362": {"race_condition"}, // Concurrent Execution using Shared Resource with Improper Synchronization
	"366": {"race_condition"}, // Race Condition within a Thread
	"367": {"race_condition"}, // Time-of-check Time-of-use (TOCTOU) Race Condition

	// DoS
	"400": {"dos"}, // Uncontrolled Resource Consumption
	"770": {"dos"}, // Allocation of Resources Without Limits or Throttling
	"835": {"dos"}, // Loop with Unreachable Exit Condition
	"674": {"dos"}, // Uncontrolled Recursion
	"404": {"dos"}, // Improper Resource Shutdown or Release

	// Privilege Escalation
	"269": {"privilege_escalation"}, // Improper Privilege Management
	"250": {"privilege_escalation"}, // Execution with Unnecessary Privileges
	"266": {"privilege_escalation"}, // Incorrect Privilege Assignment
	"268": {"privilege_escalation"}, // Privilege Chaining
	"274": {"privilege_escalation"}, // Improper Handling of Insufficient Privileges

	// Input Validation (generic)
	"20":   {"input_validation"}, // Improper Input Validation
	"129":  {"input_validation"}, // Improper Validation of Array Index
	"1284": {"input_validation"}, // Improper Validation of Specified Quantity in Input
}

func main() {
	fmt.Println("=================================================================")
	fmt.Println("CWE Hierarchy Builder")
	fmt.Println("=================================================================\n")

	// Download CWE XML
	fmt.Println("Downloading CWE XML from MITRE...")
	cweXML, err := downloadCWEXML()
	if err != nil {
		fmt.Printf("Error downloading CWE XML: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Downloaded successfully\n")

	// Parse CWE XML
	fmt.Println("Parsing CWE XML...")
	catalog, err := parseCWEXML(cweXML)
	if err != nil {
		fmt.Printf("Error parsing CWE XML: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Parsed %d weaknesses\n\n", len(catalog.Weaknesses))

	// Build hierarchy
	fmt.Println("Building CWE hierarchy...")
	hierarchy := buildHierarchy(catalog)
	fmt.Printf("Built hierarchy for %d CWEs\n\n", len(hierarchy.CWEs))

	// Save to JSON
	outputFile := "resources/cwe_hierarchy.json"
	fmt.Printf("Saving hierarchy to: %s\n", outputFile)
	if err := saveHierarchy(hierarchy, outputFile); err != nil {
		fmt.Printf("Error saving hierarchy: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Hierarchy saved successfully!")

	// Statistics
	fmt.Println("\n=================================================================")
	fmt.Println("Statistics:")
	fmt.Println("=================================================================")
	fmt.Printf("  Total CWEs: %d\n", len(hierarchy.CWEs))

	mappedCount := 0
	for _, cwe := range hierarchy.CWEs {
		if len(cwe.AttackVectors) > 0 {
			mappedCount++
		}
	}
	fmt.Printf("  CWEs with attack vector mappings: %d\n", mappedCount)
	fmt.Printf("  Attack vector mapping coverage: %.1f%%\n", float64(mappedCount)/float64(len(hierarchy.CWEs))*100)

	fmt.Println("\nCWE Hierarchy Builder complete!")
}

func downloadCWEXML() ([]byte, error) {
	url := "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Read ZIP file
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Open ZIP
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	// Find and extract XML file
	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, ".xml") {
			rc, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()

			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("no XML file found in ZIP")
}

func parseCWEXML(data []byte) (*WeaknessCatalog, error) {
	var catalog WeaknessCatalog
	if err := xml.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}
	return &catalog, nil
}

func buildHierarchy(catalog *WeaknessCatalog) *CWEHierarchy {
	hierarchy := &CWEHierarchy{
		CWEs:                make(map[string]*CWEInfo),
		AttackVectorMapping: make(map[string][]string),
	}

	// First pass: create all CWE entries
	for _, weakness := range catalog.Weaknesses {
		cweInfo := &CWEInfo{
			ID:            weakness.ID,
			Name:          weakness.Name,
			Abstraction:   weakness.Abstraction,
			Parents:       []string{},
			Children:      []string{},
			AttackVectors: []string{},
		}

		// Map to attack vectors if available
		if vectors, exists := cweToAttackVector[weakness.ID]; exists {
			cweInfo.AttackVectors = vectors
			hierarchy.AttackVectorMapping[weakness.ID] = vectors
		}

		hierarchy.CWEs[weakness.ID] = cweInfo
	}

	// Second pass: build relationships
	for _, weakness := range catalog.Weaknesses {
		cweInfo := hierarchy.CWEs[weakness.ID]

		for _, rel := range weakness.RelatedWeaknesses {
			if rel.Nature == "ChildOf" {
				// This CWE is a child of rel.CWEID
				cweInfo.Parents = append(cweInfo.Parents, rel.CWEID)

				// Add this CWE as a child of the parent
				if parent, exists := hierarchy.CWEs[rel.CWEID]; exists {
					parent.Children = append(parent.Children, weakness.ID)
				}
			}
		}
	}

	return hierarchy
}

func saveHierarchy(hierarchy *CWEHierarchy, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(hierarchy)
}
