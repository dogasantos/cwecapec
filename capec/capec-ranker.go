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

// CAPEC training data structure
type CAPECData struct {
	CAPECID            string   `json:"capec_id"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	LikelihoodOfAttack string   `json:"likelihood_of_attack"`
	TypicalSeverity    string   `json:"typical_severity"`
	RelatedCWEs        []string `json:"related_cwes"`
	Prerequisites      []string `json:"prerequisites"`
}

// Ranked CAPEC result with hybrid scoring
type RankedCAPEC struct {
	CAPECID         string   `json:"capec_id"`
	Name            string   `json:"name"`
	TotalScore      float64  `json:"total_score"`
	TFIDFScore      float64  `json:"tfidf_score"`
	CWEScore        float64  `json:"cwe_score"`
	KeywordScore    float64  `json:"keyword_score"`
	MetadataScore   float64  `json:"metadata_score"`
	Confidence      string   `json:"confidence"`
	Severity        string   `json:"severity"`
	Likelihood      string   `json:"likelihood"`
	MatchedTerms    []string `json:"matched_terms"`
	MatchedKeywords []string `json:"matched_keywords"`
}

// NVD API structures
type NVDResponse struct {
	Vulnerabilities []struct {
		CVE CVEItem `json:"cve"`
	} `json:"vulnerabilities"`
}

type CVEItem struct {
	ID           string        `json:"id"`
	Descriptions []Description `json:"descriptions"`
	Weaknesses   []Weakness    `json:"weaknesses"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Weakness struct {
	Description []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"description"`
}

// CWE to CAPEC mapping with relationship strength
type CWEMapping struct {
	CAPECs   []string
	Strength string // "direct", "parent", "related"
}

// Relationships database structure
type RelationshipsDB struct {
	CWEToCapec    map[string][]string `json:"CWEToCapec"`
	CapecToAttack map[string][]string `json:"CapecToAttack"`
}

// Global variable for CWE to CAPEC mappings (loaded from file or fallback)
var cweToCapec map[string][]string

// Minimal fallback mappings if relationships file not found
var fallbackMappings = map[string][]string{
	// Most common attack types only
	"79":  {"588", "591", "592", "63"},
	"89":  {"66", "7", "108"},
	"22":  {"126", "597"},
	"502": {"586"},
	"611": {"221"},
	"918": {"664"},
	"352": {"62"},
}

// Attack pattern keywords for fallback matching
// CWE Specificity Weights
// High (1.5): Attack-specific CWEs (1-3 CAPECs)
// Medium (1.0): Category-specific CWEs (3-10 CAPECs)
// Low (0.5): Generic CWEs (10+ CAPECs)
var cweSpecificity = map[string]float64{
	// Highly Specific (1.5x)
	"502": 1.5, // Deserialization
	"611": 1.5, // XXE
	"918": 1.5, // SSRF
	"352": 1.5, // CSRF
	"434": 1.5, // File Upload
	"94":  1.5, // Code Injection
	"95":  1.5, // Eval Injection
	"798": 1.5, // Hard-coded Credentials

	// Moderately Specific (1.0x)
	"79":  1.0, // XSS
	"89":  1.0, // SQL Injection
	"77":  1.0, // Command Injection
	"78":  1.0, // OS Command Injection
	"22":  1.0, // Path Traversal
	"119": 1.0, // Buffer Overflow
	"120": 1.0, // Buffer Copy
	"125": 1.0, // Out-of-bounds Read
	"787": 1.0, // Out-of-bounds Write
	"190": 1.0, // Integer Overflow

	// Generic (0.5x)
	"20":  0.5, // Improper Input Validation
	"200": 0.5, // Information Disclosure
	"287": 0.5, // Authentication
	"269": 0.5, // Privilege Management
	"400": 0.5, // Resource Exhaustion
	"444": 0.5, // HTTP Request Smuggling
	"501": 0.5, // Trust Boundary
	"93":  0.5, // CRLF Injection
}

// Expanded keyword database (576 CAPECs with exclusive keywords)

var attackKeywords = map[string][]string{
	"1":   {"properly constrained", "accessing functionality", "constrained by", "properly constrained by", "constrained by acls", "authorization framework", "particularly url", "url s"},                                                        // Accessing Functionality Not Properly Constrained by ACLs
	"2":   {"inducing account", "account lockout", "inducing account lockout"},                                                                                                                                                                    // Inducing Account Lockout
	"3":   {"character sequences", "sequences to", "sequences to bypass", "bypass input filters", "character sequences to", "input filters", "bypass input", "ghost character"},                                                                   // Using Leading 'Ghost' Character Sequences to Bypass Input Filters
	"4":   {"address encodings", "alternative ip", "alternative ip address", "fqdns url", "url ip", "url ip address"},                                                                                                                             // Using Alternative IP Address Encodings
	"5":   {"blue boxing", "usurping command", "strong authorization", "command of"},                                                                                                                                                              // Blue Boxing
	"6":   {"argument injection", "command syntax"},                                                                                                                                                                                               // Argument Injection
	"7":   {"blind sql", "blind sql injection", "injection although", "injection blind", "sql expressions", "prevent sql", "facilitate sql", "boolean sql"},                                                                                       // Blind SQL Injection
	"8":   {"api call", "overflow in an", "overflow in", "buffer overflow in", "code library", "shared code", "code modules", "overflow attacks an"},                                                                                              // Buffer Overflow in an API Call
	"9":   {"local command-line", "command-line utilities", "overflow in local", "local command-line utilities", "buffer overflow in", "overflow in"},                                                                                             // Buffer Overflow in Local Command-Line Utilities
	"10":  {"via environment", "environment variables", "overflow via environment", "via environment variables", "overflow associated", "overflow via", "buffer overflow via", "overflow associated buffers"},                                     // Buffer Overflow via Environment Variables
	"11":  {"server misclassification", "web server misclassification", "web server"},                                                                                                                                                             // Cause Web Server Misclassification
	"12":  {"choosing message", "message identifier", "choosing message identifier", "command bus", "parameter value", "parameter value assigned"},                                                                                                // Choosing Message Identifier
	"13":  {"subverting environment", "variable values", "subverting environment variable", "environment variable values", "environment variable"},                                                                                                // Subverting Environment Variable Values
	"14":  {"injection-induced buffer", "client-side injection-induced", "client-side injection-induced buffer", "injection-induced buffer overflow", "injection of"},                                                                             // Client-side Injection-induced Buffer Overflow
	"15":  {"command delimiter", "command delimiters", "legitimate command", "sql queries", "delimiter payload", "payload as", "command delimiter payload", "payload as an"},                                                                      // Command Delimiters
	"16":  {"dictionary-based password"},                                                                                                                                                                                                          // Dictionary-based Password Attack
	"17":  {"executable file", "servers ftp", "ftp servers", "ftp"},                                                                                                                                                                               // Using Malicious Files
	"18":  {"targeting non-script", "non-script elements", "targeting non-script elements", "xss targeting non-script", "xml documents -cdata-", "xss targeting", "xml documents"},                                                                // XSS Targeting Non-Script Elements
	"19":  {"embedding scripts", "scripts within", "within scripts", "embedding scripts within", "scripts within scripts", "script by", "own script", "script by embedding"},                                                                      // Embedding Scripts within Scripts
	"20":  {"encryption brute", "encryption brute forcing", "brute forcing", "encryption algorithm"},                                                                                                                                              // Encryption Brute Forcing
	"21":  {"trusted identifiers", "exploitation of trusted", "cookie etc", "session id resource", "cookie etc to", "session id", "cookie"},                                                                                                       // Exploitation of Trusted Identifiers
	"22":  {"exploiting trust", "exploiting trust in", "trust in client", "trust in", "channel authentication"},                                                                                                                                   // Exploiting Trust in Client
	"23":  {"file content", "file content injection", "content injection", "including binary", "payload targeting", "binary files"},                                                                                                               // File Content Injection
	"24":  {"filter failure"},                                                                                                                                                                                                                     // Filter Failure through Buffer Overflow
	"25":  {"forced deadlock"},                                                                                                                                                                                                                    // Forced Deadlock
	"26":  {"leveraging race", "leveraging race conditions", "race conditions"},                                                                                                                                                                   // Leveraging Race Conditions
	"27":  {"conditions via", "conditions via symbolic", "race conditions via", "leveraging race", "via symbolic", "symbolic links", "race conditions", "via symbolic links"},                                                                     // Leveraging Race Conditions via Symbolic Links
	"29":  {"leveraging time-of-check", "toctou race", "race conditions", "time-of-use toctou", "time-of-use toctou race", "toctou race conditions"},                                                                                              // Leveraging Time-of-Check and Time-of-Use (TOCTOU) Race Conditions
	"30":  {"thread of", "privileged thread", "privileged thread of", "thread of execution", "hijacking a", "hijacking a privileged"},                                                                                                             // Hijacking a Privileged Thread of Execution
	"31":  {"http cookies", "accessing http", "cookie", "cookie s content", "http cookies to", "cookie s"},                                                                                                                                        // Accessing/Intercepting/Modifying HTTP Cookies
	"32":  {"http query", "query strings", "http query strings", "http query string", "query string", "html code", "script code in", "query string to"},                                                                                           // XSS Through HTTP Query Strings
	"33":  {"request smuggling", "http request smuggling", "header by", "various http", "given http", "http request", "http header by", "http headers request-line"},                                                                              // HTTP Request Smuggling
	"34":  {"response splitting", "http response splitting", "http response", "spoofed http", "unauthorized http", "http responses", "single http", "back-end http"},                                                                              // HTTP Response Splitting
	"35":  {"non-executable files", "leverage executable", "code in non-executable", "leverage executable code", "executable code in", "executable code", "executable loads", "code directly"},                                                    // Leverage Executable Code in Non-Executable Files
	"36":  {"interfaces or", "unpublished interfaces", "interfaces or functionality", "unpublished interfaces or"},                                                                                                                                // Using Unpublished Interfaces or Functionality
	"37":  {"retrieve embedded", "embedded sensitive", "retrieve embedded sensitive"},                                                                                                                                                             // Retrieve Embedded Sensitive Data
	"38":  {"configuration file", "search paths", "file search", "file search paths", "configuration file search", "known command", "command is", "command is executed"},                                                                          // Leveraging/Manipulating Configuration File Search Paths
	"39":  {"manipulating opaque", "opaque client-based", "manipulating opaque client-based", "encryption or", "authentication tokens", "authentication tokens or", "encryption or obfuscation"},                                                  // Manipulating Opaque Client-based Data Tokens
	"40":  {"terminal devices", "writeable terminal", "manipulating writeable terminal", "writeable terminal devices", "manipulating writeable", "sends command", "command strings to", "command strings"},                                        // Manipulating Writeable Terminal Devices
	"41":  {"meta-characters in", "e-mail headers", "headers to", "meta-characters in e-mail", "headers to inject", "e-mail headers to", "header contains", "email header"},                                                                       // Using Meta-characters in E-mail Headers to Inject Malicious Payloads
	"42":  {"mime conversion"},                                                                                                                                                                                                                    // MIME Conversion
	"43":  {"multiple input", "interpretation layers", "exploiting multiple", "input interpretation", "exploiting multiple input", "multiple input interpretation", "input interpretation layers", "bypass input validation"},                     // Exploiting Multiple Input Interpretation Layers
	"44":  {"overflow binary", "resource file", "binary resource", "overflow binary resource", "binary resource file", "binary resources", "execution stack", "resources binary"},                                                                 // Overflow Binary Resource File
	"45":  {"overflow via symbolic", "via symbolic", "symbolic links", "overflow internal", "potentially overflow", "overflow via", "via symbolic links", "buffer overflow via"},                                                                  // Buffer Overflow via Symbolic Links
	"46":  {"overflow variables"},                                                                                                                                                                                                                 // Overflow Variables and Tags
	"47":  {"via parameter", "parameter expansion", "overflow via parameter", "via parameter expansion", "overflow via", "buffer overflow via"},                                                                                                   // Buffer Overflow via Parameter Expansion
	"48":  {"passing local", "filenames to", "expect a", "local filenames", "local filenames to", "expect a url", "filenames to functions", "passing local filenames"},                                                                            // Passing Local Filenames to Functions That Expect a URL
	"49":  {"password brute", "password brute forcing", "brute forcing"},                                                                                                                                                                          // Password Brute Forcing
	"50":  {"recovery exploitation", "password recovery", "password recovery exploitation"},                                                                                                                                                       // Password Recovery Exploitation
	"51":  {"service registry", "poison web", "web service", "web service registry", "poison web service", "schema or", "schema or metadata", "schema"},                                                                                           // Poison Web Service Registry
	"52":  {"embedding null", "null bytes", "embedding null bytes"},                                                                                                                                                                               // Embedding NULL Bytes
	"53":  {"null terminate", "postfix null", "encoding of null", "postfix null terminate", "alternate encoding", "encoding of"},                                                                                                                  // Postfix, Null Terminate, and Backslash
	"55":  {"table password", "password cracking", "rainbow table", "rainbow table password", "table password cracking"},                                                                                                                          // Rainbow Table Password Cracking
	"56":  {"guard logic", "removing/short-circuiting guard logic"},                                                                                                                                                                               // DEPRECATED: Removing/short-circuiting 'guard logic'
	"57":  {"utilizing rest", "resource to", "obtain sensitive", "resource to obtain", "trust in", "once ssl", "ssl is", "rest s"},                                                                                                                // Utilizing REST's Trust in the System Resource to Obtain Sensitive Data
	"58":  {"restful privilege", "privilege elevation", "restful privilege elevation", "rest http", "accepting http", "http messages"},                                                                                                            // Restful Privilege Elevation
	"59":  {"session credential", "credential falsification", "predictable session", "session id in", "session credential falsification", "perform spoofing", "session id", "session hijacking"},                                                  // Session Credential Falsification through Prediction
	"60":  {"reusing session", "aka session", "session replay", "aka session replay", "reusing session ids", "session ids", "stolen session", "session id"},                                                                                       // Reusing Session IDs (aka Session Replay)
	"61":  {"session fixation", "client-generated session", "session identifiers", "privileged session", "session identifier", "same session", "session identifier in", "session identifier provided"},                                            // Session Fixation
	"62":  {"cross site request", "site request forgery", "site request", "existing session", "cross site", "session cookies", "request forgery", "cookie including"},                                                                             // Cross Site Request Forgery
	"63":  {"cross-site scripting", "execute code", "cross-site scripting xss"},                                                                                                                                                                   // Cross-Site Scripting (XSS)
	"64":  {"combined to", "encoding combined", "combined to bypass", "encoding combined to", "url encoding combined", "bypass validation", "octet code", "forbidden url"},                                                                        // Using Slashes and URL Encoding Combined to Bypass Validation Logic
	"65":  {"code bound"},                                                                                                                                                                                                                         // Sniff Application Code
	"66":  {"resulting sql", "sql statement", "constructs sql", "sql statements", "intended sql", "sql statements based", "sql statement performs", "sql injection results"},                                                                      // SQL Injection
	"67":  {"format overflow", "string format", "format overflow in", "overflow in syslog", "string format overflow", "overflow in", "overflow there", "parameter leading"},                                                                       // String Format Overflow in syslog()
	"68":  {"code-signing facilities", "subvert code-signing", "subvert code-signing facilities", "tie code", "enforces code", "code s", "code signing facilities", "code signing classifies"},                                                    // Subvert Code-signing Facilities
	"69":  {"elevated privileges", "code to execute"},                                                                                                                                                                                             // Target Programs with Elevated Privileges
	"70":  {"default usernames", "try common", "common or", "try common or", "common or default"},                                                                                                                                                 // Try Common or Default Usernames and Passwords
	"71":  {"unicode encoding", "unicode encoding to", "unicode", "encoding to", "bypass validation", "encoding to bypass", "validation logic", "unicode aware"},                                                                                  // Using Unicode Encoding to Bypass Validation Logic
	"72":  {"url encoding", "url an", "encoding an url", "encoding an", "encoding of"},                                                                                                                                                            // URL Encoding
	"73":  {"user-controlled filename", "url links", "xss redirection", "potentially executable", "uploads code", "payload variants", "url links directly", "executable content"},                                                                 // User-Controlled Filename
	"74":  {"manipulating state"},                                                                                                                                                                                                                 // Manipulating State
	"75":  {"writeable configuration", "configuration files", "manipulating writeable configuration", "writeable configuration files", "manipulating writeable"},                                                                                  // Manipulating Writeable Configuration Files
	"76":  {"input to", "manipulating web", "web input", "input to file", "manipulating web input", "web input to"},                                                                                                                               // Manipulating Web Input to File System Calls
	"77":  {"manipulating user-controlled", "user-controlled variables", "manipulating user-controlled variables", "untrusted query", "query variables", "query variables directly"},                                                              // Manipulating User-Controlled Variables
	"78":  {"escaped slashes", "escaped slashes in", "slashes in", "slashes in alternate", "alternate encoding", "encoding an"},                                                                                                                   // Using Escaped Slashes in Alternate Encoding
	"79":  {"slashes in", "indicate traversal", "traversal between", "slashes in alternate", "traversal between directories", "alternate encoding", "encoding of"},                                                                                // Using Slashes in Alternate Encoding
	"80":  {"utf-8 encoding to", "utf-8 encoding", "encoding to", "encoding to bypass", "bypass validation", "validation logic", "unicode legal", "possible encoding"},                                                                            // Using UTF-8 Encoding to Bypass Validation Logic
	"81":  {"server logs", "logs tampering", "web server logs", "server logs tampering", "web server"},                                                                                                                                            // Web Server Logs Tampering
	"82":  {"denial of", "assumptions regarding", "implicit assumptions", "violating implicit", "aka xml", "regarding xml", "assumptions regarding xml", "implicit assumptions regarding"},                                                        // DEPRECATED: Violating Implicit Assumptions Regarding XML Content (aka XML Denial of Service (XDoS))
	"83":  {"xpath injection", "xpath", "injection enables", "xpath expressions", "query an", "dynamic xpath", "completely xpath", "injection enables an"},                                                                                        // XPath Injection
	"84":  {"xquery injection", "injection uses", "sql calls", "injection uses improperly", "sql calls to"},                                                                                                                                       // XQuery Injection
	"85":  {"ajax footprinting"},                                                                                                                                                                                                                  // AJAX Footprinting
	"86":  {"http headers", "actors xss", "xss in http", "http headers attacks", "xss in"},                                                                                                                                                        // XSS Through HTTP Headers
	"87":  {"forceful browsing", "direct url", "url entry", "url entry to"},                                                                                                                                                                       // Forceful Browsing
	"88":  {"build command", "command injection", "command injection in", "injection in an", "command strings is", "injection in", "command strings"},                                                                                             // OS Command Injection
	"89":  {"script injection", "injection or", "require script", "script injection or", "injection or clicking"},                                                                                                                                 // Pharming
	"90":  {"authentication protocol", "authentication protocol susceptible", "authentication protocols", "during authentication"},                                                                                                                // Reflection Attack in Authentication Protocol
	"91":  {"img tags", "xss in img", "xss in", "capec-18 xss", "deprecated xss in", "xss targeting non-script", "deprecated xss", "xss targeting"},                                                                                               // DEPRECATED: XSS in IMG Tags
	"92":  {"integer overflow", "forced integer", "forced integer overflow", "integer", "integer variable to", "integer variable is", "integer in question", "integer variable"},                                                                  // Forced Integer Overflow
	"94":  {"middle aitm"},                                                                                                                                                                                                                        // Adversary in the Middle (AiTM)
	"95":  {"wsdl scanning", "injection etc", "injection command", "injection command injection", "command injection etc", "injection etc wsdl", "content injection", "parameter tampering"},                                                      // WSDL Scanning
	"97":  {"encryption ciphertext", "decryption"},                                                                                                                                                                                                // Cryptanalysis
	"98":  {"frequently authentication", "authentication credentials"},                                                                                                                                                                            // Phishing
	"99":  {"xml parser", "deprecated xml parser", "deprecated xml", "capec-230 xml", "xml oversized", "xml nested", "capec-231 xml", "xml oversized payloads"},                                                                                   // DEPRECATED: XML Parser Attack
	"100": {"overflow buffers", "buffer operations", "buffer regions", "buffer operations typically", "buffer regions in", "overflow attacks", "allocated buffer", "buffer overflow attacks"},                                                     // Overflow Buffers
	"101": {"side include", "server side include", "server side", "ssi injection", "include ssi", "send code", "injection to send", "include ssi injection"},                                                                                      // Server Side Include (SSI) Injection
	"102": {"sidejacking", "session sidejacking", "session token", "token to", "stolen token", "session tokens", "sidejacking takes", "token is"},                                                                                                 // Session Sidejacking
	"103": {"clickjacking"},                                                                                                                                                                                                                       // Clickjacking
	"104": {"zone scripting", "cross zone", "cross zone scripting", "scripting code"},                                                                                                                                                             // Cross Zone Scripting
	"105": {"request splitting", "http request splitting", "http request", "request messages by", "http agents", "http requests", "intermediary http", "request messages"},                                                                        // HTTP Request Splitting
	"106": {"log files", "deprecated xss"},                                                                                                                                                                                                        // DEPRECATED: XSS through Log Files
	"107": {"site tracing", "cross site tracing", "cross site", "header of", "authentication credentials transmitted", "session cookie", "authentication credentials", "http request"},                                                            // Cross Site Tracing
	"108": {"line execution", "command line execution", "command line", "injection methods", "standard sql", "injection methods to", "sql injection methods", "command line arguments"},                                                           // Command Line Execution through SQL Injection
	"109": {"mapping injection", "object relational", "relational mapping", "relational mapping injection", "object relational mapping", "injection sometimes", "injection except", "sql commands"},                                               // Object Relational Mapping Injection
	"110": {"soap parameter", "soap parameter tampering", "parameter binding", "executed sql", "sql query", "parameter tampering", "soap message is", "parameter binding thus"},                                                                   // SQL Injection through SOAP Parameter Tampering
	"111": {"json hijacking", "javascript hijacking", "json", "aka javascript", "aka javascript hijacking", "hijacking aka", "json as", "notation json"},                                                                                          // JSON Hijacking (aka JavaScript Hijacking)
	"112": {"brute force"},                                                                                                                                                                                                                        // Brute Force
	"113": {"interface manipulation"},                                                                                                                                                                                                             // Interface Manipulation
	"114": {"authentication abuse", "authentication scheme", "authentication mechanism or", "authentication scheme s", "authentication mechanism is", "authentication mechanism"},                                                                 // Authentication Abuse
	"115": {"authentication bypass", "without authentication", "authentication ever", "authentication ever having", "authentication mechanism"},                                                                                                   // Authentication Bypass
	"117": {"involve sniffing", "sniffing network", "sniffing network traffic"},                                                                                                                                                                   // Interception
	"120": {"double encoding", "traversal attacks", "traversal or", "encoding process", "above url", "particular request", "url encoded", "traversal or injection"},                                                                               // Double Encoding
	"121": {"non-production interfaces"},                                                                                                                                                                                                          // Exploit Non-Production Interfaces
	"122": {"privilege abuse"},                                                                                                                                                                                                                    // Privilege Abuse
	"123": {"buffer manipulation", "most buffer", "buffer is", "buffer attacks", "buffer space", "buffer in", "buffer resulting", "code responsible"},                                                                                             // Buffer Manipulation
	"124": {"shared resource", "resource manipulation", "shared resource manipulation"},                                                                                                                                                           // Shared Resource Manipulation
	"126": {"path traversal"},                                                                                                                                                                                                                     // Path Traversal
	"127": {"directory indexing", "script contents", "request containing", "accounts script", "request containing a", "request is received", "script contents as", "request is"},                                                                  // Directory Indexing
	"128": {"integer attacks", "integer", "positive integer", "signed integer", "integer storage", "integer in a", "integer storage formats", "integer variables to"},                                                                             // Integer Attacks
	"129": {"pointer", "pointer manipulation", "pointer attacks", "variables integer", "certain pointer", "pointer values", "simply integer", "pointer within"},                                                                                   // Pointer Manipulation
	"130": {"excessive allocation", "request thereby", "request s", "attackers request", "normal request", "request thereby reducing", "request s often"},                                                                                         // Excessive Allocation
	"131": {"leak exposure", "resource leak", "resource leak exposure"},                                                                                                                                                                           // Resource Leak Exposure
	"133": {"common switches"},                                                                                                                                                                                                                    // Try All Common Switches
	"134": {"email injection"},                                                                                                                                                                                                                    // Email Injection
	"135": {"format string", "format string injection", "string injection", "code if", "program stack", "stack"},                                                                                                                                  // Format String Injection
	"136": {"ldap injection", "ldap", "query to", "ldap queries", "query during", "ldap server", "query might", "aforementioned query"},                                                                                                           // LDAP Injection
	"137": {"parameter injection", "parameter encodings", "request parameters", "encoding scheme", "input parameter", "parameter is", "any encoding", "parameter is set"},                                                                         // Parameter Injection
	"138": {"reflection injection"},                                                                                                                                                                                                               // Reflection Injection
	"139": {"relative path", "relative path traversal", "path traversal"},                                                                                                                                                                         // Relative Path Traversal
	"140": {"bypassing of", "multiple-form sets", "intermediate forms", "forms in", "bypassing of intermediate", "intermediate forms in", "forms in multiple-form"},                                                                               // Bypassing of Intermediate Forms in Multiple-Form Sets
	"141": {"cache poisoning", "poisoning", "dns or arp", "dns or"},                                                                                                                                                                               // Cache Poisoning
	"142": {"dns cache", "dns cache poisoning", "cache poisoning", "public dns", "poisoning", "dns cache to"},                                                                                                                                     // DNS Cache Poisoning
	"143": {"web pages", "unpublicized web pages", "detect unpublicized", "unpublicized web", "detect unpublicized web"},                                                                                                                          // Detect Unpublicized Web Pages
	"144": {"unpublicized web services", "detect unpublicized", "unpublicized web", "detect unpublicized web", "web services"},                                                                                                                    // Detect Unpublicized Web Services
	"145": {"checksum spoofing", "checksum", "spoofing an", "common checksum", "checksum value", "checksum message", "corresponding checksum", "checksum mechanism"},                                                                              // Checksum Spoofing
	"146": {"xml schema", "xml schema poisoning", "schema poisoning", "schema", "documents schema", "xml schemas", "poisoning is", "schema either"},                                                                                               // XML Schema Poisoning
	"147": {"ping of", "xml ping", "soap protocol", "normal flooding", "repetitive soap", "simple flooding", "small xml", "xml ping of"},                                                                                                          // XML Ping of the Death
	"148": {"content spoofing", "spoofing is", "spoofing is most"},                                                                                                                                                                                // Content Spoofing
	"149": {"file names", "predictable temporary", "temporary file", "temporary file names", "predictable temporary file"},                                                                                                                        // Explore for Predictable Temporary File Names
	"150": {"common resource", "resource locations", "common resource locations"},                                                                                                                                                                 // Collect Data from Common Resource Locations
	"151": {"spoofing refers", "identity spoofing", "spoofing refers to", "spoofed authentication", "authentication credentials"},                                                                                                                 // Identity Spoofing
	"154": {"location spoofing", "resource location", "resource location spoofing", "request a", "request a resource"},                                                                                                                            // Resource Location Spoofing
	"155": {"temporary files", "screen temporary", "screen temporary files"},                                                                                                                                                                      // Screen Temporary Files for Sensitive Information
	"157": {"sniffing attacks", "recipient sniffing"},                                                                                                                                                                                             // Sniffing Attacks
	"158": {"network traffic", "sniffing network", "sniffing applications", "tcp/ip dns", "dns ethernet", "sniffing network traffic", "network sniffing"},                                                                                         // Sniffing Network Traffic
	"159": {"code base", "unauthorized code", "code an"},                                                                                                                                                                                          // Redirect Access to Libraries
	"160": {"script-based apis", "support script", "script tags"},                                                                                                                                                                                 // Exploit Script-Based APIs
	"161": {"infrastructure manipulation"},                                                                                                                                                                                                        // Infrastructure Manipulation
	"162": {"hidden fields", "manipulating hidden", "manipulating hidden fields", "form response"},                                                                                                                                                // Manipulating Hidden Fields
	"163": {"spear phishing", "url to"},                                                                                                                                                                                                           // Spear Phishing
	"164": {"mobile phishing"},                                                                                                                                                                                                                    // Mobile Phishing
	"165": {"file manipulation", "buffer overflows or", "buffer overflows"},                                                                                                                                                                       // File Manipulation
	"166": {"reset values"},                                                                                                                                                                                                                       // Force the System to Reset Values
	"167": {"white box", "white box reverse", "box reverse", "executable or", "box reverse engineering", "reverse engineering"},                                                                                                                   // White Box Reverse Engineering
	"168": {"dir command", "command line dir", "command line"},                                                                                                                                                                                    // Windows ::DATA Alternate Data Stream
	"170": {"response headers", "http protocol directory", "response headers variations", "http protocol"},                                                                                                                                        // Web Application Fingerprinting
	"171": {"variable manipulation", "deprecated variable", "deprecated variable manipulation"},                                                                                                                                                   // DEPRECATED: Variable Manipulation
	"173": {"action spoofing", "clickjacking"},                                                                                                                                                                                                    // Action Spoofing
	"174": {"flash parameter injection", "flash parameter", "parameter injection"},                                                                                                                                                                // Flash Parameter Injection
	"175": {"injection involves", "while code", "code while", "code injection in", "code injection involves", "code inclusion", "code while code", "code to be"},                                                                                  // Code Inclusion
	"177": {"files protected", "higher classification", "create files", "executable and/or", "executable and/or is"},                                                                                                                              // Create files with the same name as files protected with a higher classification
	"178": {"cross-site flashing"},                                                                                                                                                                                                                // Cross-Site Flashing
	"179": {"calling micro-services", "micro-services directly", "calling micro-services directly", "query micro-services", "query micro-services at"},                                                                                            // Calling Micro-Services Directly
	"180": {"exploiting incorrectly", "incorrectly configured", "exploiting incorrectly configured"},                                                                                                                                              // Exploiting Incorrectly Configured Access Control Security Levels
	"181": {"flash file", "file overlay", "flash file overlay", "clickjacking"},                                                                                                                                                                   // Flash File Overlay
	"182": {"flash injection", "parameter to", "controlled parameter", "parameter to a"},                                                                                                                                                          // Flash Injection
	"183": {"imap/smtp command", "imap/smtp command injection", "smtp", "request sent", "smtp mail", "command injection", "smtp mail server", "request sent to"},                                                                                  // IMAP/SMTP Command Injection
	"184": {"software integrity", "firmware achieving", "software code", "code device", "device firmware"},                                                                                                                                        // Software Integrity Attack
	"185": {"software download", "dangerous code"},                                                                                                                                                                                                // Malicious Software Download
	"186": {"code believed", "code believed to", "software update", "dangerous code"},                                                                                                                                                             // Malicious Software Update
	"187": {"via redirection", "update via redirection", "automated software", "update via", "code downloaded", "software update via", "automated software update", "software update"},                                                            // Malicious Automated Software Update via Redirection
	"188": {"reverse engineering"},                                                                                                                                                                                                                // Reverse Engineering
	"189": {"black box", "black box reverse", "box reverse", "box reverse engineering", "reverse engineering", "executable object"},                                                                                                               // Black Box Reverse Engineering
	"190": {"assumed hidden", "reverse engineer", "expose assumed", "engineer an", "hidden functionality", "executable to expose", "assumed hidden functionality", "expose assumed hidden"},                                                       // Reverse Engineer an Executable to Expose Assumed Hidden Functionality
	"191": {"sensitive constants", "constants within", "within an", "read sensitive", "sensitive constants within", "within an executable", "read sensitive constants", "constants within an"},                                                    // Read Sensitive Constants Within an Executable
	"192": {"protocol analysis"},                                                                                                                                                                                                                  // Protocol Analysis
	"193": {"remote file", "php remote", "remote file inclusion", "php remote file", "file inclusion", "code remotely", "code remotely available"},                                                                                                // PHP Remote File Inclusion
	"194": {"source of", "improper authentication", "authentication to provide", "authentication to"},                                                                                                                                             // Fake the Source of Data
	"195": {"principal spoof", "authentication credentials instead", "spoofed authentication", "identity spoofing", "authentication credentials"},                                                                                                 // Principal Spoof
	"196": {"functional session", "service session", "credential falsification", "sidejacking attacks", "session credential", "session credential in", "sidejacking attacks in", "session credential falsification"},                              // Session Credential Falsification through Forging
	"198": {"targeting error", "error pages", "xss targeting error", "targeting error pages", "live code", "query structure", "xss targeting", "request to a"},                                                                                    // XSS Targeting Error Pages
	"199": {"alternate syntax", "bypass filters e", "script or script", "bypass filters", "script tag", "script or", "script is"},                                                                                                                 // XSS Using Alternate Syntax
	"200": {"output filters", "removal of", "removal of filters", "input filters", "overflow or", "filters input", "constrained executable", "filters output"},                                                                                    // Removal of filters: Input filters, output filters, data masking
	"201": {"external linking", "xml yaml", "xml yaml etc"},                                                                                                                                                                                       // Serialized Data External Linking
	"203": {"manipulate registry", "spoofing or", "rmi", "authorization in", "billing authorization", "authorization or", "java rmi", "identity spoofing"},                                                                                        // Manipulate Registry Information
	"204": {"lifting sensitive", "embedded in cache", "embedded in"},                                                                                                                                                                              // Lifting Sensitive Data Embedded in Cache
	"205": {"lifting credential", "thick or", "/key material", "material embedded", "client distributions", "thick or thin", "embedded in client", "material embedded in"},                                                                        // DEPRECATED: Lifting credential(s)/key material embedded in client distributions (thick or thin)
	"206": {"code effectively", "sign code", "code bundles", "code bundles users", "code effectively allowing", "code or hashes", "code signing", "own code"},                                                                                     // Signing Malicious Code
	"207": {"removing important", "important client", "client functionality", "removing important client", "important client functionality"},                                                                                                      // Removing Important Client Functionality
	"208": {"cash decrements", "purse logic", "logic removing/mutating", "removing/mutating cash", "removing/mutating cash decrements", "removing/short-circuiting purse logic", "purse logic removing/mutating", "logic removing/mutating cash"}, // Removing/short-circuiting 'Purse' logic: removing/mutating 'cash' decrements
	"209": {"mime type", "type mismatch", "mime type mismatch", "invoke script", "arbitrary script", "script in", "script file", "script filters"},                                                                                                // XSS Using MIME Type Mismatch
	"211": {"web tools", "leveraging web", "leveraging web tools", "firebug to", "mozilla s", "greasemonkey firebug", "tools e", "deprecated leveraging"},                                                                                         // DEPRECATED: Leveraging web tools (e.g. Mozilla's GreaseMonkey, Firebug) to change application behavior
	"212": {"functionality misuse"},                                                                                                                                                                                                               // Functionality Misuse
	"213": {"directory traversal", "traversal please", "deprecated directory", "traversal please refer", "deprecated directory traversal", "path traversal"},                                                                                      // DEPRECATED: Directory Traversal
	"214": {"net-based stack", "stack traces", "garnering j2ee/", "net-based stack traces", "j2ee/ net-based", "deprecated fuzzing", "stack", "garnering j2ee/ net-based"},                                                                        // DEPRECATED: Fuzzing for garnering J2EE/.NET-based stack traces, for application mapping
	"216": {"communication channel", "channel manipulation", "communication channel manipulation", "parameter on", "parameter on communications"},                                                                                                 // Communication Channel Manipulation
	"217": {"configured ssl/tls", "incorrectly configured ssl/tls", "exploiting incorrectly", "incorrectly configured", "exploiting incorrectly configured"},                                                                                      // Exploiting Incorrectly Configured SSL/TLS
	"218": {"spoofing of", "uddi/ebxml messages", "spoofing of uddi/ebxml", "soap transactions"},                                                                                                                                                  // Spoofing of UDDI/ebXML Messages
	"219": {"xml routing", "detour attacks", "routing detour", "routing detour attacks", "xml routing detour", "content xml", "xml message", "xml process"},                                                                                       // XML Routing Detour Attacks
	"220": {"client-server protocol", "client-server protocol manipulation", "protocol manipulation"},                                                                                                                                             // Client-Server Protocol Manipulation
	"221": {"serialization external", "entities blowup", "external entities", "serialization external entities", "external entities blowup", "serialization", "uri a", "serialization languages"},                                                 // Data Serialization External Entities Blowup
	"222": {"iframe overlay"},                                                                                                                                                                                                                     // iFrame Overlay
	"226": {"session credential", "credential falsification", "session credential falsification", "authentication without", "session credentials", "initial authentication", "authentication without needing"},                                    // Session Credential Falsification through Manipulation
	"227": {"sustained client", "client engagement", "sustained client engagement"},                                                                                                                                                               // Sustained Client Engagement
	"228": {"dtd injection", "xml parsers", "xml documents"},                                                                                                                                                                                      // DTD Injection
	"229": {"parameter blowup", "xml yaml", "xml yaml etc"},                                                                                                                                                                                       // Serialized Data Parameter Blowup
	"230": {"nested payloads"},                                                                                                                                                                                                                    // Serialized Data with Nested Payloads
	"231": {"oversized serialized", "code execution"},                                                                                                                                                                                             // Oversized Serialized Data Payloads
	"233": {"privilege escalation"},                                                                                                                                                                                                               // Privilege Escalation
	"234": {"privileged process", "hijacking a", "hijacking a privileged", "own code"},                                                                                                                                                            // Hijacking a privileged process
	"235": {"implementing a", "awt queue", "callback to", "implementing a callback", "deprecated implementing", "deprecated implementing a", "hijacking a", "hijacking a privileged"},                                                             // DEPRECATED: Implementing a callback to system routine (old AWT Queue)
	"236": {"catching exception", "exception throw/signal", "privileged block", "catching exception throw/signal", "capec-30 hijacking", "deprecated catching", "deprecated catching exception", "hijacking a"},                                   // DEPRECATED: Catching exception throw/signal from privileged block
	"237": {"calling code", "sandbox by", "escaping a", "calling code in", "sandbox by calling", "escaping a sandbox", "java code", "byte code"},                                                                                                  // Escaping a Sandbox by Calling Code in Another Language
	"238": {"sandbox of", "code source", "convince sandbox", "url/codebase /", "sandbox of privilege", "convince sandbox of", "url/codebase / g", "source to"},                                                                                    // DEPRECATED: Using URL/codebase / G.A.C. (code source) to convince sandbox of privilege
	"239": {"authorization checks", "cache filtering", "subversion of", "subversion of authorization", "checks cache", "deprecated subversion", "filtering programmatic", "authorization checks cache"},                                           // DEPRECATED: Subversion of Authorization Checks: Cache Filtering, Programmatic Security, etc.
	"240": {"resource injection"},                                                                                                                                                                                                                 // Resource Injection
	"241": {"code injection", "injection please", "deprecated code", "capec-242 code", "deprecated code injection", "code injection please", "injection please refer"},                                                                            // DEPRECATED: Code Injection
	"242": {"code injection", "code inclusion in", "code file", "code inclusion involves", "code inclusion"},                                                                                                                                      // Code Injection
	"243": {"targeting html", "html attributes", "targeting html attributes", "xss targeting html", "xss actions", "xss actions in", "xss targeting", "normal xss"},                                                                               // XSS Targeting HTML Attributes
	"244": {"targeting uri", "uri placeholders", "xss targeting uri", "targeting uri placeholders", "base64", "uri", "uri schemes", "uri in"},                                                                                                     // XSS Targeting URI Placeholders
	"245": {"doubled characters", "crafted url", "url or", "script command", "command script", "uri encoding", "script command script", "script tag if"},                                                                                          // XSS Using Doubled Characters
	"246": {"xss please", "xss please refer", "stored xss", "flash parameter", "parameter injection", "deprecated xss"},                                                                                                                           // DEPRECATED: XSS Using Flash
	"247": {"invalid characters"},                                                                                                                                                                                                                 // XSS Using Invalid Characters
	"248": {"existing command", "command thus", "command construction", "command injection", "command thus modifying", "command strings weaknesses", "command of", "command strings"},                                                             // Command Injection
	"249": {"terminal injection", "linux terminal", "linux terminal injection", "deprecated linux", "deprecated linux terminal"},                                                                                                                  // DEPRECATED: Linux Terminal Injection
	"250": {"xml injection", "crafted xml", "xml user-controllable", "direct xml", "xml user-controllable input", "bypassing authentication", "xml database", "authentication or"},                                                                // XML Injection
	"251": {"local code", "local code inclusion", "code inclusion", "code files"},                                                                                                                                                                 // Local Code Inclusion
	"252": {"local file", "php local", "php local file", "local file inclusion", "file inclusion"},                                                                                                                                                // PHP Local File Inclusion
	"253": {"remote code inclusion", "remote code", "code inclusion", "code files"},                                                                                                                                                               // Remote Code Inclusion
	"254": {"dtd injection in", "injection in a", "dtd injection", "soap message", "injection going", "injection in", "deprecated dtd", "deprecated dtd injection"},                                                                               // DEPRECATED: DTD Injection in a SOAP Message
	"256": {"array overflow", "soap array overflow", "soap array", "overflow if", "request if", "soap request", "buffer overflow if"},                                                                                                             // SOAP Array Overflow
	"257": {"abuse of", "abuse of transaction", "deprecated abuse", "deprecated abuse of"},                                                                                                                                                        // DEPRECATED: Abuse of Transaction Data Structure
	"258": {"during dynamic", "dynamic update", "client during dynamic", "during dynamic update", "passively sniffing", "client during", "authorized client", "code bound"},                                                                       // DEPRECATED: Passively Sniffing and Capturing Application Code Bound for an Authorized Client During Dynamic Update
	"259": {"during patching", "client during patching", "passively sniffing", "authorized client", "client during", "code bound", "authorized client during", "code please"},                                                                     // DEPRECATED: Passively Sniffing and Capturing Application Code Bound for an Authorized Client During Patching
	"260": {"initial distribution", "during initial", "client during initial", "during initial distribution", "passively sniffing", "authorized client", "client during", "code bound"},                                                           // DEPRECATED: Passively Sniffing and Capturing Application Code Bound for an Authorized Client During Initial Distribution
	"261": {"adjacent user/sensitive"},                                                                                                                                                                                                            // Fuzzing for garnering other adjacent user/sensitive data
	"263": {"corrupted files", "buffer overflows"},                                                                                                                                                                                                // Force Use of Corrupted Files
	"264": {"environment variable manipulation", "environment variable", "deprecated environment", "variable manipulation", "deprecated environment variable"},                                                                                    // DEPRECATED: Environment Variable Manipulation
	"265": {"global variable", "global variable manipulation", "variable manipulation", "deprecated global", "deprecated global variable"},                                                                                                        // DEPRECATED: Global variable manipulation
	"266": {"manipulate canonicalization", "deprecated manipulate", "deprecated manipulate canonicalization"},                                                                                                                                     // DEPRECATED: Manipulate Canonicalization
	"267": {"leverage alternate", "leverage alternate encoding", "alternate encoding", "encoding standard"},                                                                                                                                       // Leverage Alternate Encoding
	"268": {"audit log", "log manipulation", "audit log manipulation"},                                                                                                                                                                            // Audit Log Manipulation
	"269": {"registry manipulation", "deprecated registry", "deprecated registry manipulation"},                                                                                                                                                   // DEPRECATED: Registry Manipulation
	"270": {"run keys", "registry run", "modification of registry", "registry run keys", "modification of", "executable to operate", "executable to"},                                                                                             // Modification of Registry Run Keys
	"271": {"schema poisoning", "schema", "poisoning"},                                                                                                                                                                                            // Schema Poisoning
	"272": {"protocol manipulation", "session or", "session or perform"},                                                                                                                                                                          // Protocol Manipulation
	"273": {"response smuggling", "http response smuggling", "http response", "unauthorized http", "http responses", "single http", "back-end http", "http agent"},                                                                                // HTTP Response Smuggling
	"274": {"http verb", "verb tampering", "http verb tampering", "http verb or", "http verb e"},                                                                                                                                                  // HTTP Verb Tampering
	"275": {"dns rebinding", "dns server"},                                                                                                                                                                                                        // DNS Rebinding
	"276": {"inter-component protocol", "inter-component protocol manipulation", "protocol manipulation", "session or", "session or perform"},                                                                                                     // Inter-component Protocol Manipulation
	"277": {"interchange protocol", "interchange protocol manipulation", "protocol manipulation", "session or", "session or perform"},                                                                                                             // Data Interchange Protocol Manipulation
	"278": {"services protocol", "web services protocol", "services protocol manipulation", "web services", "protocol manipulation"},                                                                                                              // Web Services Protocol Manipulation
	"279": {"soap manipulation", "soap paramters", "protocol soap", "soap is", "soap paramters leading"},                                                                                                                                          // SOAP Manipulation
	"280": {"soap parameter", "capec-279 soap", "deprecated soap", "parameter tampering", "soap parameter tampering", "soap manipulation please", "deprecated soap parameter", "soap manipulation"},                                               // DEPRECATED: SOAP Parameter Tampering
	"285": {"echo request", "request ping", "icmp echo", "request commonly", "icmp echo request", "echo request ping", "request commonly known", "icmp type 0"},                                                                                   // ICMP Echo Request Ping
	"287": {"syn scan", "tcp syn scan", "tcp syn"},                                                                                                                                                                                                // TCP SYN Scan
	"288": {"icmp echo", "request ping", "echo request", "echo request ping", "icmp echo request", "deprecated icmp echo", "deprecated icmp"},                                                                                                     // DEPRECATED: ICMP Echo Request Ping
	"290": {"enumerate mail", "mail exchange", "enumerate mail exchange", "dns query", "exchange mx", "mail exchange mx", "exchange mx records", "dns zone transfer"},                                                                             // Enumerate Mail Exchange (MX) Records
	"291": {"zone transfers", "dns zone transfers", "dns zone", "external dns", "dns servers", "multiple dns", "dns misconfiguration", "dns servers while"},                                                                                       // DNS Zone Transfers
	"292": {"host discovery", "response an"},                                                                                                                                                                                                      // Host Discovery
	"293": {"traceroute route", "route enumeration", "traceroute route enumeration", "icmp methods", "tcp were", "ingress icmp", "header as", "tcp were developed"},                                                                               // Traceroute Route Enumeration
	"294": {"address mask", "mask request", "icmp address", "address mask request", "icmp address mask", "configuration icmp", "request is an", "icmp type 18"},                                                                                   // ICMP Address Mask Request
	"295": {"timestamp request", "time-based authentication", "authentication mechanisms"},                                                                                                                                                        // Timestamp Request
	"296": {"mechanism icmp", "dhcp", "request to a"},                                                                                                                                                                                             // ICMP Information Request
	"297": {"ack ping", "tcp ack ping", "tcp ack", "tcp ping", "several tcp", "rst response", "tcp ping types", "tcp ack pings"},                                                                                                                  // TCP ACK Ping
	"298": {"udp ping", "block udp", "incoming icmp", "response so", "udp pings", "icmp port", "icmp weaknesses", "icmp host"},                                                                                                                    // UDP Ping
	"299": {"syn ping", "tcp syn ping", "tcp port", "tcp syn", "tcp syn packet", "tcp port is", "uses tcp", "tcp syn packets"},                                                                                                                    // TCP SYN Ping
	"300": {"port scanning", "tcp or", "udp networking", "tcp or udp"},                                                                                                                                                                            // Port Scanning
	"301": {"tcp connect", "connect scan", "tcp connect scan", "full tcp", "tcp/ip stack", "tcp connect scanning", "tcp connection attempts", "tcp connection"},                                                                                   // TCP Connect Scan
	"302": {"tcp fin", "fin scan", "tcp fin scan", "sending tcp", "tcp segments", "packet header", "any tcp", "tcp segment"},                                                                                                                      // TCP FIN Scan
	"303": {"tcp xmas", "xmas scan", "tcp xmas scan", "header generating", "sending tcp", "header generating packets", "tcp segments", "any tcp"},                                                                                                 // TCP Xmas Scan
	"304": {"null scan", "tcp null", "tcp null scan", "header generating", "sending tcp", "header generating packets", "tcp segments", "packet header"},                                                                                           // TCP Null Scan
	"305": {"ack scan", "tcp ack scan", "tcp ack", "tcp ack segments", "uses tcp"},                                                                                                                                                                // TCP ACK Scan
	"306": {"window scan", "tcp window scan", "tcp window", "positive tcp", "fewer tcp", "while tcp", "response rst", "tcp stack"},                                                                                                                // TCP Window Scan
	"307": {"tcp rpc", "rpc scan", "tcp rpc scan"},                                                                                                                                                                                                // TCP RPC Scan
	"308": {"udp scan", "udp scanning", "udp ports", "session responses", "port udp", "upon icmp", "udp ports usually", "udp port status"},                                                                                                        // UDP Scan
	"309": {"network topology", "topology mapping", "network topology mapping", "icmp tools", "including icmp", "icmp tools network"},                                                                                                             // Network Topology Mapping
	"310": {"vulnerable software", "smtp snmp", "ftp telnet", "telnet smtp", "smtp snmp running", "ftp telnet smtp", "smtp", "ftp"},                                                                                                               // Scanning for Vulnerable Software
	"311": {"deprecated os", "deprecated os fingerprinting"},                                                                                                                                                                                      // DEPRECATED: OS Fingerprinting
	"312": {"active os", "active os fingerprinting", "firmware version", "tcp differ", "unique response", "firmware version of", "tcp differ in", "firmware in"},                                                                                  // Active OS Fingerprinting
	"313": {"passive os", "passive os fingerprinting"},                                                                                                                                                                                            // Passive OS Fingerprinting
	"314": {"deprecated ip", "fingerprinting probes", "deprecated ip fingerprinting"},                                                                                                                                                             // DEPRECATED: IP Fingerprinting Probes
	"315": {"tcp/ip fingerprinting", "tcp/ip fingerprinting probes", "fingerprinting probes", "deprecated tcp/ip", "deprecated tcp/ip fingerprinting"},                                                                                            // DEPRECATED: TCP/IP Fingerprinting Probes
	"316": {"icmp fingerprinting", "icmp fingerprinting probes", "fingerprinting probes", "deprecated icmp fingerprinting", "deprecated icmp"},                                                                                                    // DEPRECATED: ICMP Fingerprinting Probes
	"317": {"sequencing probe", "between icmp", "generating response", "response packets rfc", "response packets"},                                                                                                                                // IP ID Sequencing Probe
	"318": {"echoed byte-order", "byte-order probe", "echoed byte-order probe", "header portion", "firmware reverse", "router firmware", "header portion of", "icmp error"},                                                                       // IP 'ID' Echoed Byte-Order Probe
	"319": {"fragment bit", "echoing probe", "don t", "bit echoing", "response packet", "bit echoing probe", "fragment bit echoing", "response packet an"},                                                                                        // IP (DF) 'Don't Fragment Bit' Echoing Probe
	"320": {"tcp timestamp", "timestamp probe", "tcp timestamp probe", "active tcp", "tcp timestamps", "tcp service", "analyzed tcp", "tcp service in"},                                                                                           // TCP Timestamp Probe
	"321": {"tcp sequence", "test tcp", "tcp sequence numbers"},                                                                                                                                                                                   // TCP Sequence Number Probe
	"322": {"common divisor", "divisor probe", "greatest common", "common divisor probe", "greatest common divisor", "isn greatest", "syn/ack response", "isn greatest common"},                                                                   // TCP (ISN) Greatest Common Divisor Probe
	"323": {"counter rate", "rate probe", "counter rate probe", "isn counter", "tcp isn counter", "isn counter rate", "tcp isn"},                                                                                                                  // TCP (ISN) Counter Rate Probe
	"324": {"sequence predictability", "predictability probe", "sequence predictability probe", "isn sequence", "tcp isn sequence", "isn sequence predictability", "tcp isn"},                                                                     // TCP (ISN) Sequence Predictability Probe
	"325": {"tcp congestion", "flag ecn", "ecn probe", "flag ecn probe"},                                                                                                                                                                          // TCP Congestion Control Flag (ECN) Probe
	"326": {"window size", "initial window", "size probe", "tcp initial", "initial window size", "tcp initial window", "window size probe", "session various"},                                                                                    // TCP Initial Window Size Probe
	"327": {"options probe", "tcp options probe", "tcp options", "header options", "tcp traffic", "options tcp", "structuring tcp", "response segment"},                                                                                           // TCP Options Probe
	"328": {"flag checksum", "checksum probe", "flag checksum probe", "checksum", "any ascii", "checksum on", "rst flag", "tcp rst flag"},                                                                                                         // TCP 'RST' Flag Checksum Probe
	"329": {"message quoting", "quoting probe", "error message quoting", "message quoting probe", "error message", "icmp error", "exceeded parameter", "originating request"},                                                                     // ICMP Error Message Quoting Probe
	"330": {"integrity probe", "echoing integrity", "message echoing", "echoing integrity probe", "error message echoing", "message echoing integrity", "error message", "icmp error"},                                                            // ICMP Error Message Echoing Integrity Probe
	"331": {"field probe", "total length", "length field", "total length field", "length field probe", "icmp ip total", "icmp ip", "header s"},                                                                                                    // ICMP IP Total Length Field Probe
	"332": {"message probe", "field error", "error message probe", "field error message", "icmp ip", "error message", "udp datagram having", "icmp ip id"},                                                                                        // ICMP IP 'ID' Field Error Message Probe
	"383": {"via api", "api event", "event monitoring", "via api event", "api event monitoring", "automated script"},                                                                                                                              // Harvesting Information via API Event Monitoring
	"384": {"via man-in-the-middle", "message manipulation", "api message", "manipulation via", "api message manipulation", "message manipulation via", "manipulation via man-in-the-middle", "code supplied"},                                    // Application API Message Manipulation via Man-in-the-Middle
	"385": {"event tampering", "tampering via", "transaction or", "event tampering via", "transaction or event", "api manipulation"},                                                                                                              // Transaction or Event Tampering via Application API Manipulation
	"386": {"api navigation", "api navigation remapping", "navigation remapping", "csrf"},                                                                                                                                                         // Application API Navigation Remapping
	"387": {"remapping to", "navigation remapping to", "remapping to propagate", "navigation remapping"},                                                                                                                                          // Navigation Remapping To Propagate Malicious Content
	"388": {"button hijacking", "api button", "api button hijacking"},                                                                                                                                                                             // Application API Button Hijacking
	"389": {"spoofing via", "content spoofing via", "api manipulation", "content spoofing", "attackers code", "code in general"},                                                                                                                  // Content Spoofing Via Application API Manipulation
	"390": {"bypassing physical"},                                                                                                                                                                                                                 // Bypassing Physical Security
	"391": {"physical locks", "bypassing physical locks", "bypassing physical", "bypass physical", "bypass those", "bypass those locks"},                                                                                                          // Bypassing Physical Locks
	"392": {"lock bumping"},                                                                                                                                                                                                                       // Lock Bumping
	"393": {"lock picking"},                                                                                                                                                                                                                       // Lock Picking
	"394": {"lock to", "force a", "snap gun", "gun lock", "gun lock to", "lock to force", "force a lock", "snap gun lock"},                                                                                                                        // Using a Snap Gun Lock to Force a Lock
	"395": {"bypassing electronic", "electronic locks", "bypassing electronic locks", "bypass electronic", "bypass electronic locks"},                                                                                                             // Bypassing Electronic Locks and Access Controls
	"396": {"bypassing card", "card or", "badge-based systems", "bypassing card or", "card or badge-based", "deprecated bypassing", "deprecated bypassing card"},                                                                                  // DEPRECATED: Bypassing Card or Badge-Based Systems
	"397": {"strip cards", "cloning magnetic", "magnetic strip cards", "cloning magnetic strip", "magnetic strip"},                                                                                                                                // Cloning Magnetic Strip Cards
	"398": {"strip card", "force attacks", "card brute", "magnetic strip card", "strip card brute", "card brute force", "brute force attacks", "magnetic strip"},                                                                                  // Magnetic Strip Card Brute Force Attacks
	"399": {"rfid cards", "cards or", "cloning rfid", "rfid cards or", "cards or chips", "cloning rfid cards"},                                                                                                                                    // Cloning RFID Cards or Chips
	"400": {"chip deactivation", "deactivation or", "rfid chip", "chip deactivation or", "deactivation or destruction", "rfid chip deactivation"},                                                                                                 // RFID Chip Deactivation or Destruction
	"401": {"physically hacking", "hacking hardware", "physically hacking hardware"},                                                                                                                                                              // Physically Hacking Hardware
	"402": {"bypassing ata", "ata password", "bypassing ata password", "command to", "ata command", "command to update"},                                                                                                                          // Bypassing ATA Password Security
	"404": {"gathering attacks", "deprecated social"},                                                                                                                                                                                             // DEPRECATED: Social Information Gathering Attacks
	"405": {"gathering via", "via research", "gathering via research", "deprecated social"},                                                                                                                                                       // DEPRECATED: Social Information Gathering via Research
	"406": {"dumpster diving"},                                                                                                                                                                                                                    // Dumpster Diving
	"408": {"traditional sources"},                                                                                                                                                                                                                // DEPRECATED: Information Gathering from Traditional Sources
	"409": {"non-traditional sources"},                                                                                                                                                                                                            // DEPRECATED: Information Gathering from Non-Traditional Sources
	"411": {"deprecated pretexting"},                                                                                                                                                                                                              // DEPRECATED: Pretexting
	"412": {"via customer", "customer service", "pretexting via customer", "via customer service", "pretexting via"},                                                                                                                              // Pretexting via Customer Service
	"413": {"via tech", "tech support", "pretexting via tech", "via tech support", "pretexting via"},                                                                                                                                              // Pretexting via Tech Support
	"414": {"via delivery", "delivery person", "via delivery person", "pretexting via delivery", "pretexting via"},                                                                                                                                // Pretexting via Delivery Person
	"415": {"via phone", "pretexting via phone", "pretexting via"},                                                                                                                                                                                // Pretexting via Phone
	"416": {"manipulate human", "human behavior", "manipulate human behavior"},                                                                                                                                                                    // Manipulate Human Behavior
	"418": {"perception of reciprocation"},                                                                                                                                                                                                        // Influence Perception of Reciprocation
	"419": {"via perception", "via perception of", "perception of concession", "influence via perception"},                                                                                                                                        // DEPRECATED: Target Influence via Perception of Concession
	"420": {"perception of scarcity"},                                                                                                                                                                                                             // Influence Perception of Scarcity
	"421": {"perception of authority"},                                                                                                                                                                                                            // Influence Perception of Authority
	"422": {"perception of commitment", "request individuals"},                                                                                                                                                                                    // Influence Perception of Commitment and Consistency
	"423": {"perception of liking"},                                                                                                                                                                                                               // Influence Perception of Liking
	"424": {"consensus or", "social proof", "perception of consensus", "consensus or social"},                                                                                                                                                     // Influence Perception of Consensus or Social Proof
	"425": {"via framing", "influence via framing"},                                                                                                                                                                                               // Target Influence via Framing
	"426": {"via incentives", "influence via incentives"},                                                                                                                                                                                         // Influence via Incentives
	"427": {"psychological principles", "via psychological", "influence via psychological", "via psychological principles"},                                                                                                                       // Influence via Psychological Principles
	"428": {"via modes", "modes of", "via modes of", "modes of thinking", "influence via modes"},                                                                                                                                                  // Influence via Modes of Thinking
	"429": {"via eye", "eye cues", "via eye cues", "influence via eye"},                                                                                                                                                                           // Target Influence via Eye Cues
	"430": {"via micro-expressions", "influence via micro-expressions"},                                                                                                                                                                           // DEPRECATED:  Target Influence via Micro-Expressions
	"431": {"neuro-linguistic programming", "via neuro-linguistic", "influence via neuro-linguistic", "via neuro-linguistic programming", "programming nlp", "neuro-linguistic programming nlp"},                                                  // DEPRECATED:  Target Influence via Neuro-Linguistic Programming (NLP)
	"432": {"via voice", "voice in", "influence via voice", "via voice in", "voice in nlp"},                                                                                                                                                       // DEPRECATED:  Target Influence via Voice in NLP
	"433": {"human buffer", "human buffer overflow", "overflow methodology", "buffer overflow methodology"},                                                                                                                                       // Target Influence via The Human Buffer Overflow
	"438": {"modification during", "during manufacture", "modification during manufacture", "assembly firmware", "firmware or basic", "firmware or"},                                                                                              // Modification During Manufacture
	"439": {"manipulation during", "during distribution", "manipulation during distribution"},                                                                                                                                                     // Manipulation During Distribution
	"440": {"hardware integrity"},                                                                                                                                                                                                                 // Hardware Integrity Attack
	"441": {"logic insertion"},                                                                                                                                                                                                                    // Malicious Logic Insertion
	"442": {"infected software", "legitimate code"},                                                                                                                                                                                               // Infected Software
	"443": {"logic inserted", "product by", "authorized developer", "product by authorized"},                                                                                                                                                      // Malicious Logic Inserted Into Product by Authorized Developer
	"444": {"development alteration", "code or to", "source code"},                                                                                                                                                                                // Development Alteration
	"445": {"via configuration", "product software", "software via", "configuration management", "management manipulation", "product software via", "software via configuration", "via configuration management"},                                 // Malicious Logic Insertion into Product Software via Configuration Management Manipulation
	"446": {"third-party component", "product via", "inclusion of third-party", "product via inclusion", "via inclusion", "inclusion of", "via inclusion of", "logic insertion"},                                                                  // Malicious Logic Insertion into Product via Inclusion of Third-Party Component
	"447": {"design alteration"},                                                                                                                                                                                                                  // Design Alteration
	"448": {"embed virus"},                                                                                                                                                                                                                        // Embed Virus into DLL
	"449": {"usb stick", "via usb stick", "via usb", "malware propagation", "propagation via", "propagation via usb", "malware propagation via", "deprecated malware"},                                                                            // DEPRECATED: Malware Propagation via USB Stick
	"450": {"usb u3", "via usb u3", "usb u3 autorun", "via usb", "malware propagation", "propagation via", "propagation via usb", "malware propagation via"},                                                                                      // DEPRECATED: Malware Propagation via USB U3 Autorun
	"451": {"via infected", "infected peripheral", "peripheral device", "infected peripheral device", "propagation via infected", "via infected peripheral", "propagation via", "malware propagation"},                                            // DEPRECATED: Malware Propagation via Infected Peripheral Device
	"452": {"infected hardware"},                                                                                                                                                                                                                  // Infected Hardware
	"453": {"via counterfeit", "insertion via counterfeit", "via counterfeit hardware", "insertion via", "logic insertion via", "counterfeit hardware", "logic insertion"},                                                                        // DEPRECATED: Malicious Logic Insertion via Counterfeit Hardware
	"454": {"existing components", "modification of existing", "deprecated modification", "modification of", "counterfeit hardware", "deprecated modification of"},                                                                                // DEPRECATED: Modification of Existing Components with Counterfeit Hardware
	"455": {"hardware components", "inclusion of counterfeit", "counterfeit hardware components", "insertion via inclusion", "insertion via", "via inclusion", "inclusion of", "via inclusion of"},                                                // DEPRECATED: Malicious Logic Insertion via Inclusion of Counterfeit Hardware Components
	"456": {"infected memory"},                                                                                                                                                                                                                    // Infected Memory
	"457": {"usb memory", "usb memory attacks", "memory attacks", "code onto", "code onto a"},                                                                                                                                                     // USB Memory Attacks
	"458": {"flash memory", "flash memory attacks", "memory attacks"},                                                                                                                                                                             // Flash Memory Attacks
	"459": {"creating a", "certification authority", "authority certificate", "rogue certification", "creating a rogue", "certification authority certificate", "rogue certification authority", "certificate"},                                   // Creating a Rogue Certification Authority Certificate
	"460": {"http parameter", "parameter pollution", "http parameter pollution", "hardcoded http", "duplicate http", "http get/post", "injecting query", "pollution hpp"},                                                                         // HTTP Parameter Pollution (HPP)
	"461": {"forgery leveraging", "leveraging hash", "signature forgery", "function extension", "services api", "hash function", "api signature", "extension weakness"},                                                                           // Web Services API Signature Forgery Leveraging Hash Function Extension Weakness
	"462": {"cross-domain search", "search timing", "cross-domain search timing", "domain http", "http /"},                                                                                                                                        // Cross-Domain Search Timing
	"463": {"oracle crypto", "padding oracle", "padding oracle crypto", "encryption key", "performing decryption", "perform encryption", "decryption an", "decryption key"},                                                                       // Padding Oracle Crypto Attack
	"464": {"cookie cache", "cookie in", "persistent cookie", "cookie", "cookie cache via", "cookie is stored", "cookie s resurrection", "cookie s"},                                                                                              // Evercookie
	"465": {"transparent proxy", "proxy abuse", "transparent proxy abuse"},                                                                                                                                                                        // Transparent Proxy Abuse
	"466": {"bypass same", "origin policy", "leveraging active", "same origin", "middle attacks", "attacks to", "bypass same origin", "attacks to bypass"},                                                                                        // Leveraging Active Adversary in the Middle Attacks to Bypass Same Origin Policy
	"467": {"site identification", "cross site identification", "cross site", "payload to", "payload to execute", "active session"},                                                                                                               // Cross Site Identification
	"468": {"cross-browser cross-domain", "cross-domain theft", "generic cross-browser", "cross-browser cross-domain theft", "generic cross-browser cross-domain", "css injection", "injection to steal", "injection to"},                         // Generic Cross-Browser Cross-Domain Theft
	"469": {"http dos", "session alive", "http sessions", "flooding at", "http level", "http session", "performs flooding", "initiated http"},                                                                                                     // HTTP DoS
	"470": {"sql injections", "command shell", "traditionally sql", "sql injections attacks", "command shell creating"},                                                                                                                           // Expanding Control over the Operating System from the Database
	"471": {"process binary", "binary resides"},                                                                                                                                                                                                   // Search Order Hijacking
	"472": {"browser fingerprinting", "java script", "script as", "page request", "request by", "script to efficiently", "script as a", "script to"},                                                                                              // Browser Fingerprinting
	"473": {"signature spoof"},                                                                                                                                                                                                                    // Signature Spoof
	"474": {"key theft", "spoofing by key", "signature spoofing", "spoofing by", "signature spoofing by", "private signature", "signature key", "signature key by"},                                                                               // Signature Spoofing by Key Theft
	"475": {"improper validation", "spoofing by improper", "signature without", "spoofing by", "signature spoofing", "signature verification algorithm", "signature without knowing", "signature spoofing by"},                                    // Signature Spoofing by Improper Validation
	"476": {"spoofing by misrepresentation", "display code", "spoofing by", "signature spoofing", "signature spoofing by", "valid signature"},                                                                                                     // Signature Spoofing by Misrepresentation
	"477": {"mixing signed", "unsigned content", "spoofing by mixing", "spoofing by", "signature spoofing", "signature spoofing by"},                                                                                                              // Signature Spoofing by Mixing Signed and Unsigned Content
	"478": {"windows service", "service configuration", "modification of windows", "windows service configuration", "binary in", "modification of"},                                                                                               // Modification of Windows Service Configuration
	"479": {"root certificate", "certificate", "certificate on", "over https", "https to", "certificate on a", "https"},                                                                                                                           // Malicious Root Certificate
	"480": {"escaping virtualization", "code within", "unauthorized code"},                                                                                                                                                                        // Escaping Virtualization
	"481": {"traffic routing", "contradictory destinations", "destinations in", "routing schemes", "traffic routing schemes", "contradictory destinations in", "destinations in traffic", "header an"},                                            // Contradictory Destinations in Traffic Routing Schemes
	"482": {"tcp flood", "tcp syn messages", "tcp protocol", "tcp syn"},                                                                                                                                                                           // TCP Flood
	"484": {"xml client-side", "deprecated xml client-side", "deprecated xml", "capec-230 xml", "xml oversized", "capec-231 xml", "xml nested", "xml nested payloads"},                                                                            // DEPRECATED: XML Client-Side Attack
	"485": {"key recreation", "spoofing by key", "signature algorithm", "spoofing by", "signature spoofing", "signature algorithm or", "signature spoofing by", "private signature"},                                                              // Signature Spoofing by Key Recreation
	"486": {"udp flood", "udp attacks", "udp connection", "firewall udp", "udp protocol", "udp port meaning", "dns or voip", "udp connection destined"},                                                                                           // UDP Flood
	"487": {"icmp flood", "icmp packets", "icmp protocol", "receiving icmp", "icmp packets at"},                                                                                                                                                   // ICMP Flood
	"488": {"http flood", "session-based http", "http protocol"},                                                                                                                                                                                  // HTTP Flood
	"489": {"ssl flood", "ssl", "ssl protocol", "https requests", "ssl connection", "https requests on", "https"},                                                                                                                                 // SSL Flood
	"490": {"service spoofing", "response is", "larger response", "initial request", "final payload", "payload delivered", "response is far", "payload delivered to"},                                                                             // Amplification
	"492": {"expression exponential", "exponential blowup", "regular expression", "regular expression exponential", "expression exponential blowup", "regex", "regex algorithm", "regex a"},                                                       // Regular Expression Exponential Blowup
	"493": {"array blowup", "soap array blowup", "soap array", "uses soap", "large soap", "soap messages in", "soap array declaration", "xml parser"},                                                                                             // SOAP Array Blowup
	"494": {"tcp fragmentation", "tcp packet"},                                                                                                                                                                                                    // TCP Fragmentation
	"495": {"udp fragmentation", "large udp", "udp packets", "typical udp", "udp packets over", "udp flood"},                                                                                                                                      // UDP Fragmentation
	"496": {"icmp fragmentation", "fragmented icmp", "icmp message", "icmp message to"},                                                                                                                                                           // ICMP Fragmentation
	"497": {"file discovery"},                                                                                                                                                                                                                     // File Discovery
	"498": {"probe ios", "ios screenshots", "probe ios screenshots"},                                                                                                                                                                              // Probe iOS Screenshots
	"499": {"android intent", "intent intercept", "android intent intercept", "injection an", "injection an implicit"},                                                                                                                            // Android Intent Intercept
	"500": {"webview injection", "injected code", "dom tree", "injects code", "dom", "code an"},                                                                                                                                                   // WebView Injection
	"501": {"android activity", "activity hijack", "android activity hijack"},                                                                                                                                                                     // Android Activity Hijack
	"502": {"intent spoof", "injection components", "request helping"},                                                                                                                                                                            // Intent Spoof
	"503": {"webview exposure"},                                                                                                                                                                                                                   // WebView Exposure
	"504": {"task impersonation"},                                                                                                                                                                                                                 // Task Impersonation
	"505": {"scheme squatting", "url scheme", "url scheme intended"},                                                                                                                                                                              // Scheme Squatting
	"507": {"physical theft"},                                                                                                                                                                                                                     // Physical Theft
	"508": {"shoulder surfing"},                                                                                                                                                                                                                   // Shoulder Surfing
	"509": {"request active", "request active directory", "kerberos authentication", "authentication protocol", "authentication protocol centers"},                                                                                                // Kerberoasting
	"510": {"request forgery", "authenticated session"},                                                                                                                                                                                           // SaaS User Request Forgery
	"511": {"infiltration of software", "software development environment", "infiltration of", "software development", "development environment"},                                                                                                 // Infiltration of Software Development Environment
	"516": {"substitution during", "during baselining", "component substitution during", "substitution during baselining", "component substitution", "hardware component substitution", "hardware component"},                                     // Hardware Component Substitution During Baselining
	"517": {"circumvent dial-down", "alteration to circumvent", "alteration to", "documentation alteration", "documentation alteration to"},                                                                                                       // Documentation Alteration to Circumvent Dial-down
	"518": {"under-performing systems", "produce under-performing", "produce under-performing systems", "alteration to produce", "documentation alteration", "alteration to", "documentation alteration to"},                                      // Documentation Alteration to Produce Under-performing Systems
	"519": {"errors in", "alteration to", "documentation alteration", "documentation alteration to"},                                                                                                                                              // Documentation Alteration to Cause Errors in System Design
	"520": {"inserted during", "during product", "product assembly", "component inserted", "counterfeit hardware component", "hardware component inserted", "during product assembly", "component inserted during"},                               // Counterfeit Hardware Component Inserted During Product Assembly
	"521": {"hardware design", "design specifications", "hardware design specifications"},                                                                                                                                                         // Hardware Design Specifications Are Altered
	"522": {"component replacement", "hardware component replacement", "hardware component"},                                                                                                                                                      // Malicious Hardware Component Replacement
	"523": {"software implanted"},                                                                                                                                                                                                                 // Malicious Software Implanted
	"524": {"integration procedures", "rogue integration", "rogue integration procedures"},                                                                                                                                                        // Rogue Integration Procedures
	"528": {"xml flood", "xml based", "xml based requests", "xml messages", "xml denial", "xml denial of"},                                                                                                                                        // XML Flood
	"529": {"malware-directed internal", "internal reconnaissance", "malware-directed internal reconnaissance"},                                                                                                                                   // Malware-Directed Internal Reconnaissance
	"530": {"provide counterfeit", "counterfeit component", "provide counterfeit component"},                                                                                                                                                      // Provide Counterfeit Component
	"531": {"component substitution", "hardware component substitution", "hardware component"},                                                                                                                                                    // Hardware Component Substitution
	"532": {"altered installed", "installed bios", "altered installed bios"},                                                                                                                                                                      // Altered Installed BIOS
	"533": {"manual software", "manual software update", "url attacks", "executable to as", "software update", "payload of", "executable to", "payload of a"},                                                                                     // Malicious Manual Software Update
	"534": {"hardware update"},                                                                                                                                                                                                                    // Malicious Hardware Update
	"535": {"gray market", "market hardware", "gray market hardware"},                                                                                                                                                                             // Malicious Gray Market Hardware
	"536": {"injected during", "during configuration", "injected during configuration"},                                                                                                                                                           // Data Injected During Configuration
	"537": {"hardware development", "infiltration of hardware", "hardware development environment", "infiltration of", "development environment", "and/or firmware", "firmware development", "firmware development environment"},                  // Infiltration of Hardware Development Environment
	"538": {"open-source library", "library manipulation", "open-source library manipulation", "code in open"},                                                                                                                                    // Open-Source Library Manipulation
	"540": {"overread buffers", "defined buffer", "code execution"},                                                                                                                                                                               // Overread Buffers
	"542": {"targeted malware"},                                                                                                                                                                                                                   // Targeted Malware
	"543": {"counterfeit websites"},                                                                                                                                                                                                               // Counterfeit Websites
	"544": {"counterfeit organizations"},                                                                                                                                                                                                          // Counterfeit Organizations
	"546": {"deletion in", "multi-tenant environment", "deletion in a"},                                                                                                                                                                           // Incomplete Data Deletion in a Multi-Tenant Environment
	"547": {"destruction of", "device or", "physical destruction", "physical destruction of", "destruction of device", "device or component"},                                                                                                     // Physical Destruction of Device or Component
	"548": {"contaminate resource"},                                                                                                                                                                                                               // Contaminate Resource
	"549": {"local execution", "execution of", "execution of code", "local execution of", "code on"},                                                                                                                                              // Local Execution of Code
	"551": {"modify existing", "existing service", "modify existing service"},                                                                                                                                                                     // Modify Existing Service
	"552": {"install rootkit", "authentication to install", "authentication to"},                                                                                                                                                                  // Install Rootkit
	"554": {"functionality bypass"},                                                                                                                                                                                                               // Functionality Bypass
	"555": {"remote services", "stolen credentials", "ssh", "telnet ssh"},                                                                                                                                                                         // Remote Services with Stolen Credentials
	"556": {"extension handlers", "replace file", "file extension handlers", "replace file extension", "file extension"},                                                                                                                          // Replace File Extension Handlers
	"557": {"software to", "schedule software", "schedule software to", "software to run", "deprecated schedule", "deprecated schedule software"},                                                                                                 // DEPRECATED: Schedule Software To Run
	"558": {"replace trusted", "trusted executable", "replace trusted executable", "executable is"},                                                                                                                                               // Replace Trusted Executable
	"559": {"orbital jamming"},                                                                                                                                                                                                                    // Orbital Jamming
	"560": {"known domain", "domain credentials", "known domain credentials", "achieve authentication"},                                                                                                                                           // Use of Known Domain Credentials
	"561": {"windows admin", "admin shares", "windows admin shares", "stolen credentials"},                                                                                                                                                        // Windows Admin Shares with Stolen Credentials
	"562": {"modify shared", "shared file", "modify shared file", "code to valid"},                                                                                                                                                                // Modify Shared File
	"563": {"shared webroot", "file to", "file to shared"},                                                                                                                                                                                        // Add Malicious File to Shared Webroot
	"564": {"run software", "software at", "software at logon", "run software at", "effectively bypass", "bypass workstation", "logon script", "additional code"},                                                                                 // Run Software at Logon
	"565": {"password spraying"},                                                                                                                                                                                                                  // Password Spraying
	"566": {"password hashes", "dump password", "dump password hashes", "deprecated dump", "deprecated dump password"},                                                                                                                            // DEPRECATED: Dump Password Hashes
	"567": {"via utilities", "deprecated obtain"},                                                                                                                                                                                                 // DEPRECATED: Obtain Data via Utilities
	"568": {"capture credentials", "credentials via", "via keylogger", "capture credentials via", "credentials via keylogger"},                                                                                                                    // Capture Credentials via Keylogger
	"569": {"provided by", "provided by users"},                                                                                                                                                                                                   // Collect Data as Provided by Users
	"570": {"signature-based avoidance", "deprecated signature-based", "deprecated signature-based avoidance"},                                                                                                                                    // DEPRECATED: Signature-Based Avoidance
	"571": {"central repository", "block logging", "logging to", "block logging to", "logging to central"},                                                                                                                                        // Block Logging to Central Repository
	"572": {"artificially inflate", "inflate file", "file sizes", "artificially inflate file", "inflate file sizes"},                                                                                                                              // Artificially Inflate File Sizes
	"573": {"process footprinting"},                                                                                                                                                                                                               // Process Footprinting
	"574": {"services footprinting"},                                                                                                                                                                                                              // Services Footprinting
	"575": {"account footprinting"},                                                                                                                                                                                                               // Account Footprinting
	"576": {"group permission", "permission footprinting", "group permission footprinting", "windows command"},                                                                                                                                    // Group Permission Footprinting
	"577": {"owner footprinting", "windows command"},                                                                                                                                                                                              // Owner Footprinting
	"579": {"helper dll", "replace winlogon", "winlogon helper", "replace winlogon helper", "winlogon helper dll", "adversarial code", "code at startup", "code at"},                                                                              // Replace Winlogon Helper DLL
	"581": {"software footprinting"},                                                                                                                                                                                                              // Security Software Footprinting
	"582": {"route disabling"},                                                                                                                                                                                                                    // Route Disabling
	"583": {"network hardware", "disabling network", "disabling network hardware"},                                                                                                                                                                // Disabling Network Hardware
	"584": {"bgp route", "bgp route disabling", "route disabling"},                                                                                                                                                                                // BGP Route Disabling
	"585": {"dns domain", "domain seizure", "dns domain seizure"},                                                                                                                                                                                 // DNS Domain Seizure
	"586": {"object injection", "deserialization", "serialization in", "leverage serialization", "static binary", "binary format", "deserialization process", "serialization"},                                                                    // Object Injection
	"587": {"frame scripting", "cross frame", "cross frame scripting", "scripting xfs", "frame scripting xfs"},                                                                                                                                    // Cross Frame Scripting (XFS)
	"588": {"dom-based xss", "dom", "bypass any", "script runs", "script launch", "includes script", "xss attacks", "model dom"},                                                                                                                  // DOM-Based XSS
	"589": {"dns blocking", "drops dns", "dns requests based", "request in", "dns requests"},                                                                                                                                                      // DNS Blocking
	"590": {"address blocking"},                                                                                                                                                                                                                   // IP Address Blocking
	"591": {"reflected xss", "script is reflected", "script to a", "script to", "script is"},                                                                                                                                                      // Reflected XSS
	"592": {"stored xss", "script is persistently", "script is"},                                                                                                                                                                                  // Stored XSS
	"593": {"performing authentication", "session hijacking", "active session"},                                                                                                                                                                   // Session Hijacking
	"594": {"traffic injection"},                                                                                                                                                                                                                  // Traffic Injection
	"595": {"connection reset"},                                                                                                                                                                                                                   // Connection Reset
	"596": {"rst injection", "tcp rst injection", "tcp rst", "tcp rst packets", "tcp connection"},                                                                                                                                                 // TCP RST Injection
	"597": {"absolute path", "absolute path traversal", "path traversal"},                                                                                                                                                                         // Absolute Path Traversal
	"598": {"dns spoofing", "record response", "request before", "route request", "dns a", "domain code", "code or dns", "request before a"},                                                                                                      // DNS Spoofing
	"599": {"terrestrial jamming"},                                                                                                                                                                                                                // Terrestrial Jamming
	"600": {"credential stuffing"},                                                                                                                                                                                                                // Credential Stuffing
	"602": {"deprecated degradation"},                                                                                                                                                                                                             // DEPRECATED: Degradation
	"604": {"wi-fi jamming"},                                                                                                                                                                                                                      // Wi-Fi Jamming
	"605": {"cellular jamming"},                                                                                                                                                                                                                   // Cellular Jamming
	"606": {"weakening of", "weakening of cellular", "cellular encryption", "breakable encryption", "encryption a5/1", "encryption a5/0", "encryption a5/1 or", "encryption a5/0 mode"},                                                           // Weakening of Cellular Encryption
	"608": {"cryptanalysis of", "cryptanalysis of cellular", "cellular encryption", "newer encryption", "encryption to", "encryption algorithms", "encryption algorithms in", "encryption to reveal"},                                             // Cryptanalysis of Cellular Encryption
	"609": {"cellular traffic", "traffic intercept", "cellular traffic intercept"},                                                                                                                                                                // Cellular Traffic Intercept
	"612": {"mac address", "address tracking", "wifi mac", "mac address tracking", "wifi mac address"},                                                                                                                                            // WiFi MAC Address Tracking
	"613": {"ssid tracking", "wifi ssid", "wifi ssid tracking"},                                                                                                                                                                                   // WiFi SSID Tracking
	"614": {"rooting sim", "sim cards", "rooting sim cards", "deliver executable", "signed binary", "binary sms", "executable code to", "binary sms messages"},                                                                                    // Rooting SIM Cards
	"615": {"evil twin", "twin wi-fi", "evil twin wi-fi"},                                                                                                                                                                                         // Evil Twin Wi-Fi Attack
	"616": {"establish rogue", "rogue location", "establish rogue location"},                                                                                                                                                                      // Establish Rogue Location
	"617": {"cellular rogue", "rogue base", "base station", "cellular rogue base", "rogue base station"},                                                                                                                                          // Cellular Rogue Base Station
	"618": {"cellular broadcast", "broadcast message", "cellular broadcast message", "broadcast message request", "message request", "area code", "code lac"},                                                                                     // Cellular Broadcast Message Request
	"619": {"signal strength", "strength tracking", "signal strength tracking", "request or", "message request"},                                                                                                                                  // Signal Strength Tracking
	"620": {"drop encryption", "encryption level", "drop encryption level", "encryption level to"},                                                                                                                                                // Drop Encryption Level
	"621": {"analysis of", "packet timing", "analysis of packet", "analyzing metadata"},                                                                                                                                                           // Analysis of Packet Timing and Sizes
	"622": {"electromagnetic side-channel"},                                                                                                                                                                                                       // Electromagnetic Side-Channel Attack
	"623": {"compromising emanations"},                                                                                                                                                                                                            // Compromising Emanations Attack
	"624": {"hardware fault", "hardware fault injection", "fault injection"},                                                                                                                                                                      // Hardware Fault Injection
	"625": {"mobile device", "device fault", "device fault injection", "mobile device fault", "fault injection", "injection attacks against", "injection attacks"},                                                                                // Mobile Device Fault Injection
	"627": {"counterfeit gps", "gps signals", "counterfeit gps signals"},                                                                                                                                                                          // Counterfeit GPS Signals
	"628": {"carry-off gps", "gps spoofing"},                                                                                                                                                                                                      // Carry-Off GPS Attack
	"629": {"device resources", "deprecated unauthorized"},                                                                                                                                                                                        // DEPRECATED: Unauthorized Use of Device Resources
	"630": {"url e", "url before", "url e g", "url before clicking"},                                                                                                                                                                              // TypoSquatting
	"632": {"via homoglyphs"},                                                                                                                                                                                                                     // Homograph Attack via Homoglyphs
	"633": {"token impersonation", "token", "token or", "impersonated token", "authentication to create", "token or equivalent", "authentication to"},                                                                                             // Token Impersonation
	"634": {"probe audio", "video peripherals"},                                                                                                                                                                                                   // Probe Audio and Video Peripherals
	"635": {"alternative execution", "execution due", "due to", "deceptive filenames", "alternative execution due", "execution due to", "due to deceptive"},                                                                                       // Alternative Execution Due to Deceptive Filenames
	"636": {"within files", "code within files", "code within"},                                                                                                                                                                                   // Hiding Malicious Data or Code within Files
	"638": {"component firmware", "altered component", "altered component firmware", "firmware altering", "protected firmware", "payload once", "firmware of", "payload at"},                                                                      // Altered Component Firmware
	"640": {"existing process", "inclusion of code", "code in existing", "injection thread", "vdso hijacking", "dll injection", "injection portable", "hijacking function"},                                                                       // Inclusion of Code in Existing Process
	"641": {"dll side-loading"},                                                                                                                                                                                                                   // DLL Side-Loading
	"642": {"replace binaries"},                                                                                                                                                                                                                   // Replace Binaries
	"643": {"identify shared", "shared files/directories", "files/directories on", "identify shared files/directories", "shared files/directories on"},                                                                                            // Identify Shared Files/Directories on System
	"644": {"captured hashes", "hashes pass", "ntlm authentication", "captured hashes pass", "authentication protocols"},                                                                                                                          // Use of Captured Hashes (Pass The Hash)
	"645": {"captured tickets", "tickets pass", "captured tickets pass", "kerberos authentication", "authentication protocol", "authentication protocol centers"},                                                                                 // Use of Captured Tickets (Pass The Ticket)
	"646": {"peripheral footprinting"},                                                                                                                                                                                                            // Peripheral Footprinting
	"647": {"authorization to", "authorization to gather"},                                                                                                                                                                                        // Collect Data from Registries
	"648": {"screen capture"},                                                                                                                                                                                                                     // Collect Data from Screen Capture
	"649": {"adding a", "space to", "adding a space", "space to a", "file extension"},                                                                                                                                                             // Adding a Space to a File Extension
	"650": {"web shell", "shell to", "upload a", "web shell to", "upload a web", "shell to a", "web server", "code at elevated"},                                                                                                                  // Upload a Web Shell to a Web Server
	"652": {"kerberos credentials", "known kerberos", "known kerberos credentials"},                                                                                                                                                               // Use of Known Kerberos Credentials
	"653": {"known operating", "achieve authentication"},                                                                                                                                                                                          // Use of Known Operating System Credentials
	"654": {"prompt impersonation", "credential prompt", "credential prompt impersonation"},                                                                                                                                                       // Credential Prompt Impersonation
	"655": {"tool identification", "identification by", "tool identification by", "identification by adding"},                                                                                                                                     // Avoid Security Tool Identification by Adding Data
	"656": {"voice phishing"},                                                                                                                                                                                                                     // Voice Phishing
	"657": {"via spoofing", "update via spoofing", "automated software", "update via", "spoofing content", "spoofing to", "protocol spoofing", "spoofing attacks"},                                                                                // Malicious Automated Software Update via Spoofing
	"660": {"via hooking", "evasion via hooking", "detection evasion", "evasion via", "root/jailbreak detection", "root/jailbreak detection evasion", "detection evasion via", "hook code"},                                                       // Root/Jailbreak Detection Evasion via Hooking
	"661": {"via debugging", "evasion via debugging", "detection evasion", "root/jailbreak detection", "evasion via", "bypass signature", "detection evasion via", "root/jailbreak detection evasion"},                                            // Root/Jailbreak Detection Evasion via Debugging
	"662": {"browser aitb"},                                                                                                                                                                                                                       // Adversary in the Browser (AiTB)
	"663": {"instruction execution", "transient instruction", "transient instruction execution", "exploitation of transient"},                                                                                                                     // Exploitation of Transient Instruction Execution
	"664": {"side request", "server side request", "side request forgery", "server side", "whereas csrf", "request either", "request forgery", "authentication controls"},                                                                         // Server Side Request Forgery
	"665": {"thunderbolt protection", "protection flaws", "exploitation of thunderbolt", "thunderbolt protection flaws", "firmware manipulation", "controller firmware", "subvert authentication", "firmware weakness"},                           // Exploitation of Thunderbolt Protection Flaws
	"666": {"bluetooth flooding", "flooding to", "flooding to transfer"},                                                                                                                                                                          // BlueSmacking
	"667": {"bluetooth impersonation", "impersonation attacks", "bluetooth impersonation attacks", "attacks bias", "impersonation attacks bias"},                                                                                                  // Bluetooth Impersonation AttackS (BIAS)
	"668": {"key negotiation", "negotiation of", "key negotiation of", "negotiation of bluetooth", "authentication process specifically", "authentication process"},                                                                               // Key Negotiation of Bluetooth Attack (KNOB)
	"669": {"alteration of", "alteration of a", "software update"},                                                                                                                                                                                // Alteration of a Software Update
	"670": {"development tools", "tools maliciously", "software development tools", "development tools maliciously", "tools maliciously altered", "software development", "maliciously altered"},                                                  // Software Development Tools Maliciously Altered
	"671": {"asic functionality", "functionality maliciously", "asic functionality maliciously", "functionality maliciously altered", "maliciously altered"},                                                                                      // Requirements for ASIC Functionality Maliciously Altered
	"672": {"implanted during", "during chip", "chip programming", "code implanted", "code implanted during", "implanted during chip", "during chip programming"},                                                                                 // Malicious Code Implanted During Chip Programming
	"673": {"signing maliciously", "altered software", "developer signing", "developer signing maliciously", "signing maliciously altered", "maliciously altered software", "maliciously altered"},                                                // Developer Signing Maliciously Altered Software
	"674": {"fpga maliciously", "fpga maliciously altered", "maliciously altered"},                                                                                                                                                                // Design for FPGA Maliciously Altered
	"675": {"decommissioned devices"},                                                                                                                                                                                                             // Retrieve Data from Decommissioned Devices
	"676": {"nosql injection", "authentication and/or", "executing code", "authentication and/or executing", "bypassing authentication"},                                                                                                          // NoSQL Injection
	"677": {"server motherboard", "motherboard compromise", "server motherboard compromise"},                                                                                                                                                      // Server Motherboard Compromise
	"678": {"maliciously altered"},                                                                                                                                                                                                                // System Build Data Maliciously Altered
	"679": {"improperly configured", "configured or", "implemented memory", "memory protections", "improperly configured or", "configured or implemented", "implemented memory protections", "exploitation of improperly"},                        // Exploitation of Improperly Configured or Implemented Memory Protections
	"680": {"controlled registers", "improperly controlled registers", "improperly controlled", "exploitation of improperly"},                                                                                                                     // Exploitation of Improperly Controlled Registers
	"681": {"controlled hardware", "improperly controlled hardware", "improperly controlled", "exploitation of improperly"},                                                                                                                       // Exploitation of Improperly Controlled Hardware Security Identifiers
	"682": {"rom code", "unpatchable vulnerabilities", "firmware or rom", "exploitation of firmware", "firmware or", "code i", "vulnerable code", "code i e"},                                                                                     // Exploitation of Firmware or ROM Code with Unpatchable Vulnerabilities
	"690": {"metadata spoofing", "metadata of", "metadata of a"},                                                                                                                                                                                  // Metadata Spoofing
	"691": {"spoof open-source", "open-source software", "software metadata", "spoof open-source software", "open-source software metadata", "metadata in", "metadata in an"},                                                                     // Spoof Open-Source Software Metadata
	"692": {"spoof version", "commit metadata", "spoofs metadata", "metadata pertaining", "metadata pertaining to"},                                                                                                                               // Spoof Version Control System Commit Metadata
	"693": {"popularity metadata", "metadata to", "metadata to deceive"},                                                                                                                                                                          // StarJacking
	"694": {"location discovery"},                                                                                                                                                                                                                 // System Location Discovery
	"695": {"repo jacking"},                                                                                                                                                                                                                       // Repo Jacking
	"696": {"value injection", "load value", "load value injection", "existing code", "code gadgets"},                                                                                                                                             // Load Value Injection
	"697": {"dhcp spoofing", "dhcp", "spoofing dhcp", "protocol dhcp", "dhcp server", "dhcp traffic", "spoofing dhcp traffic", "dhcp server by"},                                                                                                  // DHCP Spoofing
	"699": {"eavesdropping on", "eavesdropping on a"},                                                                                                                                                                                             // Eavesdropping on a Monitor
	"700": {"boundary bridging", "network boundary", "network boundary bridging"},                                                                                                                                                                 // Network Boundary Bridging
	"701": {"browser in", "middle bitm", "desktop session"},                                                                                                                                                                                       // Browser in the Middle (BiTM)
	"702": {"exploiting incorrect", "incorrect chaining", "chaining or", "debug components", "granularity of", "hardware debug", "granularity of hardware", "exploiting incorrect chaining"},                                                      // Exploiting Incorrect Chaining or Granularity of Hardware Debug Components
}

// Load CWE to CAPEC relationships from JSON file
func loadRelationships(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var relationships RelationshipsDB
	if err := json.Unmarshal(data, &relationships); err != nil {
		return err
	}

	cweToCapec = relationships.CWEToCapec
	return nil
}

func main() {
	cveID := flag.String("cve", "", "CVE ID to analyze")
	dataFile := flag.String("data", "capec_training_data.json", "CAPEC data file")
	relationshipsFile := flag.String("relationships", "relationships_db.json", "Relationships database file")
	topN := flag.Int("top", 5, "Number of top results to show")
	verbose := flag.Bool("v", false, "Verbose output with score breakdown")
	flag.Parse()

	if *cveID == "" {
		fmt.Println("Usage: capec-ranker-hybrid -cve CVE-ID [-data capec_training_data.json] [-relationships relationships_db.json] [-top N] [-v]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load relationships from file, fallback to minimal mappings if not found
	if err := loadRelationships(*relationshipsFile); err != nil {
		fmt.Printf("⚠ Warning: Could not load relationships from %s: %v\n", *relationshipsFile, err)
		fmt.Println("Using minimal fallback mappings...\n")
		cweToCapec = fallbackMappings
	} else {
		fmt.Printf("✓ Loaded %d CWE→CAPEC mappings from %s\n\n", len(cweToCapec), *relationshipsFile)
	}

	fmt.Println("================================================================================")
	fmt.Println("CAPEC RANKER - Hybrid Scoring (TF-IDF + CWE + Keywords + Metadata)")
	fmt.Println("================================================================================")

	// Step 1: Fetch CVE data
	fmt.Printf("\n[STEP 1] Fetching CVE data from NVD API...\n")
	description, cweIDs, err := fetchCVEData(*cveID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching CVE: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n[CVE INFORMATION]\n")
	fmt.Printf("ID: %s\n", *cveID)
	fmt.Printf("Description: %s\n", description)

	// Step 2: Display CWEs
	fmt.Printf("\n[RELATED CWEs] (%d)\n", len(cweIDs))
	if len(cweIDs) == 0 {
		fmt.Println("  No CWEs found for this CVE")
	} else {
		for _, cweID := range cweIDs {
			fmt.Printf("  • CWE-%s\n", cweID)
		}
	}

	// Step 3: Get candidate CAPECs from CWEs
	fmt.Printf("\n[STEP 2] Getting candidate CAPECs from CWE relationships...\n")
	candidateIDs := getCandidateCAPECs(cweIDs)

	// Step 3.5: Fallback if no candidates found (e.g., generic CWE-20)
	if len(candidateIDs) == 0 {
		fmt.Println("\n⚠ No direct CWE-to-CAPEC mapping found")
		fmt.Println("[STEP 2.5] Using keyword-based fallback...\n")

		// Load CAPEC data first for fallback
		allCAPECs, err := loadCAPECData(*dataFile)
		if err != nil {
			fmt.Printf("Error loading CAPEC data: %v\n", err)
			os.Exit(1)
		}

		candidateIDs = getCandidateCAPECsFallback(description, allCAPECs)

		if len(candidateIDs) == 0 {
			fmt.Println("\n⚠ No candidate CAPECs found even with fallback")
			os.Exit(0)
		}

	}

	fmt.Printf("\n[CANDIDATE CAPECs] (%d)\n", len(candidateIDs))
	for i, capecID := range candidateIDs {
		fmt.Printf("  %d. CAPEC-%s\n", i+1, capecID)
	}

	// Step 4: Load CAPEC data
	if *verbose {
		fmt.Printf("\n[STEP 3] Loading CAPEC data from %s...\n", *dataFile)
	}
	allCAPECs, err := loadCAPECData(*dataFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CAPEC data: %v\n", err)
		os.Exit(1)
	}

	// Step 5: Rank CAPECs using hybrid scoring
	fmt.Printf("\n[STEP 3] Ranking CAPECs using hybrid scoring...\n")
	if *verbose {
		fmt.Println("  Scoring components:")
		fmt.Println("    • TF-IDF Similarity (0-40 points)")
		fmt.Println("    • CWE Relationship (0-30 points)")
		fmt.Println("    • Keyword Matching (0-20 points)")
		fmt.Println("    • Metadata (Severity/Likelihood) (0-10 points)")
	}

	candidates := filterCandidates(allCAPECs, candidateIDs)
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No matching CAPEC data found\n")
		os.Exit(1)
	}

	ranked := rankCAPECsHybrid(description, cweIDs, candidates, *verbose)

	// Step 6: Display ranked results
	fmt.Println("\n================================================================================")
	fmt.Println("[RANKED CAPECs] (Top", min(*topN, len(ranked)), ")")
	fmt.Println("================================================================================\n")

	displayCount := min(*topN, len(ranked))
	for i := 0; i < displayCount; i++ {
		result := ranked[i]
		fmt.Printf("%d. CAPEC-%s: %s\n", i+1, result.CAPECID, result.Name)
		fmt.Printf("   Total Score: %.2f/100 (%s confidence)\n", result.TotalScore, result.Confidence)

		if *verbose {
			fmt.Printf("   Score Breakdown:\n")
			fmt.Printf("     - TF-IDF Similarity: %.2f/40\n", result.TFIDFScore)
			fmt.Printf("     - CWE Relationship: %.2f/30\n", result.CWEScore)
			fmt.Printf("     - Keyword Matching: %.2f/20\n", result.KeywordScore)
			fmt.Printf("     - Metadata: %.2f/10\n", result.MetadataScore)
		}

		if result.Severity != "" {
			fmt.Printf("   Severity: %s", result.Severity)
			if result.Likelihood != "" {
				fmt.Printf(" | Likelihood: %s", result.Likelihood)
			}
			fmt.Println()
		}

		if len(result.MatchedKeywords) > 0 {
			fmt.Printf("   Matched Keywords: %v\n", result.MatchedKeywords)
		}

		if i < displayCount-1 {
			fmt.Println()
		}
	}

	// Step 7: Highlight the selected CAPEC
	if len(ranked) > 0 {
		selected := ranked[0]
		fmt.Println("\n================================================================================")
		fmt.Println("[SELECTED CAPEC] (Highest Ranked)")
		fmt.Println("================================================================================\n")
		fmt.Printf("CAPEC-%s: %s\n", selected.CAPECID, selected.Name)
		fmt.Printf("Total Score: %.2f/100 (%s confidence)\n", selected.TotalScore, selected.Confidence)
		if *verbose {
			fmt.Printf("\nScore Breakdown:\n")
			fmt.Printf("  • TF-IDF Similarity: %.2f/40\n", selected.TFIDFScore)
			fmt.Printf("  • CWE Relationship: %.2f/30\n", selected.CWEScore)
			fmt.Printf("  • Keyword Matching: %.2f/20\n", selected.KeywordScore)
			fmt.Printf("  • Metadata: %.2f/10\n", selected.MetadataScore)
		}
		if selected.Severity != "" {
			fmt.Printf("Severity: %s", selected.Severity)
			if selected.Likelihood != "" {
				fmt.Printf(" | Likelihood: %s", selected.Likelihood)
			}
			fmt.Println()
		}
		if len(selected.MatchedKeywords) > 0 {
			fmt.Printf("Matched Keywords: %v\n", selected.MatchedKeywords)
		}
	}

	fmt.Println("\n================================================================================")
}

func rankCAPECsHybrid(cveDesc string, cweIDs []string, candidates []CAPECData, verbose bool) []RankedCAPEC {
	cveDescLower := strings.ToLower(cveDesc)

	// Tokenize CVE description for TF-IDF
	cveTokens := tokenize(cveDesc)
	cveTermFreq := calculateTermFrequency(cveTokens)

	// Calculate document frequency for TF-IDF
	docFreq := make(map[string]int)
	for _, capec := range candidates {
		capecText := capec.Description + " " + capec.Name + " " + strings.Join(capec.Prerequisites, " ")
		capecTokens := tokenize(capecText)
		uniqueTerms := make(map[string]bool)
		for _, term := range capecTokens {
			uniqueTerms[term] = true
		}
		for term := range uniqueTerms {
			docFreq[term]++
		}
	}

	cveTFIDF := calculateTFIDF(cveTermFreq, docFreq, len(candidates))

	var results []RankedCAPEC

	for _, capec := range candidates {
		// Component 1: TF-IDF Similarity (0-40 points)
		capecText := capec.Description + " " + capec.Name + " " + strings.Join(capec.Prerequisites, " ")
		capecTokens := tokenize(capecText)
		capecTermFreq := calculateTermFrequency(capecTokens)
		capecTFIDF := calculateTFIDF(capecTermFreq, docFreq, len(candidates))

		tfidfSimilarity := cosineSimilarity(cveTFIDF, capecTFIDF)
		tfidfScore := tfidfSimilarity * 40.0 // Scale to 0-40

		// Component 2: CWE Relationship Strength (0-30 points)
		cweScore := calculateCWEScore(capec, cweIDs)

		// Component 3: Keyword Matching (0-20 points)
		keywordScore, matchedKeywords := calculateKeywordScore(cveDescLower, capec.CAPECID)

		// Component 4: Metadata Score (0-10 points)
		metadataScore := calculateMetadataScore(capec)

		// Total Score
		totalScore := tfidfScore + cweScore + keywordScore + metadataScore

		// Single candidate boost (if only 1 CAPEC, ensure reasonable score)
		if len(candidates) == 1 && totalScore < 50 {
			totalScore = 50.0 // Minimum score for single candidate
		}

		// Determine confidence
		confidence := "low"
		if totalScore >= 70 {
			confidence = "high"
		} else if totalScore >= 50 {
			confidence = "medium"
		}

		// Find matched terms for display
		matchedTerms := findMatchedTerms(cveTokens, capecTokens)

		results = append(results, RankedCAPEC{
			CAPECID:         capec.CAPECID,
			Name:            capec.Name,
			TotalScore:      totalScore,
			TFIDFScore:      tfidfScore,
			CWEScore:        cweScore,
			KeywordScore:    keywordScore,
			MetadataScore:   metadataScore,
			Confidence:      confidence,
			Severity:        capec.TypicalSeverity,
			Likelihood:      capec.LikelihoodOfAttack,
			MatchedTerms:    matchedTerms,
			MatchedKeywords: matchedKeywords,
		})
	}

	// Sort by total score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].TotalScore > results[j].TotalScore
	})

	return results
}

func calculateCWEScore(capec CAPECData, cveWEs []string) float64 {
	// Base scores:
	// - Direct CWE match: 30 points × specificity weight
	// - Related CWE match: 15 points × specificity weight

	maxScore := 0.0

	for _, cweID := range cveWEs {
		for _, relatedCWE := range capec.RelatedCWEs {
			if relatedCWE == cweID {
				// Direct match - apply specificity weight
				specificity := getCWESpecificity(cweID)
				score := 30.0 * specificity
				if score > maxScore {
					maxScore = score
				}
			}
		}
	}

	// If no direct match, give partial credit
	if maxScore == 0 {
		maxScore = 15.0
	}

	return maxScore
}

func getCWESpecificity(cweID string) float64 {
	if weight, exists := cweSpecificity[cweID]; exists {
		return weight
	}
	// Default to medium specificity if not in map
	return 1.0
}

func calculateKeywordScore(cveDesc string, capecID string) (float64, []string) {
	keywords, exists := attackKeywords[capecID]
	if !exists {
		return 0.0, []string{}
	}

	var matched []string
	totalScore := 0.0

	for _, keyword := range keywords {
		if strings.Contains(cveDesc, keyword) {
			matched = append(matched, keyword)

			// Weight by keyword specificity (longer = more specific)
			wordCount := len(strings.Fields(keyword))
			if wordCount >= 3 {
				totalScore += 8.0 // Multi-word phrase (e.g., "session takeover")
			} else if wordCount == 2 {
				totalScore += 5.0 // Two-word phrase
			} else {
				totalScore += 3.0 // Single word
			}
		}
	}

	// Cap at 20 points
	if totalScore > 20.0 {
		totalScore = 20.0
	}

	return totalScore, matched
}

func calculateMetadataScore(capec CAPECData) float64 {
	score := 0.0

	// Severity scoring
	switch strings.ToLower(capec.TypicalSeverity) {
	case "very high":
		score += 6.0
	case "high":
		score += 5.0
	case "medium":
		score += 3.0
	case "low":
		score += 1.0
	}

	// Likelihood scoring
	switch strings.ToLower(capec.LikelihoodOfAttack) {
	case "high":
		score += 4.0
	case "medium":
		score += 2.0
	case "low":
		score += 1.0
	}

	return score
}

// ... (rest of the helper functions remain the same: fetchCVEData, getCandidateCAPECs, loadCAPECData, etc.)

func fetchCVEData(cveID string) (string, []string, error) {
	cveID = strings.ToUpper(cveID)
	if !strings.HasPrefix(cveID, "CVE-") {
		cveID = "CVE-" + cveID
	}

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=%s", cveID)
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return "", nil, err
	}

	if len(nvdResp.Vulnerabilities) == 0 {
		return "", nil, fmt.Errorf("CVE not found")
	}

	cve := nvdResp.Vulnerabilities[0].CVE

	var description string
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			description = desc.Value
			break
		}
	}

	var cweIDs []string
	for _, weakness := range cve.Weaknesses {
		for _, desc := range weakness.Description {
			if strings.HasPrefix(desc.Value, "CWE-") {
				cweID := strings.TrimPrefix(desc.Value, "CWE-")
				cweIDs = append(cweIDs, cweID)
			}
		}
	}

	return description, cweIDs, nil
}

func getCandidateCAPECs(cweIDs []string) []string {
	capecSet := make(map[string]bool)

	for _, cweID := range cweIDs {
		// Normalize CWE ID to match relationships file format (CWE-XXX)
		normalizedCWE := "CWE-" + cweID
		if capecs, exists := cweToCapec[normalizedCWE]; exists {
			if len(capecs) > 0 {
				// CWE has specific mappings
				for _, capecID := range capecs {
					capecSet[capecID] = true
				}
			}
			// If empty list (generic CWE like CWE-20), skip for now
			// Fallback will be handled in main()
		}
	}

	var candidates []string
	for capecID := range capecSet {
		candidates = append(candidates, capecID)
	}

	sort.Strings(candidates)
	return candidates
}

// Fallback: get CAPECs from CAPEC data based on keywords when CWE mapping is empty
func getCandidateCAPECsFallback(cveDesc string, allCAPECs map[string]CAPECData) []string {
	cveDescLower := strings.ToLower(cveDesc)

	// Define keyword-to-CAPEC patterns for common attack types
	keywordPatterns := map[string][]string{
		"session": {"31", "102", "196", "226"},      // Session attacks
		"cookie":  {"31", "102"},                    // Cookie manipulation
		"xss":     {"63", "588", "591", "592"},      // XSS variants
		"sql":     {"7", "66", "108", "109", "110"}, // SQL injection
		"command": {"88"},                           // Command injection
		"buffer":  {"8", "9", "10", "14", "24"},     // Buffer overflow
		"ldap":    {"136"},                          // LDAP injection
		"xpath":   {"83"},                           // XPath injection
		"xml":     {"250"},                          // XML injection
	}

	capecSet := make(map[string]bool)

	// Match keywords in CVE description
	for keyword, capecs := range keywordPatterns {
		if strings.Contains(cveDescLower, keyword) {
			for _, capecID := range capecs {
				// Only add if CAPEC exists in data
				if _, exists := allCAPECs[capecID]; exists {
					capecSet[capecID] = true
				}
			}
		}
	}

	var candidates []string
	for capecID := range capecSet {
		candidates = append(candidates, capecID)
	}

	sort.Strings(candidates)
	return candidates
}

func loadCAPECData(filename string) (map[string]CAPECData, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dataList []CAPECData
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&dataList); err != nil {
		return nil, err
	}

	dataMap := make(map[string]CAPECData)
	for _, capec := range dataList {
		dataMap[capec.CAPECID] = capec
	}

	return dataMap, nil
}

func filterCandidates(allCAPECs map[string]CAPECData, candidateIDs []string) []CAPECData {
	var candidates []CAPECData

	for _, id := range candidateIDs {
		if capec, exists := allCAPECs[id]; exists {
			candidates = append(candidates, capec)
		}
	}

	return candidates
}

func tokenize(text string) []string {
	text = strings.ToLower(text)

	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")
	cveRegex := regexp.MustCompile(`\bcve-\d{4}-\d+\b`)
	text = cveRegex.ReplaceAllString(text, "")

	wordRegex := regexp.MustCompile(`[a-z]{3,}`)
	words := wordRegex.FindAllString(text, -1)

	stopwords := map[string]bool{
		"the": true, "and": true, "for": true, "with": true, "from": true,
		"that": true, "this": true, "are": true, "was": true, "were": true,
		"been": true, "being": true, "have": true, "has": true, "had": true,
		"but": true, "not": true, "can": true, "will": true, "would": true,
		"could": true, "should": true, "may": true, "might": true, "must": true,
	}

	filtered := make([]string, 0, len(words))
	for _, word := range words {
		if !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

func calculateTermFrequency(tokens []string) map[string]float64 {
	freq := make(map[string]int)
	for _, token := range tokens {
		freq[token]++
	}

	tf := make(map[string]float64)
	maxFreq := 0
	for _, count := range freq {
		if count > maxFreq {
			maxFreq = count
		}
	}

	if maxFreq == 0 {
		return tf
	}

	for term, count := range freq {
		tf[term] = float64(count) / float64(maxFreq)
	}

	return tf
}

func calculateTFIDF(termFreq map[string]float64, docFreq map[string]int, totalDocs int) map[string]float64 {
	tfidf := make(map[string]float64)

	for term, tf := range termFreq {
		df := docFreq[term]
		if df == 0 {
			df = 1
		}
		idf := math.Log(float64(totalDocs) / float64(df))
		tfidf[term] = tf * idf
	}

	return tfidf
}

func cosineSimilarity(vec1, vec2 map[string]float64) float64 {
	dotProduct := 0.0
	for term, val1 := range vec1 {
		if val2, exists := vec2[term]; exists {
			dotProduct += val1 * val2
		}
	}

	mag1 := 0.0
	for _, val := range vec1 {
		mag1 += val * val
	}
	mag1 = math.Sqrt(mag1)

	mag2 := 0.0
	for _, val := range vec2 {
		mag2 += val * val
	}
	mag2 = math.Sqrt(mag2)

	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}

	return dotProduct / (mag1 * mag2)
}

func findMatchedTerms(tokens1, tokens2 []string) []string {
	set1 := make(map[string]bool)
	for _, token := range tokens1 {
		set1[token] = true
	}

	set2 := make(map[string]bool)
	for _, token := range tokens2 {
		set2[token] = true
	}

	var matched []string
	for term := range set1 {
		if set2[term] {
			matched = append(matched, term)
		}
	}

	return matched
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
