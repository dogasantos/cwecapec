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

// ============================================================================
// ESTRUTURAS DE DADOS - XML DO CWE (ENTRADA)
// ============================================================================

// WeaknessCatalog representa o catálogo completo de fraquezas CWE do XML do MITRE
type WeaknessCatalog struct {
	XMLName    xml.Name   `xml:"Weakness_Catalog"`    // Elemento raiz do XML
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"` // Lista de todas as fraquezas
	Categories []Category `xml:"Categories>Category"` // Lista de categorias (não usado atualmente)
}

// Weakness representa uma fraqueza individual (CWE) do catálogo XML
type Weakness struct {
	ID                string         `xml:"ID,attr"`                             // ID do CWE (ex: "89")
	Name              string         `xml:"Name,attr"`                           // Nome do CWE (ex: "SQL Injection")
	Abstraction       string         `xml:"Abstraction,attr"`                    // Nível de abstração (Base, Variant, Class, Pillar)
	Description       string         `xml:"Description"`                         // Descrição textual da fraqueza
	RelatedWeaknesses []Relationship `xml:"Related_Weaknesses>Related_Weakness"` // Relacionamentos hierárquicos
}

// Category representa uma categoria de CWEs (não usado atualmente, mas parseado)
type Category struct {
	ID            string         `xml:"ID,attr"`                  // ID da categoria
	Name          string         `xml:"Name,attr"`                // Nome da categoria
	Relationships []Relationship `xml:"Relationships>Has_Member"` // Membros da categoria
}

// Relationship representa um relacionamento entre CWEs (pai-filho, etc.)
type Relationship struct {
	Nature string `xml:"Nature,attr"`  // Tipo de relacionamento (ChildOf, ParentOf, etc.)
	CWEID  string `xml:"CWE_ID,attr"`  // ID do CWE relacionado
	ViewID string `xml:"View_ID,attr"` // ID da view (não usado atualmente)
}

// ============================================================================
// ESTRUTURAS DE DADOS - HIERARQUIA CWE (SAÍDA)
// ============================================================================

// CWEInfo contém informações processadas sobre um CWE específico,
// incluindo sua posição na hierarquia e vetores de ataque mapeados
type CWEInfo struct {
	ID            string   `json:"id"`             // ID do CWE (ex: "89")
	Name          string   `json:"name"`           // Nome do CWE (ex: "SQL Injection")
	Abstraction   string   `json:"abstraction"`    // Nível de abstração (Base, Variant, Class, Pillar)
	Parents       []string `json:"parents"`        // IDs dos CWEs pais diretos (relacionamento ChildOf)
	Children      []string `json:"children"`       // IDs dos CWEs filhos diretos (relacionamento ParentOf)
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque mapeados para este CWE
}

// CWEHierarchy é a estrutura de saída completa contendo todos os CWEs
// com suas relações hierárquicas e mapeamentos de vetores de ataque
type CWEHierarchy struct {
	CWEs                map[string]*CWEInfo `json:"cwes"`                  // Mapa de CWE ID para informações do CWE
	AttackVectorMapping map[string][]string `json:"attack_vector_mapping"` // Mapa de CWE ID para vetores de ataque
}

// ============================================================================
// MAPEAMENTO CWE → VETOR DE ATAQUE
// ============================================================================
// Este mapeamento manual conecta CWEs específicos aos vetores de ataque
// que eles representam. É o núcleo da primeira camada de classificação.
// Cada CWE pode mapear para múltiplos vetores de ataque relacionados.
// ============================================================================

var cweToAttackVector = map[string][]string{
	// ========================================================================
	// FAMÍLIA INJECTION (Injeção)
	// ========================================================================
	"74":   {"injection"},                     // Injection (pai genérico)
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
	"917":  {"jndi_injection", "rce"},         // Expression Language Injection (Log4Shell)
	"943":  {"nosql_injection"},               // NoSQL Injection
	"1336": {"ssti"},                          // Template Injection

	// ========================================================================
	// PATH TRAVERSAL (Travessia de Caminho)
	// ========================================================================
	"22": {"path_traversal"}, // Path Traversal
	"23": {"path_traversal"}, // Relative Path Traversal
	"36": {"path_traversal"}, // Absolute Path Traversal
	"73": {"path_traversal"}, // External Control of File Name

	// ========================================================================
	// AUTHENTICATION & AUTHORIZATION (Autenticação e Autorização)
	// ========================================================================
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
	"863": {"idor"},                            // Incorrect Authorization (IDOR)

	// ========================================================================
	// CSRF & SESSION (CSRF e Gerenciamento de Sessão)
	// ========================================================================
	"352": {"csrf"},             // Cross-Site Request Forgery
	"346": {"csrf"},             // Origin Validation Error
	"384": {"session_fixation"}, // Session Fixation
	"472": {"session_fixation"}, // External Control of Assumed-Immutable Web Parameter
	"613": {"session_fixation"}, // Insufficient Session Expiration

	// ========================================================================
	// INFORMATION DISCLOSURE (Divulgação de Informações)
	// ========================================================================
	"200": {"info_disclosure"}, // Exposure of Sensitive Information
	"201": {"info_disclosure"}, // Insertion of Sensitive Information Into Sent Data
	"209": {"info_disclosure"}, // Generation of Error Message Containing Sensitive Information
	"213": {"info_disclosure"}, // Exposure of Sensitive Information Due to Incompatible Policies
	"215": {"info_disclosure"}, // Insertion of Sensitive Information Into Debugging Code
	"359": {"info_disclosure"}, // Exposure of Private Personal Information
	"532": {"info_disclosure"}, // Insertion of Sensitive Information into Log File
	"538": {"info_disclosure"}, // Insertion of Sensitive Information into Externally-Accessible File

	// ========================================================================
	// DESERIALIZATION (Desserialização)
	// ========================================================================
	"502": {"deserialization", "rce"}, // Deserialization of Untrusted Data

	// ========================================================================
	// FILE UPLOAD (Upload de Arquivo)
	// ========================================================================
	"434": {"file_upload", "rce"}, // Unrestricted Upload of File with Dangerous Type
	"616": {"file_upload"},        // Incomplete Identification of Uploaded File Variables

	// ========================================================================
	// SSRF (Server-Side Request Forgery)
	// ========================================================================
	"918": {"ssrf"}, // Server-Side Request Forgery

	// ========================================================================
	// XXE (XML External Entity)
	// ========================================================================
	"611": {"xxe"}, // Improper Restriction of XML External Entity Reference
	"827": {"xxe"}, // Improper Control of Document Type Definition

	// ========================================================================
	// OPEN REDIRECT (Redirecionamento Aberto)
	// ========================================================================
	"601": {"open_redirect"}, // URL Redirection to Untrusted Site

	// ========================================================================
	// CRYPTOGRAPHIC FAILURES (Falhas Criptográficas)
	// ========================================================================
	"327": {"crypto_failure"},        // Use of a Broken or Risky Cryptographic Algorithm
	"328": {"crypto_failure"},        // Use of Weak Hash
	"330": {"crypto_failure"},        // Use of Insufficiently Random Values
	"331": {"crypto_failure"},        // Insufficient Entropy
	"326": {"crypto_failure"},        // Inadequate Encryption Strength
	"321": {"hardcoded_credentials"}, // Use of Hard-coded Cryptographic Key

	// ========================================================================
	// HARD-CODED CREDENTIALS (Credenciais Hardcoded)
	// ========================================================================
	"259": {"hardcoded_credentials"}, // Use of Hard-coded Password
	"798": {"hardcoded_credentials"}, // Use of Hard-coded Credentials

	// ========================================================================
	// BUFFER OVERFLOW (Estouro de Buffer)
	// ========================================================================
	"119": {"buffer_overflow", "rce"}, // Improper Restriction of Operations within the Bounds of a Memory Buffer
	"120": {"buffer_overflow"},        // Buffer Copy without Checking Size of Input
	"121": {"buffer_overflow"},        // Stack-based Buffer Overflow
	"122": {"buffer_overflow"},        // Heap-based Buffer Overflow
	"125": {"buffer_overflow"},        // Out-of-bounds Read
	"787": {"buffer_overflow", "rce"}, // Out-of-bounds Write

	// ========================================================================
	// INTEGER OVERFLOW (Estouro de Inteiro)
	// ========================================================================
	"190": {"integer_overflow"}, // Integer Overflow or Wraparound
	"191": {"integer_overflow"}, // Integer Underflow

	// ========================================================================
	// USE AFTER FREE (Uso Após Liberação)
	// ========================================================================
	"416": {"use_after_free", "rce"}, // Use After Free
	"415": {"use_after_free"},        // Double Free

	// ========================================================================
	// NULL POINTER (Ponteiro Nulo)
	// ========================================================================
	"476": {"null_pointer"}, // NULL Pointer Dereference
	"690": {"null_pointer"}, // Unchecked Return Value to NULL Pointer Dereference

	// ========================================================================
	// FORMAT STRING (String de Formato)
	// ========================================================================
	"134": {"format_string", "rce"}, // Use of Externally-Controlled Format String

	// ========================================================================
	// RACE CONDITION (Condição de Corrida)
	// ========================================================================
	"362": {"race_condition"}, // Concurrent Execution using Shared Resource with Improper Synchronization
	"366": {"race_condition"}, // Race Condition within a Thread
	"367": {"race_condition"}, // Time-of-check Time-of-use (TOCTOU) Race Condition

	// ========================================================================
	// DOS (Denial of Service)
	// ========================================================================
	"400": {"dos"}, // Uncontrolled Resource Consumption
	"770": {"dos"}, // Allocation of Resources Without Limits or Throttling
	"835": {"dos"}, // Loop with Unreachable Exit Condition
	"674": {"dos"}, // Uncontrolled Recursion
	"404": {"dos"}, // Improper Resource Shutdown or Release

	// ========================================================================
	// PRIVILEGE ESCALATION (Escalação de Privilégios)
	// ========================================================================
	"269": {"privilege_escalation"}, // Improper Privilege Management
	"250": {"privilege_escalation"}, // Execution with Unnecessary Privileges
	"266": {"privilege_escalation"}, // Incorrect Privilege Assignment
	"268": {"privilege_escalation"}, // Privilege Chaining
	"274": {"privilege_escalation"}, // Improper Handling of Insufficient Privileges

	// ========================================================================
	// INPUT VALIDATION (Validação de Entrada - Genérico)
	// ========================================================================
	"20":   {"input_validation"}, // Improper Input Validation
	"129":  {"input_validation"}, // Improper Validation of Array Index
	"1284": {"input_validation"}, // Improper Validation of Specified Quantity in Input
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra o download, parsing e
 *            construção da hierarquia CWE completa
 * Objetivo: Criar um arquivo JSON estruturado contendo todos os CWEs do MITRE
 *           com suas relações hierárquicas (pais/filhos) e mapeamentos para
 *           vetores de ataque, permitindo classificação eficiente de CVEs
 * Como faz: 1. Baixa o arquivo XML mais recente do CWE do site do MITRE (formato ZIP)
 *           2. Extrai e parseia o XML para estruturas Go
 *           3. Constrói a hierarquia de CWEs com relacionamentos pai-filho
 *           4. Aplica os mapeamentos manuais de CWE para vetor de ataque
 *           5. Salva a hierarquia completa em JSON formatado
 *           6. Exibe estatísticas de cobertura de mapeamento
 * Input: Nenhum (baixa dados do MITRE automaticamente)
 *        URL: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
 * Output: Arquivo resources/cwe_hierarchy.json contendo:
 *         - Informações de todos os CWEs (ID, nome, abstração)
 *         - Relacionamentos hierárquicos (pais e filhos)
 *         - Mapeamentos de CWE para vetores de ataque
 *         - Estatísticas de cobertura no console
 * Por que faz: A hierarquia CWE é fundamental para a classificação de CVEs.
 *              Este programa cria a base de conhecimento que permite:
 *              - Mapear CWEs conhecidos para vetores de ataque
 *              - Navegar pela hierarquia (usar CWEs pais quando necessário)
 *              - Manter os dados atualizados com a versão mais recente do MITRE
 */
func main() {
	fmt.Println("=================================================================")
	fmt.Println("CWE Hierarchy Builder")
	fmt.Println("=================================================================\n")

	// Baixar o XML do CWE do MITRE
	fmt.Println("Downloading CWE XML from MITRE...")
	cweXML, err := downloadCWEXML()
	if err != nil {
		fmt.Printf("Error downloading CWE XML: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Downloaded successfully\n")

	// Parsear o XML do CWE
	fmt.Println("Parsing CWE XML...")
	catalog, err := parseCWEXML(cweXML)
	if err != nil {
		fmt.Printf("Error parsing CWE XML: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Parsed %d weaknesses\n\n", len(catalog.Weaknesses))

	// Construir a hierarquia
	fmt.Println("Building CWE hierarchy...")
	hierarchy := buildHierarchy(catalog)
	fmt.Printf("Built hierarchy for %d CWEs\n\n", len(hierarchy.CWEs))

	// Salvar em JSON
	outputFile := "resources/cwe_hierarchy.json"
	fmt.Printf("Saving hierarchy to: %s\n", outputFile)
	if err := saveHierarchy(hierarchy, outputFile); err != nil {
		fmt.Printf("Error saving hierarchy: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Hierarchy saved successfully!")

	// Estatísticas
	fmt.Println("\n=================================================================")
	fmt.Println("Statistics:")
	fmt.Println("=================================================================")
	fmt.Printf("  Total CWEs: %d\n", len(hierarchy.CWEs))

	// Contar quantos CWEs têm mapeamentos de vetor de ataque
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

// ============================================================================
// FUNÇÕES DE DOWNLOAD E PARSING
// ============================================================================

/*
 * Função: downloadCWEXML
 * Descrição: Baixa o arquivo XML mais recente do CWE do site do MITRE,
 *            extrai do ZIP e retorna o conteúdo XML
 * Objetivo: Obter automaticamente a versão mais atual do catálogo CWE
 *           sem necessidade de download manual
 * Como faz: 1. Faz requisição HTTP GET para o URL do MITRE
 *           2. Verifica se a resposta é HTTP 200 (sucesso)
 *           3. Lê o conteúdo do arquivo ZIP em memória
 *           4. Abre o ZIP e procura por arquivo .xml
 *           5. Extrai e retorna o conteúdo do arquivo XML
 * Input: Nenhum (URL hardcoded: https://cwe.mitre.org/data/xml/cwec_latest.xml.zip)
 * Output: ([]byte, error) - Conteúdo do arquivo XML ou erro
 * Por que faz: O MITRE atualiza regularmente o catálogo CWE com novos CWEs e
 *              correções. Baixar automaticamente garante que sempre usamos a
 *              versão mais recente sem intervenção manual.
 */
func downloadCWEXML() ([]byte, error) {
	url := "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

	// Fazer requisição HTTP GET
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Verificar código de status HTTP
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Ler o arquivo ZIP completo em memória
	zipData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Abrir o arquivo ZIP
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, err
	}

	// Procurar e extrair o arquivo XML do ZIP
	for _, file := range zipReader.File {
		if strings.HasSuffix(file.Name, ".xml") {
			rc, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()

			// Ler e retornar o conteúdo do XML
			return io.ReadAll(rc)
		}
	}

	return nil, fmt.Errorf("no XML file found in ZIP")
}

/*
 * Função: parseCWEXML
 * Descrição: Parseia o conteúdo XML do CWE em estruturas Go
 * Objetivo: Converter o XML do MITRE em estruturas de dados manipuláveis
 * Como faz: 1. Cria uma estrutura WeaknessCatalog vazia
 *           2. Usa xml.Unmarshal para desserializar o XML
 *           3. Retorna o ponteiro para o catálogo parseado
 * Input: data ([]byte) - Conteúdo do arquivo XML do CWE
 * Output: (*WeaknessCatalog, error) - Catálogo parseado ou erro
 * Por que faz: O XML precisa ser convertido em estruturas Go para que possamos
 *              processar programaticamente os CWEs e seus relacionamentos.
 */
func parseCWEXML(data []byte) (*WeaknessCatalog, error) {
	var catalog WeaknessCatalog
	if err := xml.Unmarshal(data, &catalog); err != nil {
		return nil, err
	}
	return &catalog, nil
}

// ============================================================================
// FUNÇÃO DE CONSTRUÇÃO DA HIERARQUIA
// ============================================================================

/*
 * Função: buildHierarchy
 * Descrição: Constrói a hierarquia CWE completa a partir do catálogo XML parseado,
 *            incluindo relacionamentos pai-filho e mapeamentos de vetores de ataque
 * Objetivo: Criar uma estrutura de dados otimizada para consulta rápida que contém:
 *           - Todos os CWEs com suas informações básicas
 *           - Relacionamentos hierárquicos bidirecionais (pais e filhos)
 *           - Mapeamentos de CWE para vetores de ataque
 * Como faz: 1. PRIMEIRA PASSAGEM - Criar entradas para todos os CWEs:
 *              a. Itera por todas as fraquezas do catálogo
 *              b. Para cada fraqueza, cria uma estrutura CWEInfo
 *              c. Copia informações básicas (ID, nome, abstração)
 *              d. Inicializa listas vazias de pais, filhos e vetores
 *              e. Busca no mapa cweToAttackVector se há mapeamento manual
 *              f. Se existir, adiciona os vetores de ataque ao CWE
 *              g. Armazena no mapa de CWEs
 *           2. SEGUNDA PASSAGEM - Construir relacionamentos hierárquicos:
 *              a. Itera novamente por todas as fraquezas
 *              b. Para cada relacionamento do tipo "ChildOf":
 *                 - Adiciona o CWE pai à lista de pais do CWE atual
 *                 - Adiciona o CWE atual à lista de filhos do CWE pai
 *           3. Retorna a hierarquia completa
 * Input: catalog (*WeaknessCatalog) - Catálogo CWE parseado do XML
 * Output: *CWEHierarchy - Hierarquia completa com todos os CWEs, relacionamentos
 *         e mapeamentos de vetores de ataque
 * Por que faz: A hierarquia CWE é complexa com centenas de CWEs e relacionamentos.
 *              Esta função organiza tudo em uma estrutura eficiente que permite:
 *              - Consulta rápida de qualquer CWE por ID (O(1))
 *              - Navegação pela hierarquia (pais e filhos)
 *              - Mapeamento direto de CWE para vetores de ataque
 *              - Uso eficiente de memória (ponteiros para CWEInfo)
 */
func buildHierarchy(catalog *WeaknessCatalog) *CWEHierarchy {
	// Inicializar a estrutura de hierarquia
	hierarchy := &CWEHierarchy{
		CWEs:                make(map[string]*CWEInfo),
		AttackVectorMapping: make(map[string][]string),
	}

	// ========================================================================
	// PRIMEIRA PASSAGEM: Criar todas as entradas de CWE
	// ========================================================================
	for _, weakness := range catalog.Weaknesses {
		cweInfo := &CWEInfo{
			ID:            weakness.ID,
			Name:          weakness.Name,
			Abstraction:   weakness.Abstraction,
			Parents:       []string{},
			Children:      []string{},
			AttackVectors: []string{},
		}

		// Mapear para vetores de ataque se disponível no mapeamento manual
		if vectors, exists := cweToAttackVector[weakness.ID]; exists {
			cweInfo.AttackVectors = vectors
			hierarchy.AttackVectorMapping[weakness.ID] = vectors
		}

		hierarchy.CWEs[weakness.ID] = cweInfo
	}

	// ========================================================================
	// SEGUNDA PASSAGEM: Construir relacionamentos hierárquicos
	// ========================================================================
	for _, weakness := range catalog.Weaknesses {
		cweInfo := hierarchy.CWEs[weakness.ID]

		for _, rel := range weakness.RelatedWeaknesses {
			if rel.Nature == "ChildOf" {
				// Este CWE é filho de rel.CWEID
				cweInfo.Parents = append(cweInfo.Parents, rel.CWEID)

				// Adicionar este CWE como filho do pai (relacionamento bidirecional)
				if parent, exists := hierarchy.CWEs[rel.CWEID]; exists {
					parent.Children = append(parent.Children, weakness.ID)
				}
			}
		}
	}

	return hierarchy
}

// ============================================================================
// FUNÇÃO DE PERSISTÊNCIA
// ============================================================================

/*
 * Função: saveHierarchy
 * Descrição: Serializa e salva a hierarquia CWE completa em um arquivo JSON formatado
 * Objetivo: Persistir a hierarquia construída em disco para uso pelos componentes
 *           da pipeline de classificação
 * Como faz: 1. Cria (ou sobrescreve) o arquivo de saída
 *           2. Configura o encoder JSON com indentação de 2 espaços
 *           3. Serializa a estrutura CWEHierarchy completa para JSON
 *           4. Escreve o JSON formatado no arquivo
 * Input: hierarchy (*CWEHierarchy) - Hierarquia completa a ser salva
 *        filename (string) - Caminho do arquivo de saída
 * Output: error - nil se bem-sucedido, erro caso contrário
 * Por que faz: A hierarquia CWE é usada por múltiplos componentes da pipeline:
 *              - phase3-classifier: para classificação baseada em CWE
 *              - phase4-relationship: para ranqueamento de CWEs
 *              - batch-vector-reclassify: para reclassificação em lote
 *              Salvar em JSON permite reutilização sem necessidade de reconstruir.
 */
func saveHierarchy(hierarchy *CWEHierarchy, filename string) error {
	// Criar o arquivo de saída (sobrescreve se já existir)
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Configurar o encoder JSON com indentação para legibilidade
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 2 espaços de indentação

	// Serializar e escrever a hierarquia no arquivo
	return encoder.Encode(hierarchy)
}
