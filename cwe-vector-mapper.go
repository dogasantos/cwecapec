package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// ============================================================================
// ESTRUTURAS DE DADOS
// ============================================================================

// CWEFrequency representa a frequência de ocorrência de um CWE específico
// dentro de um vetor de ataque, incluindo estatísticas de ranking e percentual
type CWEFrequency struct {
	CWEID      string  `json:"cwe_id"`     // ID do CWE (ex: "89" para SQL Injection)
	Count      int     `json:"count"`      // Número de vezes que este CWE aparece
	Percentage float64 `json:"percentage"` // Percentual em relação ao total de CVEs do vetor
	Rank       int     `json:"rank"`       // Posição no ranking (1 = mais frequente)
}

// VectorStats contém estatísticas agregadas de um vetor de ataque específico,
// incluindo todas as frequências de CWEs associados a ele
type VectorStats struct {
	TotalCVEs      int            `json:"total_cves"`      // Total de CVEs classificados neste vetor
	CWEFrequencies []CWEFrequency `json:"cwe_frequencies"` // Lista de CWEs ordenada por frequência
	TopCWEs        []string       `json:"top_cwes"`        // IDs dos CWEs mais frequentes
	CWECounts      map[string]int `json:"cwe_counts"`      // Mapa de contagens brutas por CWE
}

// CWEFrequencyMap é a estrutura completa do mapa de frequências gerado pelo
// cwe-frequency-analyzer, contendo estatísticas globais e por vetor de ataque
type CWEFrequencyMap struct {
	GeneratedAt   string                  `json:"generated_at"`    // Timestamp de geração
	TotalCVEs     int                     `json:"total_cves"`      // Total de CVEs no dataset
	AttackVectors map[string]*VectorStats `json:"attack_vectors"`  // Estatísticas por vetor de ataque
	GlobalTopCWEs []CWEFrequency          `json:"global_top_cwes"` // CWEs mais frequentes globalmente
}

// AttackVectorToCWEsMap é a estrutura de saída simplificada que mapeia
// cada vetor de ataque para uma lista dos seus CWEs mais frequentes
type AttackVectorToCWEsMap map[string][]string

// ============================================================================
// CONSTANTES DE CONFIGURAÇÃO
// ============================================================================

const (
	resourcesPath = "resources"                                      // Diretório de recursos
	inputPath     = resourcesPath + "/cwe_frequency_map.json"        // Arquivo de entrada (do cwe-frequency-analyzer)
	outputPath    = resourcesPath + "/attack_vector_to_cwe_map.json" // Arquivo de saída simplificado
	topN          = 5                                                // Número de CWEs mais frequentes a incluir para cada vetor
)

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra todo o processo de
 *            mapeamento simplificado de vetores de ataque para CWEs
 * Objetivo: Converter o mapa de frequências detalhado (gerado pelo cwe-frequency-analyzer)
 *           em um mapeamento simplificado e otimizado para consultas rápidas, contendo
 *           apenas os top N CWEs mais relevantes para cada vetor de ataque
 * Como faz: 1. Carrega o arquivo de frequências completo (JSON)
 *           2. Extrai os top N CWEs de cada vetor de ataque
 *           3. Gera um mapeamento simplificado (vetor -> lista de CWEs)
 *           4. Salva o resultado em formato JSON otimizado
 *           5. Exibe uma amostra dos resultados no console
 * Input: Arquivo resources/cwe_frequency_map.json (gerado pelo cwe-frequency-analyzer)
 * Output: Arquivo resources/attack_vector_to_cwe_map.json (mapeamento simplificado)
 *         e exibição de amostra no console
 */
func main() {
	fmt.Println("=================================================================")
	fmt.Println("CWE Vector Mapper")
	fmt.Printf("Generates simplified Attack Vector -> Top %d CWEs map\n", topN)
	fmt.Println("=================================================================\n")

	// Carregar o mapa de frequências do arquivo de entrada
	fmt.Printf("Loading frequency map from %s... ", inputPath)
	freqMap, err := loadFrequencyMap(inputPath)
	if err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Gerar o mapeamento simplificado
	fmt.Printf("Generating Attack Vector -> Top %d CWEs map... ", topN)
	simplifiedMap := generateSimplifiedMap(freqMap)
	fmt.Println("✓")

	// Salvar os resultados no arquivo de saída
	fmt.Printf("Saving results to %s... ", outputPath)
	if err := saveSimplifiedMap(simplifiedMap, outputPath); err != nil {
		fmt.Printf("✗\nError: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✓")

	// Exibir uma amostra dos resultados para verificação
	displaySample(simplifiedMap)
}

// ============================================================================
// FUNÇÕES DE PROCESSAMENTO
// ============================================================================

/*
 * Função: loadFrequencyMap
 * Descrição: Carrega e desserializa o arquivo JSON contendo o mapa completo
 *            de frequências de CWEs por vetor de ataque
 * Objetivo: Ler o arquivo de entrada gerado pelo cwe-frequency-analyzer e
 *           convertê-lo em uma estrutura de dados Go para processamento
 * Como faz: 1. Abre o arquivo especificado pelo caminho
 *           2. Lê todo o conteúdo do arquivo em memória
 *           3. Desserializa o JSON para a estrutura CWEFrequencyMap
 *           4. Retorna o ponteiro para a estrutura preenchida
 * Input: path (string) - Caminho completo para o arquivo cwe_frequency_map.json
 * Output: (*CWEFrequencyMap, error) - Ponteiro para o mapa de frequências carregado
 *         ou erro se houver falha na leitura/parsing
 * Por que faz: É necessário carregar os dados de frequência para poder extrair
 *              os top N CWEs de cada vetor de ataque. O arquivo de entrada contém
 *              estatísticas detalhadas que serão simplificadas por esta ferramenta.
 */
func loadFrequencyMap(path string) (*CWEFrequencyMap, error) {
	// Abrir o arquivo de entrada
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Ler todo o conteúdo do arquivo
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	// Desserializar JSON para a estrutura Go
	freqMap := &CWEFrequencyMap{}
	if err := json.Unmarshal(data, freqMap); err != nil {
		return nil, err
	}

	return freqMap, nil
}

/*
 * Função: generateSimplifiedMap
 * Descrição: Cria um mapeamento simplificado que associa cada vetor de ataque
 *            aos seus top N CWEs mais frequentes, descartando estatísticas detalhadas
 * Objetivo: Gerar uma estrutura de dados otimizada para consultas rápidas, permitindo
 *           que outros componentes da pipeline (como classificadores) obtenham rapidamente
 *           os CWEs mais relevantes para um vetor de ataque sem processar estatísticas completas
 * Como faz: 1. Cria um mapa vazio para armazenar o resultado
 *           2. Ordena os vetores de ataque alfabeticamente para saída consistente
 *           3. Para cada vetor de ataque:
 *              a. Acessa as estatísticas completas do vetor
 *              b. Extrai os primeiros N CWEs da lista de frequências (já ordenada)
 *              c. Adiciona a lista de CWEs ao mapa simplificado
 *           4. Retorna o mapeamento completo
 * Input: freqMap (*CWEFrequencyMap) - Ponteiro para o mapa de frequências completo
 *        carregado do arquivo de entrada
 * Output: AttackVectorToCWEsMap - Mapa simplificado onde cada chave é um vetor de ataque
 *         (string) e cada valor é uma lista dos top N CWEs ([]string) mais frequentes
 *         Exemplo: {"sql_injection": ["89", "20", "79"], "xss": ["79", "80", "20"]}
 * Por que faz: O mapa de frequências completo contém muitas estatísticas detalhadas
 *              (contagens, percentuais, rankings) que não são necessárias para consultas
 *              rápidas. Este mapeamento simplificado reduz o tamanho dos dados e acelera
 *              a tradução de vetores de ataque para CWEs durante a classificação.
 */
func generateSimplifiedMap(freqMap *CWEFrequencyMap) AttackVectorToCWEsMap {
	// Inicializar o mapa de saída
	simplifiedMap := make(AttackVectorToCWEsMap)

	// Extrair e ordenar os nomes dos vetores de ataque para saída consistente
	var vectors []string
	for vector := range freqMap.AttackVectors {
		vectors = append(vectors, vector)
	}
	sort.Strings(vectors) // Ordenação alfabética para determinismo

	// Processar cada vetor de ataque
	for _, vector := range vectors {
		stats := freqMap.AttackVectors[vector]
		var topCWEs []string

		// Extrair os top N CWEs da lista de frequências
		// A lista CWEFrequencies já vem ordenada por frequência (do mais para o menos frequente)
		for i := 0; i < topN && i < len(stats.CWEFrequencies); i++ {
			// Usar IDs brutos (ex: "89") para compatibilidade com o código Go existente
			// Nota: Poderia usar "CWE-89" para maior clareza, mas mantemos consistência
			topCWEs = append(topCWEs, stats.CWEFrequencies[i].CWEID)
		}

		// Adicionar ao mapa simplificado apenas se houver CWEs
		if len(topCWEs) > 0 {
			simplifiedMap[vector] = topCWEs
		}
	}

	return simplifiedMap
}

/*
 * Função: saveSimplifiedMap
 * Descrição: Serializa e salva o mapeamento simplificado em um arquivo JSON
 *            formatado e legível
 * Objetivo: Persistir o mapeamento simplificado em disco para que possa ser
 *           carregado rapidamente por outros componentes da pipeline (classificadores)
 *           sem necessidade de reprocessar os dados de frequência completos
 * Como faz: 1. Cria (ou sobrescreve) o arquivo de saída
 *           2. Configura o encoder JSON com indentação para legibilidade
 *           3. Serializa a estrutura AttackVectorToCWEsMap para JSON
 *           4. Escreve o JSON formatado no arquivo
 * Input: simplifiedMap (AttackVectorToCWEsMap) - Mapa simplificado gerado pela função
 *        generateSimplifiedMap
 *        path (string) - Caminho completo onde o arquivo JSON será salvo
 * Output: error - nil se a operação foi bem-sucedida, ou erro descrevendo a falha
 *         (ex: permissões de arquivo, disco cheio, etc.)
 * Por que faz: O mapeamento simplificado precisa ser persistido em disco para ser
 *              reutilizado por outros programas da pipeline. O formato JSON com
 *              indentação facilita a inspeção manual e depuração dos dados.
 */
func saveSimplifiedMap(simplifiedMap AttackVectorToCWEsMap, path string) error {
	// Criar o arquivo de saída (sobrescreve se já existir)
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Configurar o encoder JSON com indentação de 2 espaços
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Formato legível para humanos

	// Serializar e escrever o mapa no arquivo
	return encoder.Encode(simplifiedMap)
}

// ============================================================================
// FUNÇÕES DE EXIBIÇÃO
// ============================================================================

/*
 * Função: displaySample
 * Descrição: Exibe no console uma amostra representativa do mapeamento simplificado
 *            gerado, mostrando alguns dos vetores de ataque mais críticos
 * Objetivo: Fornecer feedback visual imediato ao usuário sobre o resultado da operação,
 *           permitindo verificar rapidamente se o mapeamento foi gerado corretamente
 *           sem precisar abrir o arquivo JSON
 * Como faz: 1. Imprime um cabeçalho formatado
 *           2. Define uma lista de vetores de ataque chave para exibição
 *           3. Para cada vetor na lista:
 *              a. Verifica se o vetor existe no mapa simplificado
 *              b. Se existir, formata e imprime o vetor com seus top CWEs
 *           4. Imprime "..." para indicar que há mais dados não exibidos
 * Input: simplifiedMap (AttackVectorToCWEsMap) - Mapa simplificado completo gerado
 * Output: Nenhum (void) - A função apenas imprime no stdout
 * Por que faz: Facilita a validação rápida dos resultados sem precisar abrir e
 *              inspecionar o arquivo JSON. Mostra os vetores mais críticos (Tier 1)
 *              para confirmar que o mapeamento contém os dados esperados.
 */
func displaySample(simplifiedMap AttackVectorToCWEsMap) {
	fmt.Println("\n=================================================================")
	fmt.Println("Sample of Generated Map (Attack Vector -> Top CWEs)")
	fmt.Println("=================================================================")

	// Lista de vetores de ataque críticos para exibir como amostra
	// Estes são vetores de Tier 1 (críticos) que devem estar presentes no mapeamento
	keys := []string{"xss", "sql_injection", "rce", "path_traversal", "deserialization"}

	// Exibir cada vetor com seus top CWEs
	for _, key := range keys {
		if cwes, exists := simplifiedMap[key]; exists {
			// Formatar: "SQL_INJECTION    : [89, 20, 79]"
			fmt.Printf("%-18s: [%s]\n", strings.ToUpper(key), strings.Join(cwes, ", "))
		}
	}

	// Indicar que há mais dados não exibidos
	fmt.Println("...")
}
