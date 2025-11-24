package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ============================================================================
// ESTRUTURAS DE DADOS - TRAINING DATA (ENTRADA)
// ============================================================================

// TrainingRecord representa um registro de treinamento da Fase 1
type TrainingRecord struct {
	CVEID         string   `json:"cve_id"`         // ID do CVE
	Description   string   `json:"description"`    // Descrição em inglês
	CWEs          []string `json:"cwes"`           // Lista de IDs de CWE
	AttackVectors []string `json:"attack_vectors"` // Vetores de ataque mapeados
	PublishedDate string   `json:"published_date"` // Data de publicação
}

// ============================================================================
// ESTRUTURAS DE DADOS - MODELO NAIVE BAYES (SAÍDA)
// ============================================================================

// NaiveBayesModel representa o modelo probabilístico treinado
type NaiveBayesModel struct {
	AttackVectors   []string                      `json:"attack_vectors"`    // Lista de vetores de ataque
	VectorPriors    map[string]float64            `json:"vector_priors"`     // P(vetor) - probabilidade a priori
	WordGivenVector map[string]map[string]float64 `json:"word_given_vector"` // P(palavra|vetor) - verossimilhança
	WordCounts      map[string]map[string]int     `json:"word_counts"`       // Contagem de palavra no vetor
	TotalWords      map[string]int                `json:"total_words"`       // Total de palavras por vetor
	Vocabulary      []string                      `json:"vocabulary"`        // Todas as palavras únicas
	TotalDocuments  int                           `json:"total_documents"`   // Total de documentos de treinamento
	VectorDocCounts map[string]int                `json:"vector_doc_counts"` // Documentos por vetor
}

// ============================================================================
// STOPWORDS
// ============================================================================
// Lista expandida de stopwords incluindo termos genéricos de segurança
// que têm baixo poder discriminativo para classificação de vetores de ataque
// ============================================================================

var stopwords = map[string]bool{
	// Stopwords comuns de inglês
	"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
	"be": true, "by": true, "for": true, "from": true, "has": true, "he": true,
	"in": true, "is": true, "it": true, "its": true, "of": true, "on": true,
	"that": true, "the": true, "to": true, "was": true, "will": true, "with": true,
	"this": true, "but": true, "they": true, "have": true, "had": true, "what": true,
	"when": true, "where": true, "who": true, "which": true, "why": true, "how": true,
	"can": true, "could": true, "may": true, "might": true, "must": true, "shall": true,
	"should": true, "would": true, "or": true, "not": true, "no": true, "nor": true,
	"if": true, "then": true, "than": true, "so": true, "such": true, "only": true,
	"own": true, "same": true, "some": true, "these": true, "those": true, "very": true,
	"also": true, "just": true, "more": true, "most": true, "other": true, "into": true,
	"through": true, "during": true, "before": true, "after": true, "above": true,
	"below": true, "between": true, "under": true, "again": true, "further": true,
	"once": true, "here": true, "there": true, "all": true, "both": true, "each": true,
	"few": true, "any": true, "been": true, "being": true, "do": true, "does": true,
	"did": true, "doing": true, "out": true, "off": true, "over": true, "up": true,
	"down": true, "about": true, "against": true, "because": true, "until": true,
	"while": true, "within": true, "along": true, "following": true, "across": true,
	"behind": true, "beyond": true, "plus": true, "except": true, "however": true,
	"since": true, "unless": true, "whereas": true, "whether": true,

	// Termos genéricos de segurança (baixo poder discriminativo)
	// Estes termos aparecem em quase todos os CVEs independente do vetor de ataque
	"vulnerability": true, "vulnerabilities": true, "vulnerable": true,
	"issue": true, "issues": true, "flaw": true, "flaws": true,
	"version": true, "versions": true, "release": true, "releases": true,
	"attacker": true, "attackers": true, "user": true, "users": true,
	"allows": true, "allow": true, "via": true, "using": true,
	"data": true, "code": true, "file": true, "files": true,
	"access": true, "system": true, "systems": true,
	"found": true, "used": true, "use": true, "uses": true,
	"fix": true, "fixed": true, "resolved": true, "patch": true,
	"product": true, "products": true, "component": true, "components": true,
	"application": true, "applications": true, "software": true,
	"function": true, "functions": true, "method": true, "methods": true,
	"value": true, "values": true, "parameter": true, "parameters": true,
	"request": true, "requests": true, "response": true, "responses": true,
	"certain": true, "specific": true, "particular": true, "multiple": true,
	"various": true, "related": true, "associated": true, "affected": true,
	"result": true, "results": true, "cause": true, "causes": true,
	"perform": true, "execute": true, "run": true, "process": true,
	"obtain": true, "gain": true, "achieve": true, "lead": true,
	"due": true, "lack": true, "missing": true, "improper": true,
	"insufficient": true, "incorrect": true, "invalid": true,
}

// ============================================================================
// FUNÇÕES DE TOKENIZAÇÃO
// ============================================================================

/*
 * Função: tokenize
 * Descrição: Tokeniza e limpa um texto, extraindo palavras significativas
 * Objetivo: Preparar o texto para treinamento do Naive Bayes, removendo ruído
 *           e mantendo apenas termos discriminativos
 * Como faz: 1. Converte para minúsculas
 *           2. Remove números de versão (ex: "2.15.0", "v1.2.3")
 *           3. Remove IDs de CVE (ex: "CVE-2024-12345")
 *           4. Extrai palavras alfanuméricas usando regex
 *           5. Filtra:
 *              a. Palavras com menos de 3 caracteres
 *              b. Stopwords (comuns e específicas de segurança)
 *           6. Retorna lista de palavras limpas
 * Input: text (string) - Texto a tokenizar (descrição de CVE)
 * Output: []string - Lista de palavras tokenizadas e filtradas
 * Por que faz: A qualidade do modelo Naive Bayes depende da qualidade dos tokens.
 *              Remover ruído (versões, stopwords) garante que apenas termos
 *              discriminativos sejam usados para calcular probabilidades.
 *              Exemplo: "SQL injection" é discriminativo, "the vulnerability" não é.
 */
func tokenize(text string) []string {
	// Converter para minúsculas
	text = strings.ToLower(text)

	// Remover números de versão (ex: "2.15.0", "v1.2.3")
	versionRegex := regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)
	text = versionRegex.ReplaceAllString(text, "")

	// Remover IDs de CVE
	cveRegex := regexp.MustCompile(`cve-\d{4}-\d+`)
	text = cveRegex.ReplaceAllString(text, "")

	// Extrair palavras (sequências alfanuméricas)
	wordRegex := regexp.MustCompile(`[a-z][a-z0-9]*`)
	words := wordRegex.FindAllString(text, -1)

	// Filtrar stopwords e palavras curtas
	var filtered []string
	for _, word := range words {
		if len(word) >= 3 && !stopwords[word] {
			filtered = append(filtered, word)
		}
	}

	return filtered
}

// ============================================================================
// FUNÇÕES DE TREINAMENTO
// ============================================================================

/*
 * Função: trainNaiveBayes
 * Descrição: Treina um modelo Naive Bayes Multinomial para classificação de
 *            vetores de ataque a partir dos dados de treinamento
 * Objetivo: Criar um modelo probabilístico que possa classificar CVEs em
 *           vetores de ataque baseado nas palavras da descrição
 * Como faz: 1. INICIALIZAÇÃO:
 *              a. Cria estruturas vazias do modelo
 *              b. Coleta todos os vetores de ataque únicos
 *              c. Inicializa mapas de contagem para cada vetor
 *           2. CONSTRUÇÃO DO VOCABULÁRIO:
 *              a. Tokeniza todas as descrições
 *              b. Coleta todas as palavras únicas (vocabulário)
 *              c. Conta ocorrências de cada palavra em cada vetor
 *              d. Conta total de palavras por vetor
 *              e. Conta documentos por vetor
 *           3. CÁLCULO DE PRIORS:
 *              P(vetor) = count(vetor) / total_documentos
 *              Exemplo: P(sql_injection) = 500 / 5000 = 0.10
 *           4. CÁLCULO DE VEROSSIMILHANÇAS com Laplace Smoothing:
 *              P(palavra|vetor) = (count(palavra, vetor) + 1) / (total_palavras_vetor + tamanho_vocabulário)
 *              Smoothing evita probabilidades zero para palavras não vistas
 * Input: trainingData ([]TrainingRecord) - Dataset de treinamento da Fase 1
 * Output: *NaiveBayesModel - Modelo treinado com todas as probabilidades
 * Por que faz: Naive Bayes é um classificador probabilístico eficiente e eficaz.
 *              Ele aprende P(vetor|descrição) usando o Teorema de Bayes:
 *              P(vetor|descrição) ∝ P(vetor) × ∏ P(palavra|vetor)
 *              É "naive" porque assume independência entre palavras, mas
 *              funciona bem na prática para classificação de texto.
 */
func trainNaiveBayes(trainingData []TrainingRecord) *NaiveBayesModel {
	// Inicializar estruturas do modelo
	model := &NaiveBayesModel{
		VectorPriors:    make(map[string]float64),
		WordGivenVector: make(map[string]map[string]float64),
		WordCounts:      make(map[string]map[string]int),
		TotalWords:      make(map[string]int),
		VectorDocCounts: make(map[string]int),
		TotalDocuments:  len(trainingData),
	}

	// Coletar todos os vetores de ataque únicos
	vectorSet := make(map[string]bool)
	for _, record := range trainingData {
		for _, vector := range record.AttackVectors {
			vectorSet[vector] = true
		}
	}
	for vector := range vectorSet {
		model.AttackVectors = append(model.AttackVectors, vector)
		model.WordCounts[vector] = make(map[string]int)
	}

	// Construir vocabulário e contar palavras
	vocabSet := make(map[string]bool)

	fmt.Println("Tokenizing descriptions and counting words...")
	for i, record := range trainingData {
		// Exibir progresso a cada 100 registros
		if (i+1)%100 == 0 {
			fmt.Printf("  Processed %d/%d records\n", i+1, len(trainingData))
		}

		// Tokenizar descrição
		words := tokenize(record.Description)

		// Adicionar ao vocabulário
		for _, word := range words {
			vocabSet[word] = true
		}

		// Contar palavras para cada vetor de ataque
		for _, vector := range record.AttackVectors {
			model.VectorDocCounts[vector]++
			for _, word := range words {
				model.WordCounts[vector][word]++
				model.TotalWords[vector]++
			}
		}
	}

	// Converter conjunto de vocabulário para slice
	for word := range vocabSet {
		model.Vocabulary = append(model.Vocabulary, word)
	}

	fmt.Printf("Vocabulary size: %d unique words\n\n", len(model.Vocabulary))

	// ========================================================================
	// CALCULAR PRIORS: P(vetor) = count(vetor) / total_documentos
	// ========================================================================
	fmt.Println("Calculating prior probabilities...")
	for vector := range vectorSet {
		model.VectorPriors[vector] = float64(model.VectorDocCounts[vector]) / float64(model.TotalDocuments)
		fmt.Printf("  P(%s) = %.4f (%d documents)\n", vector, model.VectorPriors[vector], model.VectorDocCounts[vector])
	}

	// ========================================================================
	// CALCULAR VEROSSIMILHANÇAS com Laplace Smoothing
	// P(palavra|vetor) = (count + 1) / (total + tamanho_vocabulário)
	// ========================================================================
	fmt.Println("\nCalculating word likelihoods with Laplace smoothing...")
	vocabularySize := len(model.Vocabulary)

	for _, vector := range model.AttackVectors {
		model.WordGivenVector[vector] = make(map[string]float64)
		totalWordsInVector := model.TotalWords[vector]

		for _, word := range model.Vocabulary {
			wordCount := model.WordCounts[vector][word]
			// Laplace smoothing: adiciona 1 ao numerador e tamanho do vocabulário ao denominador
			// Isso garante que P(palavra|vetor) nunca seja zero, mesmo para palavras não vistas
			model.WordGivenVector[vector][word] = float64(wordCount+1) / float64(totalWordsInVector+vocabularySize)
		}
	}

	fmt.Printf("Calculated likelihoods for %d words across %d attack vectors\n", vocabularySize, len(model.AttackVectors))

	return model
}

// ============================================================================
// FUNÇÕES DE ANÁLISE
// ============================================================================

/*
 * Função: findTopWords
 * Descrição: Encontra as palavras mais discriminativas para cada vetor de ataque
 * Objetivo: Identificar quais palavras têm maior probabilidade P(palavra|vetor)
 *           para análise e validação do modelo
 * Como faz: 1. Para cada vetor de ataque:
 *              a. Coleta todas as palavras com suas probabilidades
 *              b. Filtra palavras que aparecem menos de 3 vezes (ruído)
 *              c. Ordena por probabilidade (descendente) usando bubble sort
 *              d. Seleciona as top N palavras
 *           2. Retorna mapa de vetor → lista de palavras ranqueadas
 * Input: model (*NaiveBayesModel) - Modelo treinado
 *        topN (int) - Número de palavras a retornar por vetor
 * Output: map[string][]WordScore - Mapa de vetor para palavras ranqueadas
 * Por que faz: As palavras com maior P(palavra|vetor) são as mais discriminativas.
 *              Analisar essas palavras permite:
 *              - Validar se o modelo aprendeu padrões corretos
 *              - Identificar termos-chave para cada vetor
 *              - Detectar problemas no treinamento
 *              Exemplo: sql_injection deve ter "sql", "query", "database" no topo
 */
func findTopWords(model *NaiveBayesModel, topN int) map[string][]WordScore {
	result := make(map[string][]WordScore)

	for _, vector := range model.AttackVectors {
		var scores []WordScore
		for word, prob := range model.WordGivenVector[vector] {
			count := model.WordCounts[vector][word]
			// Considerar apenas palavras que aparecem pelo menos 3 vezes
			if count >= 3 {
				scores = append(scores, WordScore{Word: word, Score: prob, Count: count})
			}
		}

		// Ordenar por probabilidade (descendente) usando bubble sort
		for i := 0; i < len(scores); i++ {
			for j := i + 1; j < len(scores); j++ {
				if scores[j].Score > scores[i].Score {
					scores[i], scores[j] = scores[j], scores[i]
				}
			}
		}

		// Pegar top N
		if len(scores) > topN {
			scores = scores[:topN]
		}

		result[vector] = scores
	}

	return result
}

// WordScore representa a pontuação de uma palavra para análise
type WordScore struct {
	Word  string  `json:"word"`  // Palavra
	Score float64 `json:"score"` // Probabilidade P(palavra|vetor)
	Count int     `json:"count"` // Contagem no vetor
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

/*
 * Função: main
 * Descrição: Ponto de entrada do programa que orquestra o treinamento do
 *            modelo Naive Bayes para classificação de vetores de ataque
 * Objetivo: Criar um modelo probabilístico (naive_bayes_model.json) que possa
 *           classificar CVEs em vetores de ataque baseado em suas descrições
 * Como faz: 1. Carrega dados de treinamento da Fase 1 (training_data.json)
 *           2. Treina modelo Naive Bayes:
 *              a. Tokeniza todas as descrições
 *              b. Constrói vocabulário
 *              c. Calcula priors P(vetor)
 *              d. Calcula verossimilhanças P(palavra|vetor)
 *           3. Analisa palavras mais discriminativas por vetor
 *           4. Salva modelo completo em JSON
 *           5. Exibe estatísticas:
 *              a. Número de vetores de ataque
 *              b. Tamanho do vocabulário
 *              c. Total de documentos
 *              d. Total de palavras processadas
 * Input: Arquivo resources/training_data.json (gerado pela Fase 1)
 * Output: Arquivo resources/naive_bayes_model.json contendo:
 *         - Priors P(vetor) para todos os vetores
 *         - Verossimilhanças P(palavra|vetor) para todo o vocabulário
 *         - Contagens de palavras e documentos
 *         - Vocabulário completo
 * Por que faz: Esta é a Fase 2 da pipeline de treinamento. O modelo Naive Bayes
 *              fornece a segunda camada de classificação (após hierarquia CWE).
 *              Ele aprende padrões probabilísticos das descrições de CVE,
 *              permitindo classificação baseada em conteúdo textual.
 *              É especialmente útil quando CWEs estão ausentes ou são genéricos.
 */
func main() {
	fmt.Println("=================================================================")
	fmt.Println("Phase 2: Naive Bayes Trainer for Attack Vector Detection")
	fmt.Println("=================================================================\n")

	// Carregar dados de treinamento da Fase 1
	inputFile := "resources/training_data.json"
	outputModel := "resources/naive_bayes_model.json"

	fmt.Printf("Loading training data from: %s\n", inputFile)

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		fmt.Println("\nMake sure you've run phase1-collector first to generate resources/training_data.json")
		os.Exit(1)
	}
	defer file.Close()

	var trainingData []TrainingRecord
	if err := json.NewDecoder(file).Decode(&trainingData); err != nil {
		fmt.Printf("Error decoding JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Loaded %d training records\n\n", len(trainingData))

	// Treinar modelo
	fmt.Println("Training Naive Bayes model...")
	fmt.Println("=================================================================")
	model := trainNaiveBayes(trainingData)

	// Encontrar palavras mais discriminativas para análise
	fmt.Println("\n=================================================================")
	fmt.Println("Top discriminative words per attack vector:")
	fmt.Println("=================================================================")
	topWords := findTopWords(model, 15)

	for _, vector := range model.AttackVectors {
		if words, ok := topWords[vector]; ok && len(words) > 0 {
			fmt.Printf("\n%s:\n", strings.ToUpper(vector))
			for i, ws := range words {
				if i >= 10 { // Mostrar top 10 no console
					break
				}
				fmt.Printf("  %2d. %-20s (count: %4d, prob: %.6f)\n", i+1, ws.Word, ws.Count, ws.Score)
			}
		}
	}

	// Salvar modelo
	fmt.Println("\n=================================================================")
	fmt.Printf("Saving model to: %s\n", outputModel)

	outFile, err := os.Create(outputModel)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(model); err != nil {
		fmt.Printf("Error writing model: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Model saved successfully!")

	// Estatísticas do modelo
	fmt.Println("\n=================================================================")
	fmt.Println("Model Statistics:")
	fmt.Println("=================================================================")
	fmt.Printf("  Attack vectors: %d\n", len(model.AttackVectors))
	fmt.Printf("  Vocabulary size: %d words\n", len(model.Vocabulary))
	fmt.Printf("  Training documents: %d\n", model.TotalDocuments)

	totalWords := 0
	for _, count := range model.TotalWords {
		totalWords += count
	}
	fmt.Printf("  Total words processed: %d\n", totalWords)

	fmt.Println("\nPhase 2 complete! Ready for Phase 3 (Attack vector classifier)")
}
