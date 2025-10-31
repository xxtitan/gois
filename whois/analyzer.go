package whois

import (
	"regexp"
	"strings"
)

// DomainInfo 域名信息
type DomainInfo struct {
	Status         string   `json:"status"` // available, registered, unknown
	Registrar      string   `json:"registrar,omitempty"`
	CreationDate   string   `json:"creation_date,omitempty"`
	ExpirationDate string   `json:"expiration_date,omitempty"`
	NameServers    []string `json:"name_servers,omitempty"`
}

// Analyzer WHOIS 结果分析器
type Analyzer struct {
	availableKeywords  []string
	registeredKeywords []string
	// 预编译的正则表达式，避免重复编译
	registrarRegexps      []*regexp.Regexp
	creationDateRegexps   []*regexp.Regexp
	expirationDateRegexps []*regexp.Regexp
	nameServerRegexps     []*regexp.Regexp
}

// NewAnalyzer 创建一个新的分析器
func NewAnalyzer() *Analyzer {
	// 预编译所有正则表达式
	registrarPatterns := []string{
		`(?mi)registrar:\s*(.+)`,
		`(?mi)sponsoring registrar:\s*(.+)`,
	}
	creationDatePatterns := []string{
		`(?mi)creation date:\s*(.+)`,
		`(?mi)created:\s*(.+)`,
		`(?mi)registered on:\s*(.+)`,
	}
	expirationDatePatterns := []string{
		`(?mi)registry expiry date:\s*(.+)`,
		`(?mi)registrar registration expiration date:\s*(.+)`,
		`(?mi)expiration date:\s*(.+)`,
		`(?mi)expires:\s*(.+)`,
		`(?mi)expiry date:\s*(.+)`,
	}
	nameServerPatterns := []string{
		`(?mi)name server:\s*(.+)`,
		`(?mi)nameserver:\s*(.+)`,
		`(?mi)nserver:\s*(.+)`,
	}

	compileRegexps := func(patterns []string) []*regexp.Regexp {
		regexps := make([]*regexp.Regexp, 0, len(patterns))
		for _, pattern := range patterns {
			regexps = append(regexps, regexp.MustCompile(pattern))
		}
		return regexps
	}

	return &Analyzer{
		availableKeywords: []string{
			"no match",
			"not found",
			"no entries found",
			"no data found",
			"not registered",
			"available for registration",
			"status: free",
			"status: available",
			"no matching record",
			"nothing found",
			"no object found",
			"domain not found",
			"is available",
			"is free",
			"未找到",
			"无匹配",
		},
		registeredKeywords: []string{
			"registrar:",
			"registrant:",
			"creation date:",
			"created:",
			"expiration date:",
			"expires:",
			"expiry date:",
			"registry expiry date:",
			"domain status:",
			"name server:",
			"nameserver:",
			"dnssec:",
			"注册商",
			"注册人",
			"创建时间",
			"到期时间",
		},
		registrarRegexps:      compileRegexps(registrarPatterns),
		creationDateRegexps:   compileRegexps(creationDatePatterns),
		expirationDateRegexps: compileRegexps(expirationDatePatterns),
		nameServerRegexps:     compileRegexps(nameServerPatterns),
	}
}

// GetDomainStatus 获取域名状态：available（可用）、registered（已注册）、unknown（未知）
func (a *Analyzer) GetDomainStatus(result *QueryResult) string {
	if result == nil {
		return "unknown"
	}

	// 合并两个结果
	combined := strings.ToLower(result.RegistryResult + "\n" + result.RegistrarResult)

	if strings.TrimSpace(combined) == "" {
		return "unknown"
	}

	// 检查可用关键词
	availableScore := 0
	for _, keyword := range a.availableKeywords {
		if strings.Contains(combined, strings.ToLower(keyword)) {
			availableScore++
		}
	}

	// 检查已注册关键词
	registeredScore := 0
	for _, keyword := range a.registeredKeywords {
		if strings.Contains(combined, strings.ToLower(keyword)) {
			registeredScore++
		}
	}

	// 如果有明确的可用标记，优先判断为可用
	if availableScore > 0 && registeredScore == 0 {
		return "available"
	}

	// 如果有明确的已注册标记
	if registeredScore > 0 {
		return "registered"
	}

	// 如果两者都有，以已注册为准（保守判断）
	if availableScore > 0 {
		return "registered"
	}

	// 关键词均不存在，返回未知
	return "unknown"
}

// ExtractRegistrar 提取注册商信息
func (a *Analyzer) ExtractRegistrar(result *QueryResult) string {
	if result == nil {
		return ""
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	for _, re := range a.registrarRegexps {
		matches := re.FindStringSubmatch(combined)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// ExtractCreationDate 提取域名创建日期
func (a *Analyzer) ExtractCreationDate(result *QueryResult) string {
	if result == nil {
		return ""
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	for _, re := range a.creationDateRegexps {
		matches := re.FindStringSubmatch(combined)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// ExtractExpirationDate 提取域名过期日期
func (a *Analyzer) ExtractExpirationDate(result *QueryResult) string {
	if result == nil {
		return ""
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	for _, re := range a.expirationDateRegexps {
		matches := re.FindStringSubmatch(combined)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
	}

	return ""
}

// ExtractNameServers 提取域名服务器列表
func (a *Analyzer) ExtractNameServers(result *QueryResult) []string {
	if result == nil {
		return nil
	}

	combined := result.RegistrarResult + "\n" + result.RegistryResult

	var nameServers []string
	seen := make(map[string]bool)

	for _, re := range a.nameServerRegexps {
		matches := re.FindAllStringSubmatch(combined, -1)
		for _, match := range matches {
			if len(match) > 1 {
				ns := strings.TrimSpace(match[1])
				nsLower := strings.ToLower(ns)
				if !seen[nsLower] {
					seen[nsLower] = true
					nameServers = append(nameServers, ns)
				}
			}
		}
	}

	return nameServers
}

// GetDomainInfo 提取域名的完整信息
func (a *Analyzer) GetDomainInfo(result *QueryResult) *DomainInfo {
	return &DomainInfo{
		Status:         a.GetDomainStatus(result),
		Registrar:      a.ExtractRegistrar(result),
		CreationDate:   a.ExtractCreationDate(result),
		ExpirationDate: a.ExtractExpirationDate(result),
		NameServers:    a.ExtractNameServers(result),
	}
}
