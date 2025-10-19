package cli

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// GenerateDomainsFromPattern 从模式生成域名列表
// 支持的模式语法:
// - [a-z]: 小写字母 a-z
// - [A-Z]: 大写字母 A-Z
// - [0-9]: 数字 0-9
// - [abc]: 自定义字符集
// - {n}: 重复n次
//
// 示例:
// - [a-z]{3}.com: 生成所有3字符小写字母域名
// - test[0-9]{2}.net: test + 两位数字
// - [abc]{2}.org: abc的2字符组合
func GenerateDomainsFromPattern(pattern string) ([]string, error) {
	// 解析模式: [字符集]{重复次数}
	re := regexp.MustCompile(`\[([^\]]+)\](?:\{(\d+)\})?`)
	matches := re.FindAllStringSubmatch(pattern, -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("无效的模式: %s。请使用 [字符集]{重复次数} 格式，例如 [a-z]{3}.com", pattern)
	}

	// 构建字符集列表
	var charsetGroups [][]string
	matchIndices := re.FindAllStringIndex(pattern, -1)

	for i, match := range matches {
		charsetDef := match[1]
		repeat := 1
		if match[2] != "" {
			repeat, _ = strconv.Atoi(match[2])
		}

		// 展开字符集
		chars, err := expandCharset(charsetDef)
		if err != nil {
			return nil, err
		}

		// 根据重复次数添加字符集
		for j := 0; j < repeat; j++ {
			charsetGroups = append(charsetGroups, chars)
		}

		// 保存匹配位置信息
		_ = matchIndices[i]
	}

	if len(charsetGroups) == 0 {
		return nil, fmt.Errorf("无法从模式生成域名: %s", pattern)
	}

	// 生成所有组合
	var domains []string
	generateCombinations(pattern, matches, matchIndices, charsetGroups, 0, "", &domains)

	return domains, nil
}

// generateCombinations 递归生成所有组合
func generateCombinations(pattern string, matches [][]string, matchIndices [][]int, charsetGroups [][]string, groupIdx int, current string, results *[]string) {
	if groupIdx >= len(charsetGroups) {
		// 所有字符集都已处理，生成最终域名
		domain := buildDomain(pattern, matches, matchIndices, current)
		*results = append(*results, domain)
		return
	}

	// 遍历当前字符集
	for _, char := range charsetGroups[groupIdx] {
		generateCombinations(pattern, matches, matchIndices, charsetGroups, groupIdx+1, current+char, results)
	}
}

// buildDomain 根据组合构建域名
func buildDomain(pattern string, matches [][]string, matchIndices [][]int, combo string) string {
	domain := pattern

	// 从后往前替换，避免索引变化
	for i := len(matches) - 1; i >= 0; i-- {
		match := matches[i]
		indices := matchIndices[i]

		repeat := 1
		if match[2] != "" {
			repeat, _ = strconv.Atoi(match[2])
		}

		// 计算当前段在组合中的起始位置
		segmentIdx := 0
		for j := 0; j < i; j++ {
			r := 1
			if matches[j][2] != "" {
				r, _ = strconv.Atoi(matches[j][2])
			}
			segmentIdx += r
		}

		// 提取对应的字符段
		segment := combo[segmentIdx : segmentIdx+repeat]

		// 替换模式中的这个段
		domain = domain[:indices[0]] + segment + domain[indices[1]:]
	}

	return domain
}

// expandCharset 展开字符集定义
// 支持:
// - a-z: 小写字母
// - A-Z: 大写字母
// - 0-9: 数字
// - abc: 具体字符列表
func expandCharset(charset string) ([]string, error) {
	var chars []string
	i := 0

	for i < len(charset) {
		// 检查是否是范围表达式 (如 a-z, A-Z, 0-9)
		if i+2 < len(charset) && charset[i+1] == '-' {
			startChar := charset[i]
			endChar := charset[i+2]

			// 处理 a-z
			if startChar == 'a' && endChar == 'z' {
				for c := 'a'; c <= 'z'; c++ {
					chars = append(chars, string(c))
				}
			} else if startChar == 'A' && endChar == 'Z' {
				// 处理 A-Z
				for c := 'A'; c <= 'Z'; c++ {
					chars = append(chars, string(c))
				}
			} else if startChar == '0' && endChar == '9' {
				// 处理 0-9
				for c := '0'; c <= '9'; c++ {
					chars = append(chars, string(c))
				}
			} else {
				// 通用范围处理
				for c := startChar; c <= endChar; c++ {
					chars = append(chars, string(c))
				}
			}

			i += 3
		} else {
			// 单个字符
			chars = append(chars, string(charset[i]))
			i++
		}
	}

	if len(chars) == 0 {
		return nil, fmt.Errorf("无效的字符集: [%s]", charset)
	}

	return chars, nil
}

// LoadDomainsFromFile 从文件加载域名列表
func LoadDomainsFromFile(filePath string) ([]string, error) {
	// 读取文件
	content, err := readFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	var domains []string
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		// 跳过空行和注释
		if line != "" && !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("文件中没有找到有效的域名")
	}

	return domains, nil
}

// readFile 读取文件内容
func readFile(filePath string) ([]byte, error) {
	return os.ReadFile(filePath)
}
