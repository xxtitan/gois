package cmd

import (
	"math"
	"os"

	"gois/cli"

	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate [pattern]",
	Short: "从模式生成域名并查询",
	Long: `从模式生成域名列表并批量查询

支持的模式语法:
  - [a-z]: 小写字母 a-z
  - [A-Z]: 大写字母 A-Z
  - [0-9]: 数字 0-9
  - [abc]: 自定义字符集
  - {n}: 重复 n 次

示例:
  gois generate "[a-z]{3}.com"              # 生成所有 3 字符小写字母域名
  gois generate "test[0-9]{2}.net"          # test + 两位数字
  gois generate "[abc]{2}.org"              # abc 的 2 字符组合
  gois generate "[a-z]{2}[0-9].com" -c 10   # 并发 10
  gois generate "[0-9]{4}.io" -m simple -o results.csv`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pattern := args[0]

		// 生成域名流
		logger.Info("正在从模式生成域名", "pattern", pattern)
		domainStream, totalCount, err := cli.GenerateDomainsFromPattern(pattern)
		if err != nil {
			logger.Error("生成域名失败", "error", err)
			os.Exit(1)
		}

		logger.Info("域名生成完成", "count", totalCount)

		// 大数量警告
		switch {
		case totalCount > 10_000:
			logger.Warn("将查询大量域名，可能需要很长时间",
				"count", totalCount,
				"suggestion", "使用更小的字符集或减少重复次数")
		case totalCount > 1_000:
			logger.Info("将查询较多域名，建议使用较高的并发数",
				"count", totalCount,
				"suggestion", "使用 -c 参数增加并发数")
		}

		// 创建 CLI 实例
		cliInstance, err := createCLI()
		if err != nil {
			logger.Error("初始化失败", "error", err)
			os.Exit(1)
		}
		defer cliInstance.Close()

		// 批量查询
		totalHint := int64(-1)
		if totalCount <= uint64(math.MaxInt64) {
			totalHint = int64(totalCount)
		}
		summary := cliInstance.QueryBatchDomainsStream(domainStream, totalHint)

		if summary.HasFailures() {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
