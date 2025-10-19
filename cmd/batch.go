package cmd

import (
	"os"

	"gois/cli"

	"github.com/spf13/cobra"
)

var batchCmd = &cobra.Command{
	Use:   "batch [file]",
	Short: "批量查询域名",
	Long: `从文件中读取域名列表并批量查询

文件格式:
  - 每行一个域名
  - 支持 # 开头的注释行
  - 空行会被忽略

示例:
  gois batch domains.txt
  gois batch domains.txt -c 10
  gois batch domains.txt -m simple -o results.csv`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]

		// 检查文件是否存在
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logger.Error("文件不存在", "file", filePath)
			os.Exit(1)
		}

		// 加载域名列表
		domains, err := cli.LoadDomainsFromFile(filePath)
		if err != nil {
			logger.Error("加载域名列表失败", "error", err)
			os.Exit(1)
		}

		logger.Info("从文件加载域名列表", "file", filePath, "count", len(domains))

		// 创建 CLI 实例
		cliInstance, err := createCLI()
		if err != nil {
			logger.Error("初始化失败", "error", err)
			os.Exit(1)
		}
		defer cliInstance.Close()

		// 批量查询
		results := cliInstance.QueryBatchDomains(domains)

		// 检查是否有失败的查询
		hasFailures := false
		for _, result := range results {
			if !result.Success {
				hasFailures = true
				break
			}
		}

		if hasFailures {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(batchCmd)
}
