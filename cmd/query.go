package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var queryCmd = &cobra.Command{
	Use:   "query [domain]",
	Short: "查询单个域名的 WHOIS 信息",
	Long: `查询单个域名的 WHOIS 信息

示例:
  gois query github.com
  gois query github.com -m simple
  gois query github.com -p socks5://localhost:7897
  gois query github.com -o result.txt`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		domain := args[0]

		// 创建 CLI 实例
		cliInstance, err := createCLI()
		if err != nil {
			logger.Error("初始化失败", "error", err)
			os.Exit(1)
		}
		defer cliInstance.Close()

		// 查询域名
		result := cliInstance.QuerySingleDomain(domain)

		if !result.Success {
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(queryCmd)
}
