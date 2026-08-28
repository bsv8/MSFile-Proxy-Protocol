// msfile-nas 是 MSFile NAS V1 正式入口。
//
// 用法：
//
//	msfile-nas --config /etc/msfile-nas.yaml           # 启动服务
//	msfile-nas --config ... --check-config             # 仅校验配置后退出（诊断命令）
//
// 全部运行参数都来自 YAML 配置文件；本入口不再提供第二套配置真值。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"msfile.dev/labs/webrtc-go/internal/config"
	"msfile.dev/labs/webrtc-go/internal/nas"
)

func main() {
	configPath := flag.String("config", "", "YAML 配置文件路径（必填，字段含义见 config/msfile-nas.example.yaml 中文注释）")
	checkOnly := flag.Bool("check-config", false, "仅校验配置文件并退出，不启动任何监听或数据库写入")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "错误：必须通过 --config 指定 YAML 配置文件")
		flag.Usage()
		os.Exit(2)
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(2)
	}
	if *checkOnly {
		fmt.Println("配置校验通过：数据目录、访问策略、listener、WebRTC Direct 公网地址与 TLS 配置均合法")
		return
	}
	app, err := nas.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
	if err := app.Run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "错误：%v\n", err)
		os.Exit(1)
	}
}
