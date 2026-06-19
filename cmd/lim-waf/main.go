package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/nrlim/lim-waf/internal/config"
	"github.com/nrlim/lim-waf/internal/dashboard"
	"github.com/nrlim/lim-waf/internal/engine"
	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	cfgFile   string
)

const banner = `
    __    ________  ___   _       _____    ______
   / /   /  _/ __ \/   | | |     / /   |  / ____/
  / /    / // / / / /| | | | /| / / /| | / /_    
 / /____/ // /_/ / ___ | | |/ |/ / ___ |/ __/    
/_____/___/\____/_/  |_| |__/|__/_/  |_/_/       
                                                 
 Secured by LIM WAF - v%s
`

var rootCmd = &cobra.Command{
	Use:   "lim-waf",
	Short: "LIM WAF is a high-performance custom Web Application Firewall",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the LIM WAF reverse proxy server",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(banner, Version)

		// Load config
		cfg, err := config.LoadConfig(cfgFile)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		// Initialize WAF Engine
		wafEngine, err := engine.NewEngine(cfg)
		if err != nil {
			log.Fatalf("Failed to initialize WAF Engine: %v", err)
		}

		// Initialize Reverse Proxy
		proxy, err := engine.NewReverseProxy(wafEngine)
		if err != nil {
			log.Fatalf("Failed to initialize Reverse Proxy: %v", err)
		}

		// Start Dashboard Server
		dashServer := dashboard.NewServer(wafEngine, cfgFile)
		go func() {
			if err := dashServer.Start(); err != nil {
				log.Printf("Dashboard server error: %v", err)
			}
		}()

		// Start WAF Server
		srv := &http.Server{
			Addr:    cfg.Server.Listen,
			Handler: proxy,
		}

		go func() {
			log.Printf("Starting LIM WAF proxy on %s for backend %s", cfg.Server.Listen, cfg.Sites[0].Backend)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("WAF server error: %v", err)
			}
		}()

		// Graceful Shutdown
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Println("Shutting down LIM WAF...")
		srv.Close()
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of LIM WAF",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("LIM WAF v%s\n", Version)
	},
}

func init() {
	serveCmd.Flags().StringVarP(&cfgFile, "config", "c", "/etc/lim-waf/config.yaml", "config file path")
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
