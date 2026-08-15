//go:build windows

package main

import (
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"

	webview2 "github.com/jchv/go-webview2"
)

//go:embed ui/*
var uiAssets embed.FS

func main() {
	debug := flag.Bool("debug", false, "enable webview developer tools")
	flag.Parse()

	// Extract sub-filesystem for embedded assets
	uiFS, err := fs.Sub(uiAssets, "ui")
	if err != nil {
		log.Fatalf("failed to load embedded ui assets: %v", err)
	}

	// Start local loopback HTTP server for embedded assets
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to bind loopback listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	serverURL := fmt.Sprintf("http://127.0.0.1:%d/index.html", port)

	httpServer := &http.Server{
		Handler: http.FileServer(http.FS(uiFS)),
	}

	go func() {
		if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("http server error: %v", err)
		}
	}()
	defer httpServer.Close()

	// Create WebView2 window
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     *debug,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title:  "Fred Proxy KSP - Certificate Manager",
			Width:  1060,
			Height: 740,
			IconId: 1,
			Center: true,
		},
	})
	if w == nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize WebView2. Make sure Microsoft Edge WebView2 Runtime is installed.\n")
		os.Exit(1)
	}
	defer w.Destroy()

	w.SetTitle("Fred Proxy KSP - Certificate Manager")
	w.SetSize(1060, 740, webview2.HintNone)

	// Inject bridge object initialization
	w.Init("window.backend = window;")

	// Bind Go API handlers to JavaScript
	api := NewAppAPI()
	if err := w.Bind("LoadConfig", api.LoadConfig); err != nil {
		log.Fatalf("failed to bind LoadConfig: %v", err)
	}
	if err := w.Bind("SaveConfig", api.SaveConfig); err != nil {
		log.Fatalf("failed to bind SaveConfig: %v", err)
	}
	if err := w.Bind("DiscoverServers", api.DiscoverServers); err != nil {
		log.Fatalf("failed to bind DiscoverServers: %v", err)
	}
	if err := w.Bind("TestConnection", api.TestConnection); err != nil {
		log.Fatalf("failed to bind TestConnection: %v", err)
	}
	if err := w.Bind("ListRemoteCertificates", api.ListRemoteCertificates); err != nil {
		log.Fatalf("failed to bind ListRemoteCertificates: %v", err)
	}
	if err := w.Bind("InstallCertificate", api.InstallCertificate); err != nil {
		log.Fatalf("failed to bind InstallCertificate: %v", err)
	}
	if err := w.Bind("ListInstalledCertificates", api.ListInstalledCertificates); err != nil {
		log.Fatalf("failed to bind ListInstalledCertificates: %v", err)
	}
	if err := w.Bind("UninstallCertificate", api.UninstallCertificate); err != nil {
		log.Fatalf("failed to bind UninstallCertificate: %v", err)
	}
	if err := w.Bind("SelectFile", api.SelectFile); err != nil {
		log.Fatalf("failed to bind SelectFile: %v", err)
	}
	if err := w.Bind("GetDiagnostics", api.GetDiagnostics); err != nil {
		log.Fatalf("failed to bind GetDiagnostics: %v", err)
	}
	if err := w.Bind("TestSign", api.TestSign); err != nil {
		log.Fatalf("failed to bind TestSign: %v", err)
	}

	w.Navigate(serverURL)
	w.Run()
}
