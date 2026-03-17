package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

// startDoTForwarder runs a UDP DNS server on listen that forwards
// all queries to upstream via DNS-over-TLS (port 853). This bypasses
// Firewalla DNS Booster which intercepts all port-53 traffic.
func startDoTForwarder(listen, upstream string) func() {
	server := &dns.Server{
		Addr: listen,
		Net:  "udp",
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			c := &dns.Client{
				Net:       "tcp-tls",
				TLSConfig: &tls.Config{ServerName: "cloudflare-dns.com"},
				Timeout:   10 * time.Second,
			}
			resp, _, err := c.Exchange(r, upstream)
			if err != nil {
				log.Printf("[dot] upstream error: %v", err)
				fail := new(dns.Msg)
				fail.SetRcode(r, dns.RcodeServerFailure)
				w.WriteMsg(fail)
				return
			}
			w.WriteMsg(resp)
		}),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[dot] server failed: %v", err)
		}
	}()
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	return func() { server.Shutdown() }
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	apiToken := os.Getenv("CF_API_KEY")
	if apiToken == "" {
		log.Fatal("CF_API_KEY is required")
	}

	domains := os.Getenv("DOMAINS")
	if domains == "" {
		log.Fatal("DOMAINS is required (comma-separated, e.g. '*.valenwood.tamriel.io')")
	}

	acmeCA := env("ACME_CA", certmagic.LetsEncryptProductionCA)
	acmeEmail := os.Getenv("ACME_EMAIL")
	certDir := env("CERT_DIR", "/certs")

	domainList := strings.Split(domains, ",")
	for i := range domainList {
		domainList[i] = strings.TrimSpace(domainList[i])
	}

	log.Printf("certbot-dot starting")
	log.Printf("  domains: %s", strings.Join(domainList, ", "))
	log.Printf("  CA:      %s", acmeCA)
	log.Printf("  email:   %s", acmeEmail)
	log.Printf("  storage: %s", certDir)

	// Start embedded DoT forwarder
	const resolver = "127.0.0.1:5053"
	log.Printf("starting DoT forwarder (%s -> 1.1.1.1:853)", resolver)
	stop := startDoTForwarder(resolver, "1.1.1.1:853")
	defer stop()

	// Sanity check: resolve tamriel.io SOA via DoT
	m := new(dns.Msg)
	m.SetQuestion("tamriel.io.", dns.TypeSOA)
	resp, _, err := new(dns.Client).Exchange(m, resolver)
	if err != nil || len(resp.Answer) == 0 {
		log.Fatalf("DoT sanity check failed: %v (answers: %d)", err, func() int {
			if resp != nil {
				return len(resp.Answer)
			}
			return 0
		}())
	}
	log.Printf("DoT forwarder OK (tamriel.io SOA resolves)")

	// Configure CertMagic
	logger, _ := zap.NewProduction()

	provider := &cloudflare.Provider{APIToken: apiToken}

	certmagic.DefaultACME.CA = acmeCA
	certmagic.DefaultACME.Email = acmeEmail
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider:        provider,
			Resolvers:          []string{resolver},
			PropagationTimeout: 3 * time.Minute,
			Logger:             logger,
		},
	}

	storage := &certmagic.FileStorage{Path: certDir}
	certmagic.Default.Storage = storage

	magic := certmagic.NewDefault()

	log.Printf("running ManageSync for %d domain(s)...", len(domainList))
	err = magic.ManageSync(context.Background(), domainList)
	if err != nil {
		log.Fatalf("ManageSync failed: %v", err)
	}
	log.Printf("ManageSync completed successfully")

	// Copy certs to flat paths for Caddy consumption.
	// CertMagic stores certs in nested dirs; we copy them to
	// /certs/wildcard.crt and /certs/wildcard.key for each domain.
	for _, domain := range domainList {
		if err := exportCerts(certDir, domain); err != nil {
			log.Printf("WARNING: failed to export certs for %s: %v", domain, err)
		}
	}

	log.Printf("done — all certs renewed and exported")
}

// exportCerts finds the CertMagic cert files for domain and copies
// them to flat paths in certDir. For wildcard domains, the filename
// uses the sanitized domain name (e.g. wildcard_.valenwood.tamriel.io).
// It also creates wildcard.crt/wildcard.key as convenience aliases.
func exportCerts(certDir, domain string) error {
	// CertMagic sanitizes * -> wildcard_ in directory and file names
	safeName := strings.ReplaceAll(domain, "*", "wildcard_")

	// CertMagic stores certs under certificates/<CA-dir>/<safeName>/
	certsBase := filepath.Join(certDir, "certificates")
	entries, err := os.ReadDir(certsBase)
	if err != nil {
		return fmt.Errorf("reading certificates dir: %w", err)
	}

	// Find the CA directory (could be staging or production)
	for _, caDir := range entries {
		if !caDir.IsDir() {
			continue
		}
		domainDir := filepath.Join(certsBase, caDir.Name(), safeName)
		certFile := filepath.Join(domainDir, safeName+".crt")
		keyFile := filepath.Join(domainDir, safeName+".key")

		if _, err := os.Stat(certFile); err != nil {
			continue
		}

		// Copy cert and key to flat paths
		destCert := filepath.Join(certDir, safeName+".crt")
		destKey := filepath.Join(certDir, safeName+".key")

		if err := copyFile(certFile, destCert); err != nil {
			return fmt.Errorf("copying cert: %w", err)
		}
		if err := copyFile(keyFile, destKey); err != nil {
			return fmt.Errorf("copying key: %w", err)
		}

		// Also create wildcard.crt / wildcard.key convenience copies
		if err := copyFile(certFile, filepath.Join(certDir, "wildcard.crt")); err != nil {
			return fmt.Errorf("copying wildcard.crt: %w", err)
		}
		if err := copyFile(keyFile, filepath.Join(certDir, "wildcard.key")); err != nil {
			return fmt.Errorf("copying wildcard.key: %w", err)
		}

		log.Printf("exported: %s -> %s, %s", domain, destCert, destKey)
		log.Printf("exported: wildcard.crt, wildcard.key")
		return nil
	}

	return fmt.Errorf("no cert files found for %s (looked for %s)", domain, safeName)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}
