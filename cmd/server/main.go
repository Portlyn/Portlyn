package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"portlyn/internal/acme"
	"portlyn/internal/audit"
	"portlyn/internal/auth"
	"portlyn/internal/config"
	"portlyn/internal/geoip"
	apihttp "portlyn/internal/http"
	"portlyn/internal/observability"
	"portlyn/internal/proxy"
	"portlyn/internal/rate"
	"portlyn/internal/scanner"
	"portlyn/internal/security"
	"portlyn/internal/store"
	"portlyn/internal/tunnel"
)

var version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			if err := runInitWizard(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "init failed:", err)
				os.Exit(1)
			}
			return
		case "version", "--version", "-v":
			fmt.Println("portlyn", version)
			return
		case "settings":
			if err := runSettingsSubcommand(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "settings:", err)
				os.Exit(1)
			}
			return
		case "update":
			if err := runUpdate(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, "update:", err)
				os.Exit(1)
			}
			return
		case "help", "--help", "-h":
			printUsage()
			return
		}
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run './portlyn init' first to generate a .env file with required secrets.")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(logger)
	metrics := observability.NewMetrics()

	db, err := store.NewDatabase(cfg)
	if err != nil {
		logger.Error("failed to initialize database", "error", err)
		os.Exit(1)
	}

	if err := store.AutoMigrate(db); err != nil {
		logger.Error("failed to migrate database", "error", err)
		os.Exit(1)
	}

	userStore := store.NewUserStore(db)
	groupStore := store.NewGroupStore(db)
	nodeStore := store.NewNodeStore(db)
	clientStore := store.NewClientStore(db)
	domainStore := store.NewDomainStore(db)
	certificateStore := store.NewCertificateStore(db)
	dnsProviderStore := store.NewDNSProviderStore(db)
	serviceGroupStore := store.NewServiceGroupStore(db)
	serviceStore := store.NewServiceStore(db)
	routingStore := store.NewRoutingStore(db)
	loginTokenStore := store.NewLoginTokenStore(db)
	auditStore := store.NewAuditStore(db)
	appSettingsStore := store.NewAppSettingsStore(db)
	appSettingsStore.SetDataEncryptionSecrets(cfg.DataEncryptionSecrets())
	sessionStore := store.NewSessionStore(db)
	nodeEnrollmentTokenStore := store.NewNodeEnrollmentTokenStore(db)

	if migrated, err := loginTokenStore.MigratePlainTokens(context.Background()); err != nil {
		logger.Error("failed to migrate legacy login tokens", "error", err)
		os.Exit(1)
	} else if migrated > 0 {
		logger.Info("migrated legacy login tokens", "updated", migrated)
	}

	if migrated, err := appSettingsStore.MigrateStoredSecrets(context.Background()); err != nil {
		logger.Error("failed to migrate encrypted app settings", "error", err)
		os.Exit(1)
	} else if migrated > 0 {
		logger.Info("migrated app settings secrets", "updated", migrated)
	}

	var redisClient *redis.Client
	bootWarnings := make([]apihttp.StatusCondition, 0)
	if cfg.RedisURL != "" {
		options, err := redis.ParseURL(cfg.RedisURL)
		if err != nil {
			logger.Error("invalid redis url", "error", err)
			os.Exit(1)
		}
		redisClient = redis.NewClient(options)
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			logger.Warn("redis unavailable, falling back to local-only caches and rate limits", "error", err)
			bootWarnings = append(bootWarnings, apihttp.StatusCondition{
				Name:      "redis",
				Scope:     "cluster",
				Level:     apihttp.HealthLevelWarn,
				Summary:   "redis unavailable; running with local-only fallbacks",
				Reason:    "redis_fallback",
				CheckedAt: time.Now().UTC(),
			})
			redisClient = nil
		}
	}

	if err := appSettingsStore.SeedDefaults(context.Background(), cfg); err != nil {
		logger.Error("failed to seed app settings", "error", err)
		os.Exit(1)
	}
	if drifts, err := appSettingsStore.DetectEnvDrift(context.Background(), cfg); err != nil {
		logger.Warn("env drift detection failed", "error", err)
	} else {
		for _, d := range drifts {
			logger.Warn("env value differs from stored setting (DB wins; run 'portlyn settings sync' to apply env)",
				"field", d.Field, "env", d.EnvValue, "db", d.DBValue)
		}
	}
	authService, err := auth.NewService(
		userStore,
		groupStore,
		loginTokenStore,
		sessionStore,
		appSettingsStore,
		cfg.JWTSigningSecret,
		cfg.SessionBridgeSecret,
		cfg.OIDCStateSecret,
		cfg.MFAEncryptionSecret,
		cfg.JWTIssuer,
		cfg.FrontendBaseURL,
		cfg.TokenTTL,
		cfg.RefreshTokenTTL,
		cfg.OIDC,
		cfg.OTP,
		cfg.RouteAuthTTL,
		cfg.AuthRateLimit,
		cfg.AuthCacheTTL,
		cfg.AllowInsecureDevMode,
		metrics,
	)
	if err != nil {
		logger.Error("failed to initialize auth service", "error", err)
		os.Exit(1)
	}
	if redisClient != nil {
		authService.SetRateLimiter(rate.NewRedisLimiter(redisClient, "portlyn:auth:ratelimit"))
		authService.SetAuthCache(auth.NewRedisAuthCache(redisClient, "portlyn:auth:cache"))
	}
	if err := authService.SeedInitialAdmin(context.Background(), cfg.AdminEmail, cfg.AdminPassword); err != nil {
		logger.Error("failed to seed admin user", "error", err)
		os.Exit(1)
	}
	if err := authService.SeedUserIfMissing(context.Background(), cfg.ViewerEmail, cfg.ViewerPassword, "viewer"); err != nil {
		logger.Error("failed to seed viewer user", "error", err)
		os.Exit(1)
	}

	acmeManager, err := acme.NewManager(cfg, db, certificateStore, domainStore, dnsProviderStore, metrics)
	if err != nil {
		logger.Error("failed to initialize tls manager", "error", err)
		os.Exit(1)
	}
	if migrationSummary, err := acmeManager.MigrateStoredSecrets(context.Background()); err != nil {
		logger.Error("failed to migrate certificate secrets", "error", err)
		os.Exit(1)
	} else if migrationSummary.CertMagicPrivateKeys > 0 || migrationSummary.StoredTLSPrivateKeys > 0 {
		logger.Info(
			"migrated certificate secrets",
			"certmagic_private_keys", migrationSummary.CertMagicPrivateKeys,
			"stored_tls_private_keys", migrationSummary.StoredTLSPrivateKeys,
		)
	}
	bootstrapAdminCertificate(context.Background(), cfg, domainStore, certificateStore, logger)
	auditSink := audit.NewAsyncSink(auditStore, cfg.AuditBufferSize, cfg.AuditBatchSize, cfg.AuditFlushInterval, cfg.AuditDropPolicy, logger)
	auditLogger := audit.NewLogger(auditSink)
	auditWebhookStore := store.NewAuditWebhookStore(db)
	auditWebhookStore.SetDataEncryptionSecrets(cfg.DataEncryptionSecrets())
	webhookDispatcher := audit.NewWebhookDispatcher(auditWebhookStore)
	auditLogger.SetWebhookDispatcher(webhookDispatcher)
	exposureReportStore := store.NewExposureReportStore(db)
	exposureScanner := scanner.NewScanner(serviceStore, exposureReportStore, logger)

	userCredentialStore := store.NewUserCredentialStore(db)
	webAuthnService := auth.NewWebAuthnService(userCredentialStore, userStore)
	webAuthnService.Configure("Portlyn", cfg.FrontendBaseURL)
	authService.SetPasskeyChecker(webAuthnService.HasCredentials)
	if redisClient != nil {
		webAuthnService.SetSessionStore(auth.NewRedisWebAuthnSessionStore(redisClient, "portlyn:webauthn:session:"))
	}

	var configCache proxy.ConfigCache = proxy.NewInMemoryConfigCache()
	var configBus proxy.ConfigBus = proxy.NewInMemoryConfigBus()
	if redisClient != nil {
		configCache = proxy.NewRedisConfigCache(redisClient, "portlyn:proxy:routes")
		configBus = proxy.NewRedisConfigBus(redisClient, "portlyn:proxy:route-changed")
	}

	geoipLookup := geoip.NewLookup()
	crowdSecClient := security.NewCrowdSec()
	if currentSettings, err := appSettingsStore.Get(context.Background()); err == nil {
		if path := strings.TrimSpace(currentSettings.GeoIPDBPath); path != "" {
			if err := geoipLookup.Load(path); err != nil {
				logger.Warn("geoip: load failed", "path", path, "error", err)
			}
		}
		if currentSettings.CrowdSecEnabled {
			interval := time.Duration(currentSettings.CrowdSecPollIntervalSecs) * time.Second
			crowdSecClient.Configure(currentSettings.CrowdSecAPIURL, currentSettings.CrowdSecAPIKeyEncrypted, interval)
		}
	}

	tunnelManager := tunnel.NewManager(nodeStore, clientStore, appSettingsStore)
	tunnelServer := tunnel.NewServer(tunnel.ServerOptions{MTU: 1420})
	tunnelManager.AttachServer(tunnelServer)
	if startSettings, err := appSettingsStore.Get(context.Background()); err == nil && startSettings.TunnelEnabled {
		if _, ensureErr := tunnelManager.EnsureServerKey(context.Background()); ensureErr != nil {
			logger.Warn("tunnel: ensure server key", "error", ensureErr)
		} else if refreshed, refreshErr := appSettingsStore.Get(context.Background()); refreshErr != nil {
			logger.Warn("tunnel: reload settings", "error", refreshErr)
		} else if startErr := tunnelServer.Start(context.Background(), refreshed); startErr != nil {
			logger.Warn("tunnel: start server", "error", startErr)
		} else if err := tunnelManager.ApplyPeers(context.Background()); err != nil {
			logger.Warn("tunnel: apply peers", "error", err)
		}
	}

	proxyManager := proxy.NewManager(
		routingStore,
		configCache,
		configBus,
		authService,
		auditLogger,
		logger,
		metrics,
		proxy.ManagerOptions{
			LocalCacheTTL:          cfg.RouteLocalCacheTTL,
			LocalCacheCapacity:     cfg.RouteLocalCacheSize,
			AdminHost:              hostnameFromURL(cfg.FrontendBaseURL),
			TrustedProxyCIDRs:      cfg.TrustedProxyCIDRs,
			BootstrapAdminEnabled:  cfg.BootstrapAdminEnabled,
			AdminUITargetURL:       "http://frontend:3000",
			AdminAPITargetURL:      "http://127.0.0.1:8080",
			EmbeddedAdminUI:        embeddedFrontendHandler(),
			TunnelDialer:           tunnelServer,
			CountryLookup:          geoipLookup,
			Reputation:             crowdSecClient,
			ServiceDeploymentStore: serviceStore,
		},
	)

	healthChecks := []apihttp.HealthCheck{
		apihttp.NewDBHealthCheck(func(ctx context.Context) error {
			sqlDB, err := db.DB()
			if err != nil {
				return err
			}
			return sqlDB.PingContext(ctx)
		}),
	}
	if redisClient != nil {
		healthChecks = append(healthChecks, apihttp.NewNamedHealthCheck("redis", func(ctx context.Context) error {
			return redisClient.Ping(ctx).Err()
		}))
	}

	server := apihttp.NewServer(
		cfg,
		logger,
		db,
		authService,
		auditLogger,
		acmeManager,
		proxyManager,
		userStore,
		groupStore,
		nodeStore,
		clientStore,
		domainStore,
		certificateStore,
		dnsProviderStore,
		serviceGroupStore,
		serviceStore,
		appSettingsStore,
		loginTokenStore,
		auditStore,
		sessionStore,
		nodeEnrollmentTokenStore,
		auditWebhookStore,
		exposureReportStore,
		exposureScanner,
		tunnelManager,
		webAuthnService,
		metrics,
		bootWarnings,
		healthChecks...,
	)

	if err := server.SyncProxyState(context.Background()); err != nil {
		logger.Error("failed to sync proxy state", "error", err)
		os.Exit(1)
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server.SetNetworkSecurity(rootCtx, geoipLookup, crowdSecClient)
	server.SetWebhookDispatcher(webhookDispatcher)
	authService.StartCacheJanitor(rootCtx)
	proxyManager.Start(rootCtx)
	if crowdSecClient.Enabled() {
		crowdSecClient.Start(rootCtx)
	}
	exposureScanner.Start(rootCtx)

	apiServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           server.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	proxyHTTPHandler := acmeManager.HTTPChallengeHandler(server.ProxyHandler())
	if cfg.RedirectHTTPToHTTPS && acmeManager.HasHTTPS() {
		proxyHTTPHandler = acmeManager.HTTPChallengeHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHost := r.Host
			if host, _, err := net.SplitHostPort(r.Host); err == nil {
				targetHost = host
			}
			target := "https://" + targetHost
			if httpsPort := portFromAddr(cfg.ProxyHTTPSAddr); httpsPort != "" && httpsPort != "443" {
				target += ":" + httpsPort
			}
			target += r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}))
	}

	proxyServer := &http.Server{
		Addr:              cfg.ProxyHTTPAddr,
		Handler:           proxyHTTPHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	var proxyHTTPSServer *http.Server
	var proxyTLSListener net.Listener

	go func() {
		logger.Info("starting api server", "addr", cfg.HTTPAddr, "version", cfg.AppVersion)
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("api server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	go func() {
		logger.Info("starting proxy server", "addr", cfg.ProxyHTTPAddr, "version", cfg.AppVersion)
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("proxy server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	if acmeManager.HasHTTPS() {
		listener, err := net.Listen("tcp", cfg.ProxyHTTPSAddr)
		if err != nil {
			logger.Error("failed to listen on https proxy addr", "error", err)
			os.Exit(1)
		}

		proxyTLSListener = tls.NewListener(listener, acmeManager.TLSConfig())
		proxyHTTPSServer = &http.Server{
			Addr:              cfg.ProxyHTTPSAddr,
			Handler:           server.ProxyHandler(),
			ReadHeaderTimeout: 10 * time.Second,
		}

		go func() {
			logger.Info("starting https proxy server", "addr", cfg.ProxyHTTPSAddr, "version", cfg.AppVersion)
			if err := proxyHTTPSServer.Serve(proxyTLSListener); err != nil && err != http.ErrServerClosed {
				logger.Error("https proxy server stopped unexpectedly", "error", err)
				os.Exit(1)
			}
		}()
	}

	if cfg.ACMELeader {
		acmeManager.StartWorker(rootCtx)
	}
	<-rootCtx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	acmeManager.StopWorker()
	auditSink.Close()
	if redisClient != nil {
		_ = redisClient.Close()
	}

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("api shutdown failed", "error", err)
		os.Exit(1)
	}
	if err := proxyServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("proxy shutdown failed", "error", err)
		os.Exit(1)
	}
	if proxyHTTPSServer != nil {
		if err := proxyHTTPSServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("https proxy shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}

func portFromAddr(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

func printUsage() {
	fmt.Println(`portlyn ` + version + `

Usage:
  portlyn               start the server (requires .env)
  portlyn init          interactive setup wizard (generates .env and admin user)
  portlyn settings sync apply env values for env-controlled settings to the database
  portlyn update        download, verify and install the latest release (flags: --check, --version, --no-restart, --unit)
  portlyn version       print version and exit
  portlyn help          show this help

Documentation: https://github.com/invaliduser231/Portlyn`)
}

func hostnameFromURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if parsed, err := url.Parse(trimmed); err == nil {
		if host := parsed.Hostname(); host != "" {
			return host
		}
	}
	return ""
}
