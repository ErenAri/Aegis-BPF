// Package main is the entrypoint for the aegis-operator, a Kubernetes operator
// that translates AegisPolicy CRDs into policy ConfigMaps consumed by the
// Aegis-BPF DaemonSet daemon.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
	"github.com/ErenAri/aegis-operator/controllers"
	"github.com/ErenAri/aegis-operator/internal/console"
	"github.com/ErenAri/aegis-operator/internal/identity"
	aegiswebhook "github.com/ErenAri/aegis-operator/internal/webhook"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr          string
		healthAddr           string
		enableLeaderElection bool
		identityEnabled      bool
		identityInterval     time.Duration
		enableWebhook        bool
		webhookPort          int
		enableConsole        bool
		consoleAddr          string
		consoleAuthUser      string
		consolePasswordFile  string
		consoleTLSCertFile   string
		consoleTLSKeyFile    string
		consoleInsecureHTTP  bool
		consoleUnauth        bool
		agentNamespace       string
	)

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&healthAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager, ensuring only one active controller.")
	flag.BoolVar(&identityEnabled, "enable-identity-resolution", true,
		"Enable Kubernetes pod identity resolution and caching.")
	flag.DurationVar(&identityInterval, "identity-refresh-interval", 30*time.Second,
		"Interval between identity cache refreshes.")
	flag.BoolVar(&enableWebhook, "enable-webhook", false,
		"Enable validating admission webhook for AegisPolicy CRDs.")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "Port for the webhook server.")
	flag.BoolVar(&enableConsole, "enable-console", false,
		"Enable the web console for policy visualization and monitoring.")
	flag.StringVar(&consoleAddr, "console-addr", ":9090",
		"The address the web console binds to.")
	flag.StringVar(&consoleAuthUser, "console-auth-user", envOrDefault("AEGIS_CONSOLE_AUTH_USER", "admin"),
		"Basic auth username for the web console.")
	flag.StringVar(&consolePasswordFile, "console-auth-password-file", os.Getenv("AEGIS_CONSOLE_PASSWORD_FILE"),
		"Path to a file containing the web console basic auth password. AEGIS_CONSOLE_PASSWORD is accepted as a fallback.")
	flag.StringVar(&consoleTLSCertFile, "console-tls-cert-file", os.Getenv("AEGIS_CONSOLE_TLS_CERT_FILE"),
		"Path to the TLS certificate for the web console.")
	flag.StringVar(&consoleTLSKeyFile, "console-tls-key-file", os.Getenv("AEGIS_CONSOLE_TLS_KEY_FILE"),
		"Path to the TLS private key for the web console.")
	flag.BoolVar(&consoleInsecureHTTP, "console-insecure-allow-http", false,
		"Allow the web console to serve plaintext HTTP. Intended only for local development or TLS-terminating proxies.")
	flag.BoolVar(&consoleUnauth, "console-insecure-allow-unauthenticated", false,
		"Allow the web console without authentication. Intended only for local development.")
	flag.StringVar(&agentNamespace, "agent-namespace", envOrDefault("AEGIS_AGENT_NAMESPACE", controllers.DefaultAgentNamespace),
		"Namespace containing AegisBPF DaemonSet pods for live agent sync.")

	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	logger := ctrl.Log.WithName("setup")

	mgrOpts := ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: healthAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "aegis-operator-leader",
	}
	if enableWebhook {
		mgrOpts.WebhookServer = webhook.NewServer(webhook.Options{
			Port: webhookPort,
		})
	}
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
	if err != nil {
		logger.Error(err, "Unable to create manager")
		os.Exit(1)
	}

	eventBroker := console.NewBroker()

	if err := (&controllers.AegisPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Publisher: eventBroker,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create AegisPolicy controller")
		os.Exit(1)
	}

	// NEW: live agent sync controller
	if err := (&controllers.AegisPolicyAgentReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		RestConfig:     mgr.GetConfig(),
		AgentNamespace: agentNamespace,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create AegisPolicy agent sync controller")
		os.Exit(1)
	}

	if err := (&controllers.AegisClusterPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Publisher: eventBroker,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create AegisClusterPolicy controller")
		os.Exit(1)
	}

	if err := (&controllers.MergedPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		Publisher: eventBroker,
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create MergedPolicy controller")
		os.Exit(1)
	}

	if err := (&controllers.NodeFeatureReconciler{
		Client: mgr.GetClient(),
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create NodeFeature controller")
		os.Exit(1)
	}

	if enableWebhook {
		decoder := admission.NewDecoder(scheme)
		validator := aegiswebhook.NewPolicyValidator(decoder)
		mgr.GetWebhookServer().Register(
			"/validate-aegisbpf-io-v1alpha1-policy", &webhook.Admission{Handler: validator})
		logger.Info("Validating webhook registered", "port", webhookPort)
	}

	if identityEnabled {
		resolver := identity.NewResolver(mgr.GetClient(), identityInterval)
		if err := mgr.Add(resolver); err != nil {
			logger.Error(err, "Unable to add identity resolver")
			os.Exit(1)
		}
		logger.Info("Identity resolution enabled", "interval", identityInterval)
	}

	if enableConsole {
		consolePassword, err := loadConsolePassword(consolePasswordFile)
		if err != nil {
			logger.Error(err, "Unable to read console password")
			os.Exit(1)
		}
		consoleSrv, err := console.NewServer(mgr.GetClient(), consoleAddr, eventBroker, console.ServerOptions{
			BasicAuthUsername:    consoleAuthUser,
			BasicAuthPassword:    consolePassword,
			TLSCertFile:          consoleTLSCertFile,
			TLSKeyFile:           consoleTLSKeyFile,
			AllowInsecureHTTP:    consoleInsecureHTTP,
			AllowUnauthenticated: consoleUnauth,
		})
		if err != nil {
			logger.Error(err, "Unable to create console server")
			os.Exit(1)
		}
		if err := mgr.Add(consoleSrv); err != nil {
			logger.Error(err, "Unable to add console server")
			os.Exit(1)
		}
		logger.Info("Web console enabled", "addr", consoleAddr)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "Unable to set up readiness check")
		os.Exit(1)
	}

	logger.Info("Starting aegis-operator", "version", "0.5.0")

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "Problem running manager")
		os.Exit(1)
	}
}

func envOrDefault(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func loadConsolePassword(path string) (string, error) {
	if path != "" {
		contents, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read console password file: %w", err)
		}
		return strings.TrimRight(string(contents), "\r\n"), nil
	}
	return strings.TrimRight(os.Getenv("AEGIS_CONSOLE_PASSWORD"), "\r\n"), nil
}
