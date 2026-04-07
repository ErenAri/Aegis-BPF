// Package main is the entrypoint for the aegis-operator, a Kubernetes operator
// that translates AegisPolicy CRDs into policy ConfigMaps consumed by the
// Aegis-BPF DaemonSet daemon.
package main

import (
	"flag"
	"os"
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

	// Register AegisPolicy controller.
	if err := (&controllers.AegisPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create AegisPolicy controller")
		os.Exit(1)
	}

	// Register AegisClusterPolicy controller.
	if err := (&controllers.AegisClusterPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create AegisClusterPolicy controller")
		os.Exit(1)
	}

	// Register merged policy reconciler — watches all policies and produces
	// a single merged ConfigMap consumed by the DaemonSet daemon.
	if err := (&controllers.MergedPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		logger.Error(err, "Unable to create MergedPolicy controller")
		os.Exit(1)
	}

	// Register validating admission webhook for policy CRDs.
	if enableWebhook {
		decoder := admission.NewDecoder(scheme)
		validator := aegiswebhook.NewPolicyValidator(decoder)
		mgr.GetWebhookServer().Register(
			"/validate-aegisbpf-io-v1alpha1-policy", &webhook.Admission{Handler: validator})
		logger.Info("Validating webhook registered", "port", webhookPort)
	}

	// Start identity resolver if enabled.
	if identityEnabled {
		resolver := identity.NewResolver(mgr.GetClient(), identityInterval)
		if err := mgr.Add(resolver); err != nil {
			logger.Error(err, "Unable to add identity resolver")
			os.Exit(1)
		}
		logger.Info("Identity resolution enabled", "interval", identityInterval)
	}

	// Health and readiness probes.
	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		logger.Error(err, "Unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		logger.Error(err, "Unable to set up readiness check")
		os.Exit(1)
	}

	logger.Info("Starting aegis-operator",
		"version", "0.1.0",
		"leaderElection", enableLeaderElection,
		"identityResolution", identityEnabled,
		"webhook", enableWebhook,
	)

	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "Problem running manager")
		os.Exit(1)
	}
}
