// Package webhook implements admission webhooks for AegisPolicy CRDs.
package webhook

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
)

// PolicyValidator validates AegisPolicy and AegisClusterPolicy resources.
type PolicyValidator struct {
	decoder admission.Decoder
}

// NewPolicyValidator creates a new webhook handler.
func NewPolicyValidator(decoder admission.Decoder) *PolicyValidator {
	return &PolicyValidator{decoder: decoder}
}

// Handle validates the admission request.
func (v *PolicyValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	var spec v1alpha1.AegisPolicySpec

	switch req.Kind.Kind {
	case "AegisPolicy":
		policy := &v1alpha1.AegisPolicy{}
		if err := v.decoder.Decode(req, policy); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		spec = policy.Spec
	case "AegisClusterPolicy":
		clusterPolicy := &v1alpha1.AegisClusterPolicy{}
		if err := v.decoder.Decode(req, clusterPolicy); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		spec = clusterPolicy.Spec
	default:
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("unsupported kind %q", req.Kind.Kind))
	}

	if errs := validateSpec(spec); len(errs) > 0 {
		return admission.Denied(strings.Join(errs, "; "))
	}

	return admission.Allowed("policy is valid")
}

func validateSpec(spec v1alpha1.AegisPolicySpec) []string {
	var errs []string

	if spec.Mode != "enforce" && spec.Mode != "audit" {
		errs = append(errs, fmt.Sprintf("invalid mode %q: must be 'enforce' or 'audit'", spec.Mode))
	}

	if spec.FileRules != nil {
		for i, rule := range spec.FileRules.Deny {
			if rule.Path == "" && rule.Inode == "" {
				errs = append(errs, fmt.Sprintf("fileRules.deny[%d]: must specify path or inode", i))
			}
			if rule.Path != "" && !strings.HasPrefix(rule.Path, "/") {
				errs = append(errs, fmt.Sprintf("fileRules.deny[%d]: path must be absolute", i))
			}
		}
		for i, rule := range spec.FileRules.Protect {
			if rule.Path == "" && rule.Inode == "" {
				errs = append(errs, fmt.Sprintf("fileRules.protect[%d]: must specify path or inode", i))
			}
			if rule.Path != "" && !strings.HasPrefix(rule.Path, "/") {
				errs = append(errs, fmt.Sprintf("fileRules.protect[%d]: path must be absolute", i))
			}
		}
	}

	if spec.NetworkRules != nil {
		for i, rule := range spec.NetworkRules.Deny {
			if rule.IP == "" && rule.CIDR == "" && rule.Port == 0 {
				errs = append(errs, fmt.Sprintf("networkRules.deny[%d]: must specify ip, cidr, or port", i))
			}
			if rule.IP != "" && net.ParseIP(rule.IP) == nil {
				errs = append(errs, fmt.Sprintf("networkRules.deny[%d]: invalid IP %q", i, rule.IP))
			}
			if rule.CIDR != "" {
				if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
					errs = append(errs, fmt.Sprintf("networkRules.deny[%d]: invalid CIDR %q", i, rule.CIDR))
				}
			}
		}
	}

	if spec.ExecRules != nil {
		for i, h := range spec.ExecRules.AllowBinaryHashes {
			if decoded, err := hex.DecodeString(h); err != nil || len(decoded) != 32 {
				errs = append(errs, fmt.Sprintf("execRules.allowBinaryHashes[%d]: must be 64-char SHA-256 hex", i))
			}
		}
		for i, h := range spec.ExecRules.DenyBinaryHashes {
			if decoded, err := hex.DecodeString(h); err != nil || len(decoded) != 32 {
				errs = append(errs, fmt.Sprintf("execRules.denyBinaryHashes[%d]: must be 64-char SHA-256 hex", i))
			}
		}
	}

	return errs
}
