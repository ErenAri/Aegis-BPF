// Package webhook implements admission webhooks for AegisPolicy CRDs.
package webhook

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	v1alpha1 "github.com/ErenAri/aegis-operator/api/v1alpha1"
	"github.com/ErenAri/aegis-operator/internal/selector"
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
	var (
		spec      v1alpha1.AegisPolicySpec
		ownNS     string // empty for cluster-scoped resources
	)

	switch req.Kind.Kind {
	case "AegisPolicy":
		policy := &v1alpha1.AegisPolicy{}
		if err := v.decoder.Decode(req, policy); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		spec = policy.Spec
		ownNS = req.Namespace
	case "AegisClusterPolicy":
		clusterPolicy := &v1alpha1.AegisClusterPolicy{}
		if err := v.decoder.Decode(req, clusterPolicy); err != nil {
			return admission.Errored(http.StatusBadRequest, err)
		}
		spec = clusterPolicy.Spec
	default:
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("unsupported kind %q", req.Kind.Kind))
	}

	if errs := validateSpec(spec, ownNS); len(errs) > 0 {
		return admission.Denied(strings.Join(errs, "; "))
	}

	return admission.Allowed("policy is valid")
}

// validateSpec is the single source of truth for AegisPolicy/AegisClusterPolicy
// validation. ownNS is the policy's namespace for AegisPolicy, or "" for
// AegisClusterPolicy. The empty value disables the cross-namespace scope
// check, which is correct for cluster-scoped resources.
func validateSpec(spec v1alpha1.AegisPolicySpec, ownNS string) []string {
	var errs []string

	if spec.Mode != "enforce" && spec.Mode != "audit" {
		errs = append(errs, fmt.Sprintf("invalid mode %q: must be 'enforce' or 'audit'", spec.Mode))
	}

	errs = append(errs, validateFileRules(spec.FileRules)...)
	errs = append(errs, validateNetworkRules(spec.NetworkRules)...)
	errs = append(errs, validateExecRules(spec.ExecRules)...)
	errs = append(errs, validateWorkloadSelector(spec.WorkloadSelector, ownNS)...)

	return errs
}

func validateFileRules(fr *v1alpha1.FileRules) []string {
	if fr == nil {
		return nil
	}
	var errs []string
	errs = append(errs, validateFileRuleList("fileRules.deny", fr.Deny, true)...)
	errs = append(errs, validateFileRuleList("fileRules.protect", fr.Protect, false)...)
	return errs
}

// validateFileRuleList enforces shape rules and detects same-target Allow/Block
// collisions inside a single rule list. The collision check is intentionally
// scoped to a single list (deny vs protect) because cross-list collisions
// don't make semantic sense — protect entries don't have an Allow form.
func validateFileRuleList(field string, rules []v1alpha1.FileRule, allowActionField bool) []string {
	var errs []string
	// path → set of seen actions, used for collision detection.
	seenActions := make(map[string]map[v1alpha1.RuleAction]struct{})

	for i, rule := range rules {
		if rule.Path == "" && rule.Inode == "" {
			errs = append(errs, fmt.Sprintf("%s[%d]: must specify path or inode", field, i))
			continue
		}
		if rule.Path != "" && !strings.HasPrefix(rule.Path, "/") {
			errs = append(errs, fmt.Sprintf("%s[%d]: path must be absolute", field, i))
		}

		action := normalizeAction(rule.Action)

		if allowActionField && action == v1alpha1.RuleActionAllow && rule.Inode != "" {
			// The daemon has no [allow_inode] section; rejecting this at
			// admission stops the user from writing a policy that would
			// silently drop the rule at translate time.
			errs = append(errs, fmt.Sprintf(
				"%s[%d]: action=Allow is not supported for inode-based rules; use a path instead",
				field, i))
		}

		// protect rules don't have an Allow form — only the Block default
		// makes semantic sense, so an explicit Allow is rejected.
		if !allowActionField && action == v1alpha1.RuleActionAllow {
			errs = append(errs, fmt.Sprintf(
				"%s[%d]: action=Allow is not valid on protect rules; protect always implies Block",
				field, i))
		}

		if rule.Path != "" {
			actions, ok := seenActions[rule.Path]
			if !ok {
				actions = make(map[v1alpha1.RuleAction]struct{})
				seenActions[rule.Path] = actions
			}
			actions[action] = struct{}{}
		}
	}

	for path, actions := range seenActions {
		if _, hasAllow := actions[v1alpha1.RuleActionAllow]; hasAllow {
			if _, hasBlock := actions[v1alpha1.RuleActionBlock]; hasBlock {
				errs = append(errs, fmt.Sprintf(
					"%s: path %q is listed with both Allow and Block actions; resolve the conflict in spec instead of relying on merge precedence",
					field, path))
			}
		}
	}
	return errs
}

func validateNetworkRules(nr *v1alpha1.NetworkRules) []string {
	if nr == nil {
		return nil
	}
	var errs []string
	// Build a literal key from the rule's address-shape so we can detect
	// Allow/Block collisions on the same target. The key matches what the
	// translator emits into the INI section.
	seenActions := make(map[string]map[v1alpha1.RuleAction]struct{})

	for i, rule := range nr.Deny {
		if rule.IP == "" && rule.CIDR == "" && rule.Port == 0 {
			errs = append(errs, fmt.Sprintf("networkRules.deny[%d]: must specify ip, cidr, or port", i))
			continue
		}
		if rule.IP != "" && net.ParseIP(rule.IP) == nil {
			errs = append(errs, fmt.Sprintf("networkRules.deny[%d]: invalid IP %q", i, rule.IP))
		}
		if rule.CIDR != "" {
			if _, _, err := net.ParseCIDR(rule.CIDR); err != nil {
				errs = append(errs, fmt.Sprintf("networkRules.deny[%d]: invalid CIDR %q", i, rule.CIDR))
			}
		}

		key := networkRuleKey(rule)
		if key == "" {
			continue
		}
		action := normalizeAction(rule.Action)
		actions, ok := seenActions[key]
		if !ok {
			actions = make(map[v1alpha1.RuleAction]struct{})
			seenActions[key] = actions
		}
		actions[action] = struct{}{}
	}

	for key, actions := range seenActions {
		if _, hasAllow := actions[v1alpha1.RuleActionAllow]; hasAllow {
			if _, hasBlock := actions[v1alpha1.RuleActionBlock]; hasBlock {
				errs = append(errs, fmt.Sprintf(
					"networkRules.deny: target %q is listed with both Allow and Block actions; resolve the conflict in spec instead of relying on merge precedence",
					key))
			}
		}
	}
	return errs
}

// networkRuleKey returns a stable key identifying the literal target of a
// network rule, mirroring the INI section the translator would emit. Rules
// that don't have a recognisable target return "".
func networkRuleKey(r v1alpha1.NetworkRule) string {
	switch {
	case r.IP != "" && r.Port > 0:
		return fmt.Sprintf("ip_port:%s:%s:%d:%s", r.IP, defaultProto(r.Protocol), r.Port, defaultDir(r.Direction))
	case r.IP != "":
		return "ip:" + r.IP
	case r.CIDR != "":
		return "cidr:" + r.CIDR
	case r.Port > 0:
		return fmt.Sprintf("port:%s:%d:%s", defaultProto(r.Protocol), r.Port, defaultDir(r.Direction))
	}
	return ""
}

func defaultProto(p string) string {
	if p == "" {
		return "tcp"
	}
	return p
}

func defaultDir(d string) string {
	if d == "" {
		return "outbound"
	}
	return d
}

func validateExecRules(er *v1alpha1.ExecRules) []string {
	if er == nil {
		return nil
	}
	var errs []string
	for i, h := range er.AllowBinaryHashes {
		if !isSHA256Hex(h) {
			errs = append(errs, fmt.Sprintf("execRules.allowBinaryHashes[%d]: must be 64-char SHA-256 hex", i))
		}
	}
	for i, h := range er.DenyBinaryHashes {
		if !isSHA256Hex(h) {
			errs = append(errs, fmt.Sprintf("execRules.denyBinaryHashes[%d]: must be 64-char SHA-256 hex", i))
		}
	}
	for i, comm := range er.DenyComm {
		if len(comm) == 0 {
			errs = append(errs, fmt.Sprintf("execRules.denyComm[%d]: must not be empty", i))
		} else if len(comm) > 15 {
			errs = append(errs, fmt.Sprintf("execRules.denyComm[%d]: %q exceeds 15 chars (kernel TASK_COMM_LEN-1)", i, comm))
		}
		if strings.ContainsAny(comm, "/\x00") {
			errs = append(errs, fmt.Sprintf("execRules.denyComm[%d]: %q must not contain '/' or null bytes", i, comm))
		}
	}
	// Detect Allow/Block hash collisions in the same spec.
	allow := make(map[string]struct{}, len(er.AllowBinaryHashes))
	for _, h := range er.AllowBinaryHashes {
		allow[h] = struct{}{}
	}
	for _, h := range er.DenyBinaryHashes {
		if _, ok := allow[h]; ok {
			errs = append(errs, fmt.Sprintf(
				"execRules: hash %q is listed in both allowBinaryHashes and denyBinaryHashes",
				h))
		}
	}
	return errs
}

func isSHA256Hex(h string) bool {
	decoded, err := hex.DecodeString(h)
	return err == nil && len(decoded) == 32
}

// validateWorkloadSelector validates the new spec.workloadSelector field,
// including the cross-namespace scope check for namespaced AegisPolicy.
//
// ownNS is the policy's own namespace for AegisPolicy ("" for cluster).
// When ownNS is non-empty, namespace selectors must reference only that
// namespace.
func validateWorkloadSelector(ws *v1alpha1.WorkloadSelector, ownNS string) []string {
	if ws == nil {
		return nil
	}
	var errs []string

	if _, err := metav1.LabelSelectorAsSelector(ws.PodSelector); err != nil {
		errs = append(errs, fmt.Sprintf("workloadSelector.podSelector: %v", err))
	}
	if _, err := metav1.LabelSelectorAsSelector(ws.NamespaceSelector); err != nil {
		errs = append(errs, fmt.Sprintf("workloadSelector.namespaceSelector: %v", err))
	}

	for i, name := range ws.MatchNamespaceNames {
		if msgs := validation.IsDNS1123Label(name); len(msgs) > 0 {
			errs = append(errs, fmt.Sprintf(
				"workloadSelector.matchNamespaceNames[%d]: %q is not a valid namespace name (%s)",
				i, name, strings.Join(msgs, ", ")))
		}
	}

	// Cross-namespace scope check for namespaced AegisPolicy.
	if ownNS != "" {
		if ws.NamespaceSelector != nil &&
			(len(ws.NamespaceSelector.MatchLabels) > 0 || len(ws.NamespaceSelector.MatchExpressions) > 0) {
			// Allow only the trivial selector that matches the policy's
			// own namespace by metadata.name. Anything else implies
			// cross-namespace selection.
			if !namespaceSelectorPinnedTo(ws.NamespaceSelector, ownNS) {
				errs = append(errs, fmt.Sprintf(
					"workloadSelector.namespaceSelector: namespaced AegisPolicy in %q cannot select other namespaces; use AegisClusterPolicy for cluster-wide scope",
					ownNS))
			}
		}
		for i, name := range ws.MatchNamespaceNames {
			if name != ownNS {
				errs = append(errs, fmt.Sprintf(
					"workloadSelector.matchNamespaceNames[%d]: namespaced AegisPolicy in %q may only reference its own namespace, got %q",
					i, ownNS, name))
			}
		}
	}

	return errs
}

// namespaceSelectorPinnedTo reports whether the given namespaceSelector
// matches exactly the given namespace name and nothing else. We accept
// either matchLabels{kubernetes.io/metadata.name: ownNS} or the equivalent
// matchExpressions form.
func namespaceSelectorPinnedTo(ns *metav1.LabelSelector, name string) bool {
	if ns == nil {
		return false
	}
	if v, ok := ns.MatchLabels[selector.NamespaceMetadataNameLabel]; ok && v == name && len(ns.MatchLabels) == 1 && len(ns.MatchExpressions) == 0 {
		return true
	}
	if len(ns.MatchExpressions) == 1 && len(ns.MatchLabels) == 0 {
		req := ns.MatchExpressions[0]
		if req.Key == selector.NamespaceMetadataNameLabel &&
			req.Operator == metav1.LabelSelectorOpIn &&
			len(req.Values) == 1 && req.Values[0] == name {
			return true
		}
	}
	return false
}

// normalizeAction returns the effective action for a rule, treating an
// empty Action as Block (matching the kubebuilder default).
func normalizeAction(a v1alpha1.RuleAction) v1alpha1.RuleAction {
	if a == "" {
		return v1alpha1.RuleActionBlock
	}
	return a
}
