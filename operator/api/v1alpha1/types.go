package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=ap,categories=aegisbpf
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Nodes",type=integer,JSONPath=`.status.appliedNodes`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AegisPolicy defines a namespaced security policy enforced by Aegis-BPF.
type AegisPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AegisPolicySpec   `json:"spec,omitempty"`
	Status AegisPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AegisPolicyList contains a list of AegisPolicy resources.
type AegisPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AegisPolicy `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,shortName=acp,categories=aegisbpf
// +kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.mode`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AegisClusterPolicy defines a cluster-wide security policy enforced by Aegis-BPF.
type AegisClusterPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AegisPolicySpec   `json:"spec,omitempty"`
	Status AegisPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AegisClusterPolicyList contains a list of AegisClusterPolicy resources.
type AegisClusterPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AegisClusterPolicy `json:"items"`
}

// AegisPolicySpec defines the desired state of an Aegis security policy.
type AegisPolicySpec struct {
	// Mode controls whether the policy enforces or audits.
	// +kubebuilder:validation:Enum=enforce;audit
	// +kubebuilder:default=audit
	Mode string `json:"mode"`

	// Selector restricts which workloads this policy applies to.
	// +optional
	Selector *PolicySelector `json:"selector,omitempty"`

	// FileRules defines file access deny and protect rules.
	// +optional
	FileRules *FileRules `json:"fileRules,omitempty"`

	// NetworkRules defines network deny rules.
	// +optional
	NetworkRules *NetworkRules `json:"networkRules,omitempty"`

	// ExecRules defines execution allow/deny rules.
	// +optional
	ExecRules *ExecRules `json:"execRules,omitempty"`

	// KernelRules defines kernel-level protection rules.
	// +optional
	KernelRules *KernelRules `json:"kernelRules,omitempty"`
}

// PolicySelector restricts which workloads a policy applies to.
type PolicySelector struct {
	// MatchLabels selects pods by label.
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`

	// MatchNamespaces restricts the policy to specific namespaces.
	// +optional
	MatchNamespaces []string `json:"matchNamespaces,omitempty"`
}

// FileRules defines file access control rules.
type FileRules struct {
	// Deny lists files to block access to.
	// +optional
	Deny []FileRule `json:"deny,omitempty"`

	// Protect lists files to monitor for integrity changes.
	// +optional
	Protect []FileRule `json:"protect,omitempty"`
}

// FileRule identifies a file by path or inode.
type FileRule struct {
	// Path is the file path to match.
	// +optional
	Path string `json:"path,omitempty"`

	// Inode is the device:inode pair (e.g., "259:12345").
	// +kubebuilder:validation:Pattern=`^\d+:\d+$`
	// +optional
	Inode string `json:"inode,omitempty"`
}

// NetworkRules defines network access control rules.
type NetworkRules struct {
	// Deny lists network destinations to block.
	// +optional
	Deny []NetworkRule `json:"deny,omitempty"`
}

// NetworkRule identifies a network destination to deny.
type NetworkRule struct {
	// IP is an exact IP address to deny.
	// +optional
	IP string `json:"ip,omitempty"`

	// CIDR is a CIDR range to deny (e.g., "10.0.0.0/8").
	// +optional
	CIDR string `json:"cidr,omitempty"`

	// Port is the destination port to deny (1-65535).
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// +optional
	Port int `json:"port,omitempty"`

	// Protocol is the transport protocol ("tcp" or "udp").
	// +kubebuilder:validation:Enum=tcp;udp
	// +optional
	Protocol string `json:"protocol,omitempty"`

	// Direction is the traffic direction ("outbound" or "inbound").
	// +kubebuilder:validation:Enum=outbound;inbound
	// +optional
	Direction string `json:"direction,omitempty"`
}

// ExecRules defines execution control rules.
type ExecRules struct {
	// AllowBinaryHashes lists SHA-256 hashes of allowed binaries.
	// +optional
	AllowBinaryHashes []string `json:"allowBinaryHashes,omitempty"`

	// DenyBinaryHashes lists SHA-256 hashes of denied binaries.
	// +optional
	DenyBinaryHashes []string `json:"denyBinaryHashes,omitempty"`

	// DenyComm lists process command names to deny execution.
	// +optional
	DenyComm []string `json:"denyComm,omitempty"`
}

// KernelRules defines kernel-level protection mechanisms.
type KernelRules struct {
	// BlockModuleLoad prevents loading of kernel modules.
	// +optional
	BlockModuleLoad bool `json:"blockModuleLoad,omitempty"`

	// BlockPtrace prevents ptrace-based process debugging/injection.
	// +optional
	BlockPtrace bool `json:"blockPtrace,omitempty"`

	// BlockBpfSyscall prevents unauthorized BPF program loading.
	// +optional
	BlockBpfSyscall bool `json:"blockBpfSyscall,omitempty"`
}

// AegisPolicyStatus defines the observed state of an Aegis policy.
type AegisPolicyStatus struct {
	// Phase indicates the policy lifecycle phase.
	// +kubebuilder:validation:Enum=Pending;Applied;Error
	Phase string `json:"phase,omitempty"`

	// Message provides human-readable status details.
	// +optional
	Message string `json:"message,omitempty"`

	// AppliedNodes is the number of nodes where this policy is active.
	AppliedNodes int `json:"appliedNodes,omitempty"`

	// LastAppliedAt is the timestamp of the last successful application.
	// +optional
	LastAppliedAt *metav1.Time `json:"lastAppliedAt,omitempty"`

	// PolicyHash is the SHA-256 hash of the generated policy content.
	// +optional
	PolicyHash string `json:"policyHash,omitempty"`

	// ObservedGeneration is the generation most recently observed by the controller.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

func init() {
	SchemeBuilder.Register(
		&AegisPolicy{},
		&AegisPolicyList{},
		&AegisClusterPolicy{},
		&AegisClusterPolicyList{},
	)
}
