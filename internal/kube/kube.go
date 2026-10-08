// Package kube finds sandboxed pods and runs commands inside them.
package kube

import (
	"context"
	"fmt"
	"io"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type Target struct {
	Namespace   string        `json:"namespace"`
	Pod         string        `json:"pod"`
	Container   string        `json:"container"`
	Node        string        `json:"node"`
	Image       string        `json:"image"`
	ImageID     string        `json:"imageID"`
	ContainerID string        `json:"containerID"`
	Mounts      []VolumeMount `json:"mounts,omitempty"`
}

type VolumeMount struct {
	Path   string `json:"path"`
	Volume string `json:"volume"`
	Kind   string `json:"kind"`
}

// Sensitive reports whether the volume type carries credentials or
// configuration rather than software. These are never copied.
func (m VolumeMount) Sensitive() bool {
	switch m.Kind {
	case "secret", "configMap", "projected", "downwardAPI":
		return true
	}
	return false
}

func (t Target) String() string {
	return t.Namespace + "/" + t.Pod + "/" + t.Container
}

type Selector struct {
	Namespace     string
	AllNamespaces bool
	Pod           string
	RuntimeClass  string
	// Node limits the scan to pods scheduled on this node.
	Node string
}

type Client struct {
	cs        kubernetes.Interface
	config    *rest.Config
	namespace string
	platforms map[string]string
}

func New(kubeconfig, kubeContext string) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	loader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext})
	cfg, err := loader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}
	ns, _, err := loader.Namespace()
	if err != nil {
		return nil, err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cs: cs, config: cfg, namespace: ns, platforms: map[string]string{}}, nil
}

// Targets returns every running container in pods that use the selected runtime class.
func (c *Client) Targets(ctx context.Context, sel Selector) ([]Target, error) {
	ns := sel.Namespace
	if ns == "" {
		ns = c.namespace
	}
	if sel.AllNamespaces {
		ns = metav1.NamespaceAll
	}

	var pods []corev1.Pod
	if sel.Pod != "" {
		p, err := c.cs.CoreV1().Pods(ns).Get(ctx, sel.Pod, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if rc := p.Spec.RuntimeClassName; rc == nil || *rc != sel.RuntimeClass {
			return nil, fmt.Errorf("pod %s/%s does not use runtime class %q", ns, sel.Pod, sel.RuntimeClass)
		}
		if sel.Node != "" && p.Spec.NodeName != sel.Node {
			return nil, fmt.Errorf("pod %s/%s runs on node %q, not %q", ns, sel.Pod, p.Spec.NodeName, sel.Node)
		}
		pods = []corev1.Pod{*p}
	} else {
		opts := metav1.ListOptions{}
		if sel.Node != "" {
			opts.FieldSelector = "spec.nodeName=" + sel.Node
		}
		list, err := c.cs.CoreV1().Pods(ns).List(ctx, opts)
		if err != nil {
			return nil, err
		}
		pods = list.Items
	}

	var targets []Target
	for _, p := range pods {
		if rc := p.Spec.RuntimeClassName; rc == nil || *rc != sel.RuntimeClass {
			continue
		}
		if p.Status.Phase != corev1.PodRunning {
			continue
		}
		kinds := map[string]string{}
		for _, v := range p.Spec.Volumes {
			kinds[v.Name] = volumeKind(v.VolumeSource)
		}
		images := map[string]string{}
		mounts := map[string][]VolumeMount{}
		for _, ct := range p.Spec.Containers {
			images[ct.Name] = ct.Image
			for _, vm := range ct.VolumeMounts {
				mounts[ct.Name] = append(mounts[ct.Name], VolumeMount{Path: vm.MountPath, Volume: vm.Name, Kind: kinds[vm.Name]})
			}
		}
		for _, cs := range p.Status.ContainerStatuses {
			if cs.State.Running == nil {
				continue
			}
			targets = append(targets, Target{
				Namespace:   p.Namespace,
				Pod:         p.Name,
				Container:   cs.Name,
				Node:        p.Spec.NodeName,
				Image:       images[cs.Name],
				ImageID:     cs.ImageID,
				ContainerID: cs.ContainerID,
				Mounts:      mounts[cs.Name],
			})
		}
	}
	return targets, nil
}

func volumeKind(v corev1.VolumeSource) string {
	switch {
	case v.Secret != nil:
		return "secret"
	case v.ConfigMap != nil:
		return "configMap"
	case v.Projected != nil:
		return "projected"
	case v.DownwardAPI != nil:
		return "downwardAPI"
	case v.EmptyDir != nil:
		return "emptyDir"
	case v.PersistentVolumeClaim != nil:
		return "persistentVolumeClaim"
	case v.HostPath != nil:
		return "hostPath"
	case v.CSI != nil:
		return "csi"
	case v.Ephemeral != nil:
		return "ephemeral"
	}
	return "other"
}

// Platform returns the node's OS/architecture, e.g. "linux/arm64", so the
// image SBOM is built from the same variant of a multi-arch image the pod runs.
func (c *Client) Platform(ctx context.Context, node string) (string, error) {
	if p, ok := c.platforms[node]; ok {
		return p, nil
	}
	n, err := c.cs.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	p := n.Status.NodeInfo.OperatingSystem + "/" + n.Status.NodeInfo.Architecture
	c.platforms[node] = p
	return p, nil
}

// Exec runs cmd in the target container, the same way `kubectl exec` does.
// Under gVisor the command runs inside the sandbox, so it sees the
// container's filesystem exactly as the workload does.
func (c *Client) Exec(ctx context.Context, t Target, cmd []string, stdout, stderr io.Writer) error {
	req := c.cs.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(t.Namespace).Name(t.Pod).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: t.Container,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	ws, err := remotecommand.NewWebSocketExecutor(c.config, "GET", req.URL().String())
	if err != nil {
		return err
	}
	spdy, err := remotecommand.NewSPDYExecutor(c.config, "POST", req.URL())
	if err != nil {
		return err
	}
	exec, err := remotecommand.NewFallbackExecutor(ws, spdy, func(err error) bool {
		return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
	})
	if err != nil {
		return err
	}
	return exec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: stdout, Stderr: stderr})
}

// ImageRef turns a container status imageID into a pullable reference pinned
// by digest. Runtimes report it as "repo@sha256:...", sometimes with a
// "docker-pullable://" prefix, and some report only "sha256:...".
func ImageRef(image, imageID string) (string, error) {
	id := strings.TrimPrefix(imageID, "docker-pullable://")
	if strings.Contains(id, "@sha256:") {
		return id, nil
	}
	if strings.HasPrefix(id, "sha256:") && image != "" {
		repo := image
		if i := strings.Index(repo, "@"); i >= 0 {
			repo = repo[:i]
		}
		if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
			repo = repo[:i]
		}
		return repo + "@" + id, nil
	}
	return "", fmt.Errorf("cannot derive a digest reference from image %q, imageID %q", image, imageID)
}
