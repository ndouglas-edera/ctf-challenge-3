# CTF Challenge 3
This CTF challenge was designed around the **NSA & CISAs Cybersecurity Technical Report**<br/>
https://ndouglas-edera.github.io/ctf-challenge-3/

## Challenge Layout

```
┌─────────────────────────────────────────────────────────────┐
│ TOP BAR / BRANDING                                          │
├─────────────────────────────────────────────────────────────┤
│ MISSION                                                     │
├──────────────────────────────┬──────────────────────────────┤
│                              │                              │
│                              │       ARCHITECTURE           │
│         TERMINAL             │                              │
│                              ├──────────────────────────────┤
│   complete the challenges    │                              │
│                              │       INVESTIGATION          │
│                              │                              │
│                              │                              │
├──────────────────────────────┴──────────────────────────────┤
│ FOOTER LINKS                                                │
└─────────────────────────────────────────────────────────────┘
```

## Understand the NSA's Hardening Guide
Trying to map out how this CTF should differ from CTF Challenge 2 <br/>
We received questions about how the NSA hardening guide differs from the **[OWASP Top 10 for Kubernetes](https://kubernetes-top10.owasp.org/)**.

| NSA/CISA section | OWASP T10 Kubernetes | Gap to fill |
| --- | --- | --- |
| Pod security (non-root, read-only root filesystem, no privilege escalation) | [K01](https://kubernetes-top10.owasp.org/2025/en/src/K01-Insecure-Workload-Configurations.html) ```allowPrivilegeEscalation``` | The ```securityProfileFor()``` already models ```runAsNonRoot```, ```readOnlyRootFilesystem```, capabilities, seccomp and token automount for every pod. Making one pod run as root or with a writable root filesystem is a one-line change plus a stage entry. |
| Sandboxed runtimes (the guide names gVisor and Kata) | Edera zones run throughout | The ```cri.toml``` already says that without ```runtimeClassName: edera``` a pod falls back to ```runc```. A "which pod isn't sandboxed" stage needs almost no new code. |
| Namespaces, NetworkPolicies, default deny | [K04](https://kubernetes-top10.owasp.org/2025/en/src/K04-Lack-Of-Cluster-Level-Policy-Enforcement.html), [K05](https://kubernetes-top10.owasp.org/2025/en/src/K05-Missing-Network-Segmentation-Controls.html) | Done |
| Resource policies (```LimitRange```, ```ResourceQuota```) | None | Needed to add some new ```kubectl get``` handlers for those 2 resource types. |
| Control plane (```etcd```, ```TLS```, ```kubeconfig```, API exposure) | [K06](https://kubernetes-top10.owasp.org/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html) | Needed some new files on the node (an ```etcd``` manifest or the ```kube-apiserver``` flags). |
| Secrets encrypted at rest | [K03](https://kubernetes-top10.owasp.org/2025/en/src/K03-Secrets-Management-Failures.html) is about leaked logs<br/> (not related to storage) | We needed to add an ```EncryptionConfiguration``` file.<br/> This file should use the identity provider. |
| Authentication and RBAC | [K02](https://kubernetes-top10.owasp.org/2025/en/src/K02-Overly-Permissive-Authorization-Configurations.html), [K09](https://kubernetes-top10.owasp.org/2025/en/src/K09-Broken-Authentication-Mechanisms.html) | Done |
| Upgrades and patching | [K06](https://kubernetes-top10.owasp.org/2025/en/src/K06-Overly-Exposed-Kubernetes-Components.html) (unsupported v1.30.2), <br/>[K07](https://kubernetes-top10.owasp.org/2025/en/src/K07-Misconfigured-And-Vulnerable-Cluster-Components.html) (end-of-life PHP image) | Done |
| Kubelet hardening | none | The ```/var/lib/kubelet/config.yaml``` exists but is already hardened. Turning ```anonymous.enabled``` on, or setting ```readOnlyPort: 10255```, gives users a new finding. |
