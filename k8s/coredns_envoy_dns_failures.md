# Introduction

  In a specific staging Envoy pod, we were continuously getting 5xx with "no
  healthy upstream" errors. Upon enabling debug logs, it was found that
  Envoy DNS lookups (for upstream cluster) were failing. `tcpdump` showed
  DNS UDP packets leaving Envoy but no responses were received. Getting a
  shell within the pod and making DNS lookups manually using `dig`
  succeeded.  The below analysis goes through the root cause.

# Root Cause

* All the nodes were shutdown (for doing some experiement, which was
  unintentional), among other things, coredns pods became unavailable, thus
  no pods were available behind the coredns service (which is of type
  ClusterIP) for that duration.

* envoy pod (`envoy-blue-7bb86bbf7d-76cmr`) came up (before the
  coredns pods became Ready) and Envoy did a DNS lookup (for various
  upstream clusters)

  * As part of DNS lookup (Envoy uses
    [c-ares](https://github.com/c-ares/c-ares) for DNS lookups), c-ares
    opens an UDP socket, does a `connect` on it, and then keeps using it
    until it gets closed or restarted etc.
  * Due to the `connect` call (even though not required for UDP, but is
    valid, improves route table lookup performance), the socket will be long
    lived and used for all the DNS lookups in future.

* When Envoy did a DNS lookup using the coredns ClusterIP, kube-proxy
  loadbalancing kicked in (to loadbalance traffic between all the available
  coredns pods), as part of that conntrack entry is created, but the request
  will fail (silenty as it is UDP), as no coredns pods are available.

  The conntrack entry would look something like this, which is stale at this
  point:

```
[root@ip-10-185-102-70 sureshponnusamy]# conntrack -p udp -L --src 10.185.103.92 
udp      17 29 src=10.185.103.92 dst=172.20.0.10 sport=48586 dport=53 [UNREPLIED] src=172.20.0.10 dst=10.185.103.92 sport=53 dport=48586 mark=0 use=1
```

  The entry would be marked `UNREPLIED` as there were no ready coredns pods
  to respond to this.

> NOTE: you might want to read through this
  [doc](./k8s_introduction.pdf)
  to get some understanding on how the kubernete services, kube-proxy,
  iptables, conntrack etc interact with each other.

* When the coredns pods become `Ready`, the above stale conntrack should
  have been cleared but wasn't due to a bug in Kubernetes, which is fixed in
  this
  [change](https://github.com/kubernetes/kubernetes/commit/909925b492a674bbadb8de9b694eef67cefabdb1)
  (which is available in v1.22.4 and above)

# Actions

1. Alert for excessive/continuous dns timeout erros in Envoy
    1. There seems to be no prometheus metrics available to track the DNS
       failures (TODO: will add it when I get sometime)
    2. For now, our existing alert for "zero instances in the upstream
       cluster" should cover (just that we won't know why though).
2. Configure Envoy to use TCP for dns lookups
