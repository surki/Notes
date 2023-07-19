Random notes on running backend services reliably, talks about TCP, networking, AWS VPC SDN, Kubernetes etc

## Listen backlog
   * For services expecting to handle large number of connections, specifically of bursty nature, an appropriate value for listen backlog should be configured. For improperly configured services, connection attempts might be lost and/or slowed down. Read [here](https://theojulienne.io/2020/07/03/scaling-linux-services-before-accepting-connections.html) for an in-depth walk through.
   * If you are in Kubernetes or using containers, the configuration must be done within that network namespace.
     <details>
     <summary>Example k8s deployment configuration</summary>
       </br>

       ```
       apiVersion: apps/v1
       kind: Deployment
       metadata:
         name: foo
       spec:
         ...
         ...
         template:
           ...
           ...
           spec:
             ...
             ...
             securityContext:
               ...
               ...
               sysctls:
               - name: net.core.somaxconn
                 value: "32000"
               - name: net.ipv4.ip_local_port_range
                 value: "1024 64000"
               ...
               ...
       ```

     </details>

   * In addition to configuring, the listen backlog metrics must be collected/monitored/alerted on. Note that if the service is running within a container/pod, then the monitoring can only be done from *witin* the pod as these metrics are per network namespace and not visible from root network namespace.
     <details>
     <summary>Example k8s deployment using node-exporter sidecar</summary>
       </br>

       ```
       apiVersion: apps/v1
       kind: Deployment
       metadata:
         name: foo
       spec:
         ...
         ...
         template:
           ...
           ...
           spec:
             ...
             ...
             containers:
             - image: foo
               ...
               ...
             - image: node-exporter
               name: node-exporter
               args:
               - --web.listen-address=0.0.0.0:9100
               - --collector.disable-defaults
               - --web.disable-exporter-metrics
               - --collector.conntrack
               - --collector.filefd
               - --collector.netstat
               - --collector.sockstat
               ...
               ...
               securityContext:
                 readOnlyRootFilesystem: true
                 runAsNonRoot: true
                 allowPrivilegeEscalation: false
                 capabilities:
                   drop: ["all"]
               ...
               ...
       ```

     </details>

   * Alerting should be configured, among others, at least for drops and overflows

     <details>
     <summary>Example promql query for listen overflow alerts</summary>
       </br>

       ```
       sum by (k8s_cluster_name, pod) (rate(node_netstat_TcpExt_ListenDrops[5m]) > 0) > 5
       sum by (k8s_cluster_name, pod) (rate(node_netstat_TcpExt_ListenOverflows[5m]) > 0) > 5
       ```
     </details>

## Protect against slow clients

   * When using a process(rails etc)/thread(java etc) per request model, for each request the thread/process will be held until entire request is received, processed and the response sent. When dealing with a slow client (intentional or unintentional(mobile etc)), it is important to protect services against such slow clients as that can quickly lead to capacity exhaustion (for example: 5 app instances each configured with 100 threads, can only handle 500 concurrent requests). Note that both the request path and response path need protection.

     <details>
     <summary>Example command to mimic slow client that sends 10K bytes slowly</summary>
       </br>

       ```
       (echo -e -n 'POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10000\r\n\r\n'; i=0; while [ $i -lt 10000 ]; do echo -n "aaaaaaaaaa"; sleep 1; i=$((i+10)); done) \
         | socat -t 10 - TCP4:example.com:80
       ```

     </details>

   * One way to solve this problem is using reverse proxies (nginx or [envoy + buffer filter](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/buffer_filter)) infront of the service, which can receive entire request, and then forward it to the application once entire request has been received.

   * In addition to this, appropriate timeouts must be configured
     * Max time to receive the headers (to protect against slow header data)
     * Max time to receive the request body (to protect against slow body payload)
     * Max idle time (to protect against fd etc resource exhaustion)
     * Max request processing time once request has been received

   * These timeout configurations vary by the reverse proxy being used. For Envoy, one may refer to [this](https://www.envoyproxy.io/docs/envoy/latest/faq/configuration/timeouts.html).

   * When using such proxies, it is also important to track the queue time of such requests as not to exhause other resources (file descriptors, connection limits/ports etc). This again may vary based on the proxy being used.

## Network latency and cost
  * When using a cloud provider (such as AWS, GCP etc), one may operate multiple accounts (to minimize blast radius) and/or VPCs, each having one or more services running. They all need to communicate with each other over privately.
  * To connect all of them with each other, there are multiple options available. They all have their own tradeoffs (for example: ease of use/maintainenance but high cost, or low cost but high maintenance etc). How one chooses the preferred solution entirely depends on the use case. This puts out some numbers which can be input to decide this.
  * AWS network latency (measured ~2020 in us-east-1)
    <details>
    <summary>Setup detail</summary>
      </br>

      - Region us-east-1
      - Two AWS accounts were used
      - We measured end-to-end RTT latency (send some bytes, recv back some bytes,
        measure the RTT etc), which is how typical applications communicate
      - `netperf` is the tool used
        - Installation:
          ```
          yum install -y automake autoconf gcc git automake texinfo &&
          git clone https://github.com/HewlettPackard/netperf.git &&
              cd netperf && ./autogen.sh && ./configure --prefix=/usr && make install
          ```
        - On target machine (we use `chrt` to make sure scheduler latencies do not affect our measurements):
          ```
          chrt --rr 99 netserver -4
          ```
        - On client machine:
          ```
          chrt --rr 99 netperf -j -t TCP_RR -H $TARGET_HOST -l 60 -p 12865 -- \
            -P ,1234 -r1,1 -o P50_LATENCY,P90_LATENCY,P99_LATENCY
          ```
      - VPC NLB PrivateLink setup
        - netperf uses two separate connections/ports for `control plane` and `data plane`
        - So one must setup 2 listeners in NLB, one for `control plane` at port 12865 and another one for `data plane` at port 1234
      - c5n.xlarge machines were used
      - AZIDs were used (i.e., not AZ names since it will vary account to account)
        to consistently identity physical AZs

    </details>

    | What           | Intra AZ latency (p99)<sup>1</sup> | Inter AZ latency (p99)<sup>2</sup> | Comment            |
    |----------------|------------------------------------|------------------------------------|--------------------|
    | Single VPC     | 85 µs                              | 640 µs                             | Baseline           |
    | Subnet Sharing | 88 µs                              | 550 µs                             | ~= Baseline        |
    | Peering        | 86 µs                              | 595 µs                             | ~= Baseline        |
    | TransitGateway | 463 µs                             | 970 µs                             | ~= 300 µs overhead |
    | PrivateLink    | 654 µs                             | 1215 µs<sup>3</sup>                | ~= 600 µs overhead |

    <sup>1</sup>`use1-az1 <==> use1-az1`
    <sup>2</sup>`use1-az1 <==> use1-az2`
    <sup>3</sup>`[use1-az1 <==> use1-az2] <==> [use1-az2]`

  * AWS network transfer cost for 100TB (~2020 in us-east-1)

    <details>
    <summary>Setup detail</summary>
      </br>

      - us-east-1 region
      - 100TB of data transfer per month (ingress + egress)
      - ALB/NLB: 1000 connections per minute with 120 secs of connection duration
      - 3 AZs
      - Cost: based on [AWS Calculator](https://calculator.aws/)
      - Assumed to have zone aware routing to minimize the Inter-AZ transfer costs

    </details>

    | What               | Monthly Cost       |
    |--------------------|--------------------|
    | VPC Subnet Sharing | $0                 |
    | VPC Peering        | $0 <sup>1</sup>    |
    | VPC PrivateLink    | $1645 <sup>2</sup> |
    | Transit Gateway    | $4127              |

    <sup>1</sup>No additional cost for vpc peering, see [here](https://aws.amazon.com/about-aws/whats-new/2021/05/amazon-vpc-announces-pricing-change-for-vpc-peering/)
    <sup>2</sup>Cost of NLB + Cost of VPC Service Endpoint: `$600 + $1045`

## Connection tracking
  * Linux [conntrack](https://arthurchiao.art/blog/conntrack-design-and-implementation/) may be enabled indirectly under different scenarios (when using some kind of NAT, or iptable-based load balancing, when using Kubernetes ClusterIP service type, etc.). When enabled/used, each connection is tracked using something called conntrack table in the Linux kernel. This table has a limited size (usually calculated based on RAM size), so based on the traffic needs, one may want to adjust the value accordingly to something higher.

  * One should try to avoid conntrack as much as possible if not needed. For example, it is better to use [Kubernetes headless services](https://cloud.google.com/kubernetes-engine/docs/how-to/exposing-apps) than using ClusterIP service, and then use L7 loadbalancing within an app (gRPC, etc.) or a sidecar (Envoy, etc.). This not only avoids multiple hops but also provides significantly better performance when transferring a large amount of data. For example, if we are on AWS EKS, we can use EKS CNI to completely bypass the Kubernetes overlay network and treat pod IPs as first-class VPC routable IPs (which can be exposed over VPC peering, etc).

  * Regardless of our service configuration, we may end up using conntrack in one way or another indirectly (for example, when using Kubernetes DNS service), so it's better to tweak those values accordingly.

  * Memory usage for each entry in that table can be calcuated and the table size can be set
     <details>
      <summary>Example calculation</summary>
        </br>

       ```
       # 320 bytes per connection track entry (4th column)

       $ cat /proc/slabinfo  | grep -i nf_conntrack
       nf_conntrack        4763   7150    320   25    2 : tunables    0    0    0 : slabdata    286    286      0

       # To store 1 million entries, we would need ~305 MB:
       $ echo '(320*1000000)/1024/1024' | bc -l
       305.17578125000000000000
       ```

     </details>

     <details>
      <summary>Example setting the conntrack table size via kube-proxy </summary>
        </br>

       ```
       $ kubectl --namespace=kube-system get configmaps kube-proxy-config -o yaml | sed -i -E 's|(^[ ]+min: )[0-9]+|\11000000|' | kubectl apply -f-
       ```

     </details>

  * Additionally, we may also want to tweak how long to track the timedout tcp connections.

     <details>
      <summary>Tweak conntrack tcp timeout timed wait</summary>
        </br>

       ```
       $ sysctl -a | grep -i nf_conntrack_tcp_timeout_time_wait
       net.netfilter.nf_conntrack_tcp_timeout_time_wait = 120

       # Since TCP itself is waiting for 60s, no need for conntrack to track it for longer than that,
       # we should reduce it to 65 secs or so. This can be done by editing /etc/sysctl.conf
       ```

     </details>

  * Under abnormal circumstances we might end up consuming too many entries in the conntrack table, so better track and alert on those.

     <details>
      <summary>Example Kubernetes manifest to collect conntrack table metrics</summary>
        </br>

       Since conntrack operates at root network namespace, it must be collected via a DaemonSet at node level.

       ```
       apiVersion: apps/v1
       kind: DaemonSet
       ...
       ...
       spec:
         ...
         ...
         template:
           spec:
             containers:
             - args:
               - --web.listen-address=0.0.0.0:9100
               - --path.procfs=/host/proc
               - --path.sysfs=/host/sys
               - --path.rootfs=/host/root
               ...
               ...
               - --collector.conntrack
               ...
               ...
               image: node-exporter
               name: node-exporter
               ...
               ...
               securityContext:
                 readOnlyRootFilesystem: true
               volumeMounts:
               - mountPath: /host/proc
                 name: proc
                 readOnly: false
               - mountPath: /host/sys
                 name: sys
                 readOnly: false
               - mountPath: /host/root
                 mountPropagation: HostToContainer
                 name: root
                 readOnly: true
             hostNetwork: true
             hostPID: true
             nodeSelector:
               kubernetes.io/os: linux
             securityContext:
               runAsNonRoot: true
               runAsUser: 65534
             priorityClassName: high-priority
             tolerations:
             - operator: Exists
             volumes:
             - hostPath:
                 path: /proc
               name: proc
             - hostPath:
                 path: /sys
               name: sys
             - hostPath:
                 path: /
               name: root
             ...
             ...
       ```

     </details>

     <details>
      <summary>Example PromQL queries for alerting on 75% utilization</summary>
        </br>

       ```
       (node_nf_conntrack_entries / node_nf_conntrack_entries_limit) > 0.75
       ```

     </details>


## AWS EC2 network limit considerations

  * In AWS VPC/EC2, regarding network usage, there are some inherent limits, some of which are documented and some are undocumented. There are a few scenarios under which we might hit these limits, so it's important to monitor/alert on them.

  * When we use some kind of container orchestration system (Kubernetes etc) to binpack workload into a single EC2 instance, it is very easy to run into these limits, as one application/pod can consume the entire limit, causing all other workloads in the system to come to a grinding halt. One real-world example in Kubernetes: By default, pods are configured to use CoreDNS (the dns service that's running locally inside K8s cluster), so when our applications perform DNS lookups, the path is "application ==> one_of_the_coredns_pods ==> EC2 link_local resolver". Since only a few CoreDNS pods will be running, most of the DNS queries will end up hitting a few EC2 machines. If we are running a large cluster with hundreds/thousands of apps, it is very easy to exceed the "linklocal" limits (which is 1024 packets per second), as most of the DNS lookups will be clustered on a few EC2 instances where the CoreDNS pods are running.
  * When running a reverse proxy with a high volume of traffic or a lot of long-lived connections (like websockets, etc.), it is possible to reach the security group connection tracking limits, leading to latency spikes/timeouts.
  * When running load test or performance benchmarks, it is important to keep an eye on these limits, as our tests might exceed these limits and introduce latency (due to queued/dropped packets) at the AWS VPC/EC2 level, which we might incorrectly attribute it to our application.
  * Below are a few points to consider:
      * Security groups are stateful, so if an EC2 instance is configured to use a security group in a certain way, there is a limit to number of TCP connections that can be handled on that machine. This limit varies depending on the instance type used (for example, c5.2xlarge will have a higher limit than c5.xlarge, and so on), but the limits are not documented clearly. See [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html) for more information. Once the limit is reached, TCP connection establishment will fail, and we may experience timeouts, etc. Once we reach the limit, there are certain metrics emitted by the ENA driver (more information below), which can be used for alerting.
      * Each instance has a predefined limit on the number of bytes or packets per second (PPS) that can be transferred. Once the limit is reached, packets may be queued or dropped. See here for more information.
      * Each EC2 instance has a local service exposed via a link-local address (169.254.169.254). This is used for getting metadata about the instance, for retrieving instance temporary IAM credentials, for time synchronization etc. The link-local address also has certain limits on the amount of traffic that can be sent to it. If this limit is exceeded, packets will be rate-limited or queued or dropped. So this can lead to various hard to debug issues. It is important to monitor and receive alerts for this (more information below).
      * Each EC2 instance has a certain limit on the number of DNS queries it can perform. As of this writing, it is hard-capped to 1024 packets per second (note that it is packets, not queries) . Depending on DNS protocol transport used (TCP or UDP) and the request/response sizes, the number generated packets can be higher, resulting in a lower number of actual DNS queries that can be performed. For example, if we are using UDP, with a simple A lookup, and a response containing a few IPs, we can perform 512 DNS queries per second (1 for request, 1 for response). When the workload is bin-packed (as in Kubernetes, where hundreds of pods/applications can run on a single EC2 instance), they all share this limit, making it easy to exceed this limit. This should be monitored and alerts should be set up (more information below). DNS lookups should be cached as much as possible (in the application, node-local DNS cache, dnsmasq, etc.).
      * Each EC2 instance has a limit on the number of bytes or packets that can be transferred in a given second. This limit varies depending on the instance type used (for example, c5.2xlarge will have a higher limit than c5.xlarge, and so on). Even within that, "micro-bursts" may not be allowed (for example, transferring 1GB within a few milliseconds may not be possible, even though a given instance allows multiple GBs per second). These micro-bursts will not be visible in most monitoring systems (such as Prometheus, CloudWatch, etc.) as they scrape metrics at higher intervals (10s, 15s, etc.), so the required granularity for detecting them is much lower. There are multiple ways to track these, such as performing a packet capture and analyzing it in Wireshark or similar tools, or running tools like [network-microburst](https://github.com/surki/network-microburst) or writing an eBPF plugin and export the metrics over prometheus using tools like [ebpf_exporter](https://github.com/cloudflare/ebpf_exporter).

  * To monitor these limits, the AWS ENA network driver exposes certain metrics on each EC2 machine (not available in CloudWatch). These metrics must be scraped on each machine and sent to the monitoring system being used, where alerts can be configured.

    The available metrics are (official page is [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/monitoring-network-performance-ena.html)):

    | Metric                          | Description                                                                                                                                                                                                                                    |
    |---------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
    | bw\_in\_allowance\_exceeded     | The number of packets queued or dropped because the inbound aggregate bandwidth exceeded the maximum for the instance                                                                                                                          |
    | bw\_out\_allowance\_exceeded    | The number of packets queued or dropped because the outbound aggregate bandwidth exceeded the maximum for the instance                                                                                                                         |
    | conntrack\_allowance\_available | The number of connections that can be established in an instance                                                                                                                                                                               |
    | conntrack\_allowance\_exceeded  | The number of packets dropped because connection tracking exceeded the maximum for the instance and new connections could not be established. This can result in packet loss for traffic to or from the instance                               |
    | linklocal\_allowance\_exceeded  | The number of packets dropped because the PPS of the traffic to local proxy services exceeded the maximum for the network interface. This impacts traffic to the DNS service, the Instance Metadata Service, and the Amazon Time Sync Service. |
    | pps\_allowance\_exceeded        | The number of packets queued or dropped because the bidirectional PPS exceeded the maximum for the instance                                                                                                                                    |
  * Collect/alert on the metrics, it will vary based on the metrics system being used, here is an Kubernetes/Prometheus based example
     <details>
      <summary>Example Kubernetes manifest to collect the metrics</summary>
        </br>

       ```
       apiVersion: apps/v1
       kind: DaemonSet
       ...
       ...
       spec:
         ...
         ...
         template:
           spec:
             containers:
             - args:
               - --web.listen-address=0.0.0.0:9100
               - --path.procfs=/host/proc
               - --path.sysfs=/host/sys
               - --path.rootfs=/host/root
               ...
               ...
               - --collector.ethtool
               - --collector.ethtool.metrics-include=^(ena_.*|.*_exceeded)$ # AWS ENA metrics
               ...
               ...
               image: node-exporter
               name: node-exporter
               ...
               ...
               securityContext:
                 readOnlyRootFilesystem: true
               volumeMounts:
               - mountPath: /host/proc
                 name: proc
                 readOnly: false
               - mountPath: /host/sys
                 name: sys
                 readOnly: false
               - mountPath: /host/root
                 mountPropagation: HostToContainer
                 name: root
                 readOnly: true
             hostNetwork: true
             hostPID: true
             nodeSelector:
               kubernetes.io/os: linux
             securityContext:
               runAsNonRoot: true
               runAsUser: 65534
             priorityClassName: high-priority
             tolerations:
             - operator: Exists
             volumes:
             - hostPath:
                 path: /proc
               name: proc
             - hostPath:
                 path: /sys
               name: sys
             - hostPath:
                 path: /
               name: root
             ...
             ...
       ```

     </details>

     <details>
      <summary>Example PromQL queries for alerting</summary>
        </br>

       ```
       sum(rate(node_ethtool_conntrack_allowance_exceeded[5m])) by (node,device,region) > 0
       sum(rate(node_ethtool_pps_allowance_exceeded[5m])) by (node,device,region) > 0.5
       sum(rate(node_ethtool_linklocal_allowance_exceeded[5m])) by (node,device,region) > 6
       sum(rate(node_ethtool_bw_in_allowance_exceeded[5m])) by (node,device,region) > 0
       ```

     </details>


## AWS linklocal limits

   * AWS linklocal endpoint (aka `169.254.169.254`) has certain throughput limits: 1024 pps. This is used for DNS lookups as well as for other instance metadata retrievals. In a setup like Kubernetes, it is trivial to hit that limit as it is shared among all the pods in that node. Best practice is to cache DNS lookups and maintain long lived EC2 client objects (so don't have to hit the instance metadata for every http request) in the application.
   * Please see the above section [AWS EC2 network limit considerations](#aws_ec2_network_limit_considerations) on how to monitor/get alerted for this

## AWS Security Group and connection tracking
  * AWS security groups are stateful. Internally it uses some sort of connection tracking to track connections and allow outbound traffic automatically for the connections accepted via inboud traffic. As to how many connections an EC2 can handle depends on the size of that connection tracking table. That size varies by instance type and is not documented. One must closely monitor *conntrack_allowance_exceeded* metric to get notified of this, please see [AWS EC2 network limit considerations](#aws_ec2_network_limit_considerations) for more information.
  * If the service is expected to handle high number of long lived connections (websocket etc), it may be better to setup security group rules in such a way that connections are not tracked, please see [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-connection-tracking.html) for how to do that.

    > If a security group rule permits TCP or UDP flows for all traffic (0.0.0.0/0 or ::/0) and there is a corresponding rule in the other direction that permits all response traffic (0.0.0.0/0 or ::/0) for all ports (0-65535), then that flow of traffic is not tracked

  * One may consider using AWS Network ACLs instead of SG if it meets all the requirements

## NAT connection tracking
   * When talking to services hosted in Internet, typically we may go through a NAT device. Depending on the NAT being used, it will *forget* the connection if its idle for too long. For example, AWS NAT has a timeout of [350s](https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-troubleshooting.html#nat-gateway-troubleshooting-timeout) after which it will forget the connection. And post that, if we try to send packet on that connection, we will get a RST.
   * One way to keep the connections alive in NAT is to enable TCP keepalives
       * If the proxy/application supports TCP keepalive configuration, one can configure it (example [envoy configuration](https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/protocol.proto#envoy-v3-api-msg-config-core-v3-keepalivesettings))
       * If the proxy/application doesn't support, we might want to use LD_PRELOAD and use something like [libsetsockopt](https://github.com/surki/libsetsockopt) to enable that transparently
   * In addition to that, relevant metrics must be monitored as well. In case of AWS NAT, it is [IdleTimeoutCount](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-nat-gateway-cloudwatch.html)

## AWS NLB and connections
   * A service may be deployed behind an AWS NLB and exposed to clients (internal or external) over that.
   * Since AWS NLB doesn't operate at L7 (i.e., there is no *separate* TCP connection between two ends like ALB), it internally keeps track of TCP (or UDP) connections to maintain the flow correctly. This is remembered for [350s](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html#connection-idle-timeout) as of this writing, after which idle connections will be forgotton (and any further attempt to communicate over that will result in TCP RST from the NLB).
       * To fix this, one must enable TCP keep-alives on the application listener socket (and as well as on the client side, which we might not have control over).
           * If the proxy/application supports TCP keepalive configuration, one can configure it.

             <details>
              <summary>Example envoy configuration to enable TCP keepalive on listening socket</summary>
                </br>

               ```
               static_resources:
                 listeners:
                 - name: "my_listener"
                   address:
                     socket_address:
                       protocol: TCP
                       address: 0.0.0.0
                       port_value: 80
                   ...
                   ...
                   # These values are tuned for NLB timeouts
                   socket_options:
                   - description: "setsockopt(x, SOL_SOCKET, SO_KEEPALIVE, [1])"
                     level: 1
                     name: 9
                     int_value: 1
                     state: STATE_LISTENING
                   - description: "setsockopt(x, SOL_TCP, TCP_KEEPIDLE, [300])"
                     level: 6
                     name: 4
                     int_value: 300
                     state: STATE_LISTENING
                   - description: "setsockopt(fd, SOL_TCP, TCP_KEEPINTL, [5])"
                     level: 6
                     name: 5
                     int_value: 5
                     state: STATE_LISTENING
                   - description: "setsockopt(fd, SOL_TCP, TCP_KEEPCNT, [5])"
                     level: 6
                     name: 6
                     int_value: 5
                     state: STATE_LISTENING
                   ...
                   ...
               ```

             </details>

           * If the proxy/application doesn't support, we might want to use LD_PRELOAD and use something like [libsetsockopt](https://github.com/surki/libsetsockopt) to enable that transparently
       * Remember to add alert for `TCP_ELB_Reset_Count` [metric](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-cloudwatch-metrics.html) to keep an eye for these errors

   * NLB operates at lower lower level than L7, which means in a steady state with long lived connections, traffic distribution may be uneven, and in fact some instances may not get any traffic at all!. For example, assume that NLB is deployed in a private network with both the clients and servers within a private environment (say, clients are in one VPC, and NLB + targets are in another VPC, connected over privatelink/vpc peering) using http2 or gRPC L7 protocol: in that setup, if a new instance is booted (manually or via autoscaling), register that instance to NLB's target group, it won't receive any traffic at all until there is a deployment or restart in client side since all the services/apps use long lived persistence connections. To fix this, we must continue to periodically gracefully recycle the TCP connections. This could be on the time spent or on the number of requests served etc, depending on the application or proxy behind the NLB.

     If we are using Envoy, we may want to set `max_connection_duration` or `max_requests_per_connection`, see [here](https://www.envoyproxy.io/docs/envoy/v1.23.1/api-v3/config/core/v3/protocol.proto.html#config-core-v3-httpprotocoloptions) to gracefully recycle connections periodically.

   * NLB can mix up connections if cross-zone loadbalancing is enabled, see [here](https://www.niels-ole.com/cloud/aws/linux/2020/10/18/nlb-resets.html) for more information. Either run with cross-zone loadbalancing disabled or disable *Client IP preservation* feature and use proxy protocol to get the client IP address.

   * Graceful shutdown: when targets are shutdown (during deployment etc), target must participate and gracefully close the long-lived connections (by sending http1.1 *Connect: Close* and/or http2 *GO_AWAY* frame), see [Graceful deployments](#graceful_deployments) for more detail.

## AWS ALB and Global Accelerator (GAC)

When using ALB along with GAC, 100% traffic must go to GAC. In a mixed setup, where some part of traffic goes to GAC and other part directly goes to ALB, the connections can be mixed up (since GAC does client ip preservation).

An example:

  * Assume the the following IPs:
     ```
     client NAT : 1.1.1.1
     GAC        : 2.2.2.2
     App-ALB    : 3.3.3.3
     ```
  * Now, say, App is making an API request to foo.myapp.com  (and it is pointed to GAC), the connection would look like this (assuming 15154 is the random ephemeral src port chosen by NAT)
    ```
    From client NAT point of view (connected to GAC) :  1.1.1.1:15154 <====> 2.2.2.2:443
    Same connection from App-ALB perspective         :  1.1.1.1:15154 <====> 3.3.3.3:443
    ```
  * Now, say, at the same time, client is making another API request to bar.myapp.com (and it is pointed to ALB directly), the connection would look like this (again, since it is conneting to IP 3.3.3.3 , port 15154 is available for NAT to choose randomly, and it could/would under high traffic):

    ```
    From client NAT point of view (conneteced to App-ALB) : 1.1.1.1:15154 <====> 3.3.3.3:443
    Same connection from App-ALB perspective              : 1.1.1.1:15154 <====> 3.3.3.3:443
    ```
  * Now both the connections from App-ALB's perspective, the kernel cannot differentiate packets between these two separate connections, it would mix it up/drop/rst (seq num mismatching) etc

## Graceful deployments
  * For a typical setup like `|customers| ==> |cloud load balancer| ==> |my service|`, there are going to deployments quite often for the *my service*. It is important to not return any 5xx during deployments. How one does that depends on the infra, but we will focus on Kubernetes here.
  * When a pod is going to be terminated, something like this happens (some are run in parallel to each other)
      * Pod status changed to terminating state
      * Pod is removed from service endpoints
      * Pod/application is sent SIGTERM signal, application is expected to handle that gracefully, close the long lived http1.1, websocket etc connections and then exit
          * Note that if the application is not PID 1 in the pod, whatever is the PID 1 should forward the signal to the application. One may want to use some init system like [this](https://github.com/Yelp/dumb-init)
          * If the application cannot handle SIGTERM for some reason, then a prestop hook can be used
  * It is generally recommended to have a "prestop" hook that just sleeps for sometime to gracefully handle all of the above scenarios (which are run parallel so there can be race conditions)
  * Please see [this](https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-terminating-with-grace) for more detail


## AWS EBS
  * Almost all the newer EC2 instances come with EBS root volume, which means OS runs out of network volume
  * EBS volumes have fixed IOPS, which can be a problem under certain conditions
      * When OS runs low on memory, it may start paging out things more aggressively. Remember that even though swap is not enabled, pages marked as read only can be paged out anytime (since kernel knows that it can be brought back from underlying disk anytime). And most of the OS/system services are typically mapped read-only and executed. So they are eligible to be paged out. Under low memory conditions it is possible that system will continuously page out and page in these
      * This can lead to high read IOPS, reaching the EBS volume IOPS limit, which eventually will eat into burst balance (if available)
      * This will eventually lead to complete system freeze as system will be too busy thrashing pages in and out
  * EBS volumes must be closely monitored and alerted, especially BurstBalance etc
  * We should also factor this carefully in shared systems like Kubernetes, where single root volume is shared among all the pods in that machine, where a single pod doing high IOPS (into host or overlay volume which is backed by root volume) can drastically affect everybody else.
  * We may also want to consider separating out root volume and data volume (app operates on this) for data intensive apps/services. Or use data volume out of ephemeral storage.

## Kubernetes blast radius
  * Kubernetes operates on a shared infrastructure with limited isolation capabilities, primarily we can isolate on cpu and memory. But then there are other system as well as underlying cloud infrastructure usage that are not isolated, which can lead to one pod affecting everybody else in that machine/node
  * In AWS, each machine has certain limits, depends on the instance type.
      *  How much data can be transferred, both in terms of bytes and as well packets per second limit [AWS EC2 network limit considerations](#aws_ec2_network_limit_considerations). So, for example, one pod doing too many small packet transfers can affect every pod in that node.
      *  Root EBS volume IOPS, see [AWS EBS](#aws_ebs). So, for example, one pod doing too many small reads can affect every pod in that node.
      *  How many TCP connections can be opened, see [AWS Security Group and connection tracking](#aws_security_group_and_connection_tracking).
      *  How many DNS lookups/instance metadata calls can be made, see [AWS linklocal limits](aws_linklocal_limits). So one pod doing too many dns lookups or metadata calls can affect every pod in that node.
      * Its important to monitor for these issues, and make sure we isolate the problmatic workloads as soon as possible.

## Kubernetes tuning
  * Make sure to apply the necessary sysctl tunings at appropriate place. Some may require changes in system level root namespace and some could be within the pod namespace
  * Make sure appropriate ulimits values are set, again this might require changes in underlying node/container runtime as well
  * Optimize DNS lookups, probably configure ndot and autopath values to minimize the DNS lookups
  * If in AWS EKS
      * Use AWS provided EKS CNI
      * Make sure to set `AWS_VPC_K8S_CNI_EXTERNALSNAT=true` to avoid unnecessary NAT ops and as well for the pods to be reachable from VPC peered accounts
      * Make sure to monitor the ENI and EIP availability in the VPC, this could lead to scheduling failures.
      *
  * Try to use Kubernetes headless services and then rely on L7 proxy for proper load distribution
  * Consider configuring pod disruption budget
  * May want to run [node-problem-detector](https://github.com/kubernetes/node-problem-detector)
  * May want to use [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/) for enforcing security policies
  * Please check https://aws.github.io/aws-eks-best-practices/reliability/docs/dataplane/
  * May want to use [topology spread constraints](https://kubernetes.io/docs/concepts/scheduling-eviction/topology-spread-constraints/) to spread the workload across multiple zones for HA

    <details>
     <summary>Example deployment configuration to distribute the pods evenly across zones and hosts</summary>
       </br>

      ```
      apiVersion: apps/v1
      kind: Deployment
      metadata:
        labels:
          app: foo
        name: foo
      spec:
        ...
        ...
        selector:
          matchLabels:
            app: foo
        ...
        ...
        template:
          metadata:
            labels:
              app: foo
          spec:
            ...
            ...
            topologySpreadConstraints:
              - maxSkew: 1
                topologyKey: topology.kubernetes.io/zone
                whenUnsatisfiable: ScheduleAnyway
                labelSelector:
                  matchLabels:
                    app: foo
              - maxSkew: 1
                topologyKey: kubernetes.io/hostname
                whenUnsatisfiable: DoNotSchedule
                labelSelector:
                  matchLabels:
                    app: foo
            ...
            ...
      ```

    </details>

  * Configure the the default ulimits for the pods (which is low by default), specifically nofiles (aka "open files"). This likely requires a "default-ulimits" field change in the /etc/docker/daemon.json (or in the right place for any other CRI being used)

  * Configure topologySpreadConstraints to distribute the workload across multiple AZs

## Kubernetes and statefulsets

   TODO

## TCP close bidirectional

   TODO talk about `TCP_USER_TIMEOUT`, `TCP_KEEPALIVE_TIME`  etc
   TODO Talk about gRPC timeouts and how they interact with TCP timeouts

## Network Error Reporting (NEL)

   TODO talk about NEL and how to configure/use
