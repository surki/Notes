# FAQs

Table of Contents
=================

   * [FAQs](#faqs)
      * [How do I strace, gdb attach etc to a process running in my pod?](#how-do-i-strace-gdb-attach-etc-to-a-process-running-in-my-pod)
      * [My pod is getting restarted continuously, I want to check some (config, logs) files stored in emptydir, how do I do that?](#my-pod-is-getting-restarted-continuously-i-want-to-check-some-config-logs-files-stored-in-emptydir-how-do-i-do-that)
      * [How do I "join" namespace of my container and explore various things?](#how-do-i-join-namespace-of-my-container-and-explore-various-things)
      * [How do I get list of pods that had some container restarts?](#how-do-I-get-list-of-pods-that-had-some-container-restarts)
      * [How do I check if my pods are evenly distributed across AZs?](#how-do-i-check-if-my-pods-are-evenly-distributed-across-azs)
      * [How do I scale deployments matching certain criteria?](#how-do-I-scale-deployments-matching-certain-criteria)
      * [How to increase memory limit of a container on the fly?](#how-to-increase-memory-limit-of-a-container-on-the-fly)
      * [How do I operate on nodes in a given availability zone?](#how-do-I-operate-on-nodes-in-a-given-availability-zone)
      * [List IP address usage by instance for given subnets?](#list-ip-address-usage-by-instance-for-given-subnets)

## How do I strace, gdb attach etc to a process running in my pod?

There are couple of ways to do, for now, we will show how to do it from
underlying node (aka "hard way"). Later we will show to do that using a
"debug" container (right from the `kubectl` interface).

SSH into the node where our pod is running

```console
# Find the node where our pod is running and ssh into the node
[sureshponnusamy@eks-bastion-2 ~]$ kubectl get pods --namespace myapp myapp-blue-db4877d8f-7mrt9 -o json | jq '.metadata.uid, .spec.nodeName'
"70f954d7-219e-11ea-bda2-120816c3fa33"
"ip-172-16-128-108.ec2.internal"

[sureshponnusamy@eks-bastion-2 ~]$ ssh ip-172-16-128-108.ec2.internal
Last login: Thu Dec 19 07:49:54 2019 from ip-172-16-4-42.ec2.internal

       __|  __|_  )
       _|  (     /   Amazon Linux 2 AMI
      ___|\___|___|

[sureshponnusamy@ip-172-16-128-108 ~]$
```

Find the corresponding container we want to debug

```console
# Assuming we want to debug "metrics-shipper" container within our pod
[sureshponnusamy@ip-172-16-128-108 ~]$ docker ps | grep myapp-blue-db4877d8f-7mrt9 | grep metrics
bea2e757294b        5e45cbd9e779     "/usr/local/bin/dumb…"    18 hours ago  Up 18 hours   k8s_metrics-shipper_myapp-blue-db4877d8f-7mrt9_myapp_70f954d7-219e-11ea-bda2-120816c3fa33_0
```

Get pid and strace it

```console
[sureshponnusamy@ip-172-16-128-108 ~]$ docker inspect bea2e757294b | grep Pid
            "Pid": 8624,
            "PidMode": "",
            "PidsLimit": 0,
[sureshponnusamy@ip-172-16-128-108 ~]$ pstree -p 8624 | head
dumb-init(8624)---telegraf(8670)-+-{telegraf}(10157)
                                 |-{telegraf}(10158)
                                 |-{telegraf}(10159)
                                 |-{telegraf}(10160)
                                 |-{telegraf}(10161)
                                 |-{telegraf}(10162)
                                 |-{telegraf}(10163)
                                 |-{telegraf}(10170)
                                 |-{telegraf}(10171)
                                 |-{telegraf}(10172)


[sureshponnusamy@ip-172-16-128-108 ~]$ sudo strace -ff -e recvfrom -p 8670
strace: Process 8670 attached with 57 threads
[pid 24752] recvfrom(3, "envoy.cluster.upstream_rq_time:1"..., 65536, 0, {sa_family=AF_INET6, sin6_port=htons(60513), inet_pton(AF_INET6, "::ffff:172.16.128.131", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [112->28]) = 72
[pid 24752] recvfrom(3, "envoy.cluster.external.upstream_"..., 65536, 0, {sa_family=AF_INET6, sin6_port=htons(60513), inet_pton(AF_INET6, "::ffff:172.16.128.131", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [112->28]) = 81
[pid 24752] recvfrom(3, "envoy.http.downstream_rq_time:1|"..., 65536, 0, {sa_family=AF_INET6, sin6_port=htons(60513), inet_pton(AF_INET6, "::ffff:172.16.128.131", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [112->28]) = 79
[pid 24752] recvfrom(3, "envoy.listener.downstream_cx_len"..., 65536, 0, {sa_family=AF_INET6, sin6_port=htons(60513), inet_pton(AF_INET6, "::ffff:172.16.128.131", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, [112->28]) = 78
[pid 24752] recvfrom(3, "envoy.http.downstream_cx_length_"..., 65536, 0, {sa_family=AF_INET6, sin6_port=htons(60513), inet_pton(AF_INET6, "::ffff:172.16.128.131", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_i

```

## My pod is getting restarted continuously, I want to check some (config, logs) files stored in emptydir, how do I do that?

SSH into the node where pod is running (see above question for how to do that)

Get UID of the pod (UID is in container name)

```console
# Assuming we want to see "myapp-blue-db4877d8f-7mrt9" pod
[sureshponnusamy@ip-172-16-128-108 ~]$ docker ps --format '{{.Names}}' | grep myapp-blue-db4877d8f-7mrt9 | head -1
k8s_confd_myapp-blue-db4877d8f-7mrt9_myapp_70f954d7-219e-11ea-bda2-120816c3fa33_0
```

List all emptydir volumes for this pod

```console
[sureshponnusamy@ip-172-16-128-108 ~]$ ls -l /var/lib/kubelet/pods/70f954d7-219e-11ea-bda2-120816c3fa33/volumes/kubernetes.io~empty-dir/
total 12
drwxrwxrwx 2 root root   39 Dec 19 08:22 data-haystack-shipper-data
drwxrwxrwx 3 root root   21 Dec 18 13:58 data-myapp-current-public-assets-cdn-ignored
drwxrwxrwx 2 3130 3130    6 Dec 18 13:58 data-myapp-current-sass-cache
drwxrwxrwx 5 3130 3130 4096 Dec 18 13:58 data-myapp-shared-config
drwxrwxrwx 2 3130 3130 4096 Dec 19 08:00 data-myapp-shared-log
drwxrwxrwx 2 3130 3130    6 Dec 18 13:58 data-myapp-shared-pids
drwxrwxrwx 2 3130 3130    6 Dec 18 13:58 data-myapp-shared-system
drwxrwxrwx 3 3130 3130   31 Dec 18 14:00 data-myapp-shared-tmp
drwxrwxrwx 2 root root    6 Dec 18 13:58 data-var-log-myapp
drwxrwxrwx 5 3130 3130   40 Dec 18 13:58 dynamic-data
drwxrwxrwx 2 root root   25 Dec 18 13:58 etc-envoy
drwxrwxrwx 2 root root   47 Dec 18 13:58 etc-fd-telegraf
drwxrwxrwx 2 root root   33 Dec 18 13:58 etc-haystack-shipper
drwxrwxrwx 2 root root    6 Dec 18 13:58 etc-monitd-bg
drwxrwxrwx 2 root root    6 Dec 18 13:58 etc-proxysql
drwxrwxrwx 3 root root  145 Dec 18 13:58 etc-sumocollector
drwxrwxrwt 2 root root   60 Dec 18 13:58 home-deploy-ssh
drwxrwxrwx 2 root root  105 Dec 18 13:58 opt-logrotate
drwxrwxrwx 3 root root  287 Dec 19 08:23 opt-sumocollector-config-blades
drwxrwxrwx 2 root root  154 Dec 18 13:58 opt-sumocollector-logs
drwxrwxrwx 2 root root    6 Dec 18 13:58 usr-local-bin-bg
drwxrwxrwx 2 root root   57 Dec 19 08:20 var-lib-logrotate
drwxrwxrwt 2 root root   40 Dec 18 13:58 var-lib-monit
drwxrwxrwx 7 3130 3130   78 Dec 18 13:58 var-lib-nginx-tmp
drwxrwxrwt 2 root root   40 Dec 18 13:58 var-lock
drwxrwxrwx 4 root root   36 Dec 18 13:58 var-log
drwxrwxrwx 2 root root   30 Dec 18 13:58 var-log-envoy
drwxrwxrwx 2 root root   19 Dec 18 14:15 var-log-logrotate
drwxrwxrwx 2 3130 3130   74 Dec 18 13:58 var-log-nginx
drwxrwxrwt 3 root root   80 Dec 18 13:58 var-run
```

Read a file from one of the emptydir volume

```console
# Say, we want to check envoy config
[sureshponnusamy@ip-172-16-128-108 ~]$ head /var/lib/kubelet/pods/70f954d7-219e-11ea-bda2-120816c3fa33/volumes/kubernetes.io~empty-dir/etc-envoy/static.yaml
admin:
  access_log_path: "/var/log/envoy/admin_access.log"
  address:
    socket_address: { address: "0.0.0.0", port_value: "9901" }

static_resources:
  listeners:
    - name: static_listener
      address:
        socket_address: { address: "0.0.0.0", port_value: "81"  }
        
```

## How do I "join" namespace of my container and explore various things?

SSH into the node where pod is running (see above question for how to do that)

```console
# Assuming we want to explore "myapp-blue-db4877d8f-7mrt9" pod and "envoy" container within it
[sureshponnusamy@ip-172-16-128-108 ~]$ docker ps | grep myapp-blue-db4877d8f-7mrt9 | grep envoy
cc31dbabb800        3a6d326c2346                                                       "/usr/local/bin/dumb…"    19 hours ago        Up 19 hours                             k8s_envoy_myapp-blue-db4877d8f-7mrt9_myapp_70f954d7-219e-11ea-bda2-120816c3fa33_0
```

Get pid of the container

```console
[sureshponnusamy@ip-172-16-128-108 ~]$ docker inspect cc31dbabb800 | grep -w Pid
            "Pid": 7801,
```

List all namespaces for this PID

```console
[sureshponnusamy@ip-172-16-128-108 ~]$ lsns -p 7801
        NS TYPE   NPROCS   PID USER COMMAND
4026531835 cgroup   1091     1 root /usr/lib/systemd/systemd --switched-root --system --deserialize 21
4026531837 user     1091     1 root /usr/lib/systemd/systemd --switched-root --system --deserialize 21
4026532327 ipc        45  7384 root /pause
4026532330 net        45  7384 root /pause
4026532409 mnt         2  7801 root /usr/local/bin/dumb-init -- /usr/local/bin/envoy-entry.sh
4026532410 uts         2  7801 root /usr/local/bin/dumb-init -- /usr/local/bin/envoy-entry.sh
4026532411 pid         2  7801 root /usr/local/bin/dumb-init -- /usr/local/bin/envoy-entry.sh
```

Join network namespace of this process and explore (remember that network
namespace is shared between all containers in a given pod, so we will see
all other containers network activity as well)

```console
[sureshponnusamy@ip-172-16-128-108 ~]$ sudo nsenter --net -t 7801

[root@ip-172-16-128-108 ~]$ ss -ltp
State                      Recv-Q                      Send-Q                                            Local Address:Port                                                  Peer Address:Port                      
LISTEN                     0                           128                                                     0.0.0.0:42691                                                      0.0.0.0:*                          users:(("ruby",pid=41746,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:46245                                                      0.0.0.0:*                          users:(("ruby",pid=42608,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:34661                                                      0.0.0.0:*                          users:(("ruby",pid=42011,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:39781                                                      0.0.0.0:*                          users:(("ruby",pid=41363,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:45705                                                      0.0.0.0:*                          users:(("ruby",pid=41460,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:9901                                                       0.0.0.0:*                          users:(("envoy",pid=7862,fd=13))
LISTEN                     0                           128                                                     0.0.0.0:37679                                                      0.0.0.0:*                          users:(("ruby",pid=41557,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:38383                                                      0.0.0.0:*                          users:(("ruby",pid=41043,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:6032                                                       0.0.0.0:*                          users:(("proxysql",pid=9009,fd=28))
LISTEN                     0                           128                                                     0.0.0.0:41905                                                      0.0.0.0:*                          users:(("ruby",pid=41263,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:6033                                                       0.0.0.0:*                          users:(("proxysql",pid=9009,fd=25))
LISTEN                     0                           128                                                     0.0.0.0:6033                                                       0.0.0.0:*                          users:(("proxysql",pid=9009,fd=24))
LISTEN                     0                           128                                                     0.0.0.0:6033                                                       0.0.0.0:*                          users:(("proxysql",pid=9009,fd=23))
LISTEN                     0                           128                                                     0.0.0.0:6033                                                       0.0.0.0:*                          users:(("proxysql",pid=9009,fd=22))
LISTEN                     0                           128                                                     0.0.0.0:81                                                         0.0.0.0:*                          users:(("envoy",pid=7862,fd=207))
LISTEN                     0                           128                                                     0.0.0.0:9394                                                       0.0.0.0:*                          users:(("ruby",pid=9173,fd=8))
LISTEN                     0                           128                                                     0.0.0.0:40147                                                      0.0.0.0:*                          users:(("ruby",pid=42323,fd=21))
LISTEN                     0                           128                                                     0.0.0.0:intermapper                                                0.0.0.0:*                          users:(("nginx",pid=13581,fd=7),("nginx",pid=13575,fd=7),("nginx",pid=13571,fd=7),("nginx",pid=13570,fd=7),("nginx",pid=13565,fd=7),("nginx",pid=13559,fd=7),("nginx",pid=13556,fd=7),("nginx",pid=13555,fd=7),("nginx",pid=13551,fd=7),("nginx",pid=13524,fd=7),("nginx",pid=13520,fd=7),("nginx",pid=13514,fd=7),("nginx",pid=7713,fd=7))
LISTEN                     0                           128                                                     0.0.0.0:mit-dov                                                    0.0.0.0:*                          users:(("nginx",pid=13581,fd=8),("nginx",pid=13575,fd=8),("nginx",pid=13571,fd=8),("nginx",pid=13570,fd=8),("nginx",pid=13565,fd=8),("nginx",pid=13559,fd=8),("nginx",pid=13556,fd=8),("nginx",pid=13555,fd=8),("nginx",pid=13551,fd=8),("nginx",pid=13524,fd=8),("nginx",pid=13520,fd=8),("nginx",pid=13514,fd=8),("nginx",pid=7713,fd=8))
LISTEN                     0                           1                                                     127.0.0.1:32000                                                      0.0.0.0:*                          users:(("java",pid=10135,fd=4))
LISTEN                     0                           128                                                        [::]:9394                                                          [::]:*                          users:(("ruby",pid=9173,fd=9))
LISTEN                     0                           128                                                           *:42004                                                            *:*                          users:(("proxysql_export",pid=9353,fd=3))
```


Join all namespaces of this process and explore

```console
[sureshponnusamy@ip-172-16-128-108 ~]$ sudo nsenter --all -t 7801
root@myapp-blue-db4877d8f-7mrt9:/#
```

## How do I get list of pods that had some container restarts?

```console
# Assuming we want to get all pods in "myapp" namespace that had restarts
[production sureshponnusamy@eks-bastion-2 ~]$ kubectl get pods --namespace myapp  -o json | jq -r ' .items[] | select (.status.containerStatuses[].restartCount > 0) | [.metadata.name, .status.containerStatuses[].name, .status.containerStatuses[].restartCount] | @csv'
"myapp-blue-9c85dc84c-89kxc","app","confd","envoy","haystack","logrotate","metrics-shipper","prometheus","proxysql","sumologic",0,0,0,0,0,0,0,2,0
"myapp-blue-9c85dc84c-chnz5","app","confd","envoy","haystack","logrotate","metrics-shipper","prometheus","proxysql","sumologic",0,0,0,0,0,0,0,2,0
"myapp-green-77b54c7bd4-5nqwf","app","confd","envoy","haystack","logrotate","metrics-shipper","prometheus","proxysql","sumologic",0,0,0,0,0,0,0,2,0
```

## How do I check if my pods are evenly distributed across AZs?

```console
# Assuming our pod(s) of interest has "app=busybox" label
[sureshponnusamy@eksbastion-2 ~]$ awk 'NR==FNR{split($0,a," "); node[a[1]]=a[2]; next}{print(node[$0])}' <(kubectl get nodes -o json | jq -r '.items[] | .metadata.name + " " + .metadata.labels."failure-domain.beta.kubernetes.io/zone"') <(kubectl get pods --all-namespaces --selector=foo=bar,layer=myapp -o json | jq -r '.items[] | .spec.nodeName') | sort | uniq -c | sort -n
     50 us-east-1b
     50 us-east-1d
```

## How do I scale deployments matching certain criteria?

```console
kubectl scale --replicas=1 deployment --namespace=fd-staging --selector shell=stagingvpc-shell-main-green --selector 'approle in (sidekiq, resque, shoryuken, rakes)'
```

## How to increase memory limit of a container on the fly?

This changes cgroup limits directly without going through a deployment.

```console
# Assuming we want to increase memory limit of all logrotate containers in all pods in a node, ssh into the node and run this command, Replace memory limit value accordingly. This is in bytes.

docker ps | grep "logrotate" | awk '{print $1}' | xargs -n1 -I {} docker inspect {} | grep -w Pid  | awk -F "[:,]" '{print $2}' | xargs -i -n1 ps -o cgroup {} | awk -F ',' '{for(i=1;i<NF;i++){if ($i ~ /memory/) { split($i,a,":"); print a[3]; } }}' | xargs -n1 -I {} bash -c 'echo "Modifying /sys/fs/cgroup/memory/{}/memory.limit_in_bytes"; echo 2147483648 > /sys/fs/cgroup/memory/{}/memory.memsw.limit_in_bytes; echo 2147483648 > /sys/fs/cgroup/memory/{}/memory.limit_in_bytes;'
```

## How do I operate on nodes in a given availability zone?

Note that below commands work on currently running nodes. If you don't want
any new nodes being booted in a given AZ, adjust the corresponding ASG and
then run below commands.

To make nodes in `us-east-1a` as unavailable for scheduling:

```console
# Note the "--dry-run" flag, remove it if you really want to run
$ kubectl cordon --dry-run --selector="failure-domain.beta.kubernetes.io/zone=us-east-1a"
node/ip-172-16-114-246.ec2.internal cordoned (dry run)
node/ip-172-16-114-39.ec2.internal cordoned (dry run)
node/ip-172-16-114-68.ec2.internal cordoned (dry run)
node/ip-172-16-117-117.ec2.internal cordoned (dry run)
node/ip-172-16-117-167.ec2.internal cordoned (dry run)
node/ip-172-16-114-246.ec2.internal drained (dry run)
node/ip-172-16-114-39.ec2.internal drained (dry run)
node/ip-172-16-114-68.ec2.internal drained (dry run)
node/ip-172-16-117-117.ec2.internal drained (dry run)
node/ip-172-16-117-167.ec2.internal drained (dry run)
```

To drain workload in nodes running in `us-east-1a`:
```console
# Note the "--dry-run" flag, remove it if you really want to run
$ kubectl drain --dry-run --selector="failure-domain.beta.kubernetes.io/zone=us-east-1a"
node/ip-172-16-114-246.ec2.internal cordoned (dry run)
node/ip-172-16-114-39.ec2.internal cordoned (dry run)
node/ip-172-16-114-68.ec2.internal cordoned (dry run)
node/ip-172-16-117-117.ec2.internal cordoned (dry run)
node/ip-172-16-117-167.ec2.internal cordoned (dry run)
node/ip-172-16-114-246.ec2.internal drained (dry run)
node/ip-172-16-114-39.ec2.internal drained (dry run)
node/ip-172-16-114-68.ec2.internal drained (dry run)
node/ip-172-16-117-117.ec2.internal drained (dry run)
node/ip-172-16-117-167.ec2.internal drained (dry run)
```

## List IP address usage by instance for given subnets?

```console
$ aws ec2 describe-instances --filter "Name=network-interface.subnet-id,Values=subnet-03504c00c2f8950c0" | jq -r '.Reservations | .[] | .Instances | .[] | .InstanceId' | xargs -I{} -n1 bash -c "echo {} ; aws ec2 describe-instances --instance-ids {} | jq '.Reservations | .[] | .Instances | .[] | .NetworkInterfaces | .[] | .PrivateIpAddresses | .[] | .PrivateIpAddress' | wc -l"
```
