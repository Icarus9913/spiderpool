# Annotations

Spiderpool provides annotations for configuring custom ippools and routes.

## Application annotations

Once you set up SpiderSubnet feature, you can specify SpiderSubnet annotations for the application templates.
For more details, please refer to [SpiderSubnet](../usage/spider-subnet.md)

Notice: The current version only supports to use one SpiderSubnet V4/V6 CR for one interface, you shouldn't specify 2 or more SpiderSubnet V4 CRs,
and it will choose the first one to use.

### ipam.spidernet.io/subnets

Here's an example for multiple interfaces to use SpiderSubnet.

```yaml
ipam.spidernet.io/subnets: |-
  [{"interface": "eth0", "ipv4": ["subnet-demo-v4-1"], "ipv6": ["subnet-demo-v6-1"]},
   {"interface": "net2", "ipv4": ["subnet-demo-v4-2"], "ipv6": ["subnet-demo-v6-2"]}]
```

### ipam.spidernet.io/subnet

This is used for SpiderSubnet with single interface.

```yaml
ipam.spidernet.io/subnet: '{"ipv4": ["subnet-demo-v4"], "ipv6": ["subnet-demo-v6"]}'
```

## Pod annotations

For a pod, you can specify Spiderpool annotations for a special request.

### ipam.spidernet.io/ippool-ip-number

This annotation is used with [SpiderSubnet](../usage/spider-subnet.md) feature enabled.
It specifies the IP numbers of the corresponding SpiderIPPool (fixed and flexible mode, optional and default '+1').

```yaml
ipam.spidernet.io/ippool-ip-number: +1
```

### ipam.spidernet.io/ippool-reclaim

This annotation is used with [SpiderSubnet](../usage/spider-subnet.md) feature enabled.
It specifies the corresponding SpiderIPPool to delete or not once the application was deleted (optional and default 'true').

```yaml
ipam.spidernet.io/ippool-reclaim: true
```

### ipam.spidernet.io/ippool

Specify the ippools used to allocate IP.

```yaml
ipam.spidernet.io/ippool: |-
  {
    "ipv4": ["v4-ippool1"],
    "ipv6": ["v6-ippool1", "v6-ippool2"]
  }
```

- `ipv4` (array, optional): Specify which ippool is used to allocate the IPv4 address. When `enableIPv4` in the `spiderpool-conf` ConfigMap is set to true, this field is required.
- `ipv6` (array, optional): Specify which ippool is used to allocate the IPv6 address. When `enableIPv6` in the `spiderpool-conf` ConfigMap is set to true, this field is required.

### ipam.spidernet.io/ippools

It is similar to `ipam.spidernet.io/ippool` but could be used in the case with multiple interfaces. Note that `ipam.spidernet.io/ippools` has precedence over `ipam.spidernet.io/ippool`.

```yaml
ipam.spidernet.io/ippools: |-
  [{
      "interface": "eth0",
      "ipv4": ["v4-ippool1"],
      "ipv6": ["v6-ippool1"],
      "cleangateway": true
   },{
      "interface": "eth1",
      "ipv4": ["v4-ippool2"],
      "ipv6": ["v6-ippool2"],
      "cleangateway": false
  }]
```

- `interface` (string, required): Since the CNI request only carries the information of one interface, the `interface` field shall be specified to distinguish in the case of multiple interfaces.
- `ipv4` (array, optional): Specify which ippool is used to allocate the IPv4 address. When `enableIPv4` in the `spiderpool-conf` ConfigMap is set to true, this field is required.
- `ipv6` (array, optional): Specify which ippool is used to allocate the IPv6 address. When `enableIPv6` in the `spiderpool-conf` ConfigMap is set to true, this field is required.
- `cleangateway` (bool, optional): If set to true, the IPAM plugin will not return the default gateway route recorded in the ippool. default to false

For different interfaces, it is not recommended to use ippools of the same subnet.

### ipam.spidernet.io/routes

You can use the following code to enable additional routes take effect.

```yaml
ipam.spidernet.io/routes: |-
  [{
      "dst": "10.0.0.0/16",
      "gw": "192.168.1.1"
  }]
```

- `dst` (string, required): Network destination of the route.
- `gw` (string, required): The forwarding or next hop IP address.

### ipam.spidernet.io/assigned-{INTERFACE}

It is the IP allocation result of the interface. It is only used by Spiderpool, not reserved for users.

```yaml
ipam.spidernet.io/assigned-eth0: |-
  {
    "interface": "eth0",
    "ipv4pool": "v4-ippool1",
    "ipv6pool": "v6-ippool1",
    "ipv4": "172.16.0.100/16",
    "ipv6": "fd00::100/64",
    "vlan": 100
  }
```

## Namespace annotations

Namespace could set following annotations to specify default ippools. They are valid for all Pods under the Namespace.

### ipam.spidernet.io/default-ipv4-ippool

```yaml
ipam.spidernet.io/default-ipv4-ippool: '["ns-v4-ippool1","ns-v4-ippool2"]'
```

If multiple ippools are listed, it will try to allocate IP from the later ippool when the former one is not allocatable.

### ipam.spidernet.io/default-ipv6-ippool

```yaml
ipam.spidernet.io/default-ipv6-ippool: '["ns-v6-ippool1","ns-v6-ippool2"]'
```

For other procedure, similar to [Pod Annotations](#pod-annotations) described above.
