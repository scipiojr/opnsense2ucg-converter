"""
Data models representing network entities for OPNsense and UniFi Cloud Gateway Max.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class OPNsenseInterface:
    id: str                         # e.g. "lan", "opt1", "wan"
    descr: str                      # e.g. "MANAGEMENT", "IOT", "WAN"
    physical_if: str                # e.g. "igb0", "vlan0.10"
    ipaddr: str                     # e.g. "192.168.10.1" or "dhcp"
    subnet: str                     # e.g. "24"
    gateway: Optional[str] = None
    vlan_tag: Optional[int] = None
    enabled: bool = True


@dataclass
class OPNsenseStaticLease:
    mac: str
    ipaddr: str
    hostname: str
    descr: str
    interface: str                  # e.g. "lan", "opt1"


@dataclass
class OPNsenseDhcpRange:
    interface: str
    range_from: str
    range_to: str
    dns_servers: List[str] = field(default_factory=list)
    gateway: Optional[str] = None


@dataclass
class OPNsenseAlias:
    name: str
    type: str                       # "host", "network", "port", "url", etc.
    content: List[str] = field(default_factory=list)
    descr: str = ""


@dataclass
class OPNsensePortForward:
    interface: str
    protocol: str                   # "tcp", "udp", "tcp/udp"
    src_ip: str
    src_port: str
    dst_ip: str
    dst_port: str
    target_ip: str
    target_port: str
    descr: str = ""
    enabled: bool = True


@dataclass
class OPNsenseFilterRule:
    id: str
    interface: str                  # e.g. "lan", "opt1", "wan", "floating"
    direction: str = "in"           # usually "in"
    action: str = "pass"            # "pass", "block", "reject"
    protocol: str = "any"           # "any", "tcp", "udp", "tcp/udp", "icmp"
    src: str = "any"                # IP, alias, subnet, "any"
    src_port: str = "any"
    dst: str = "any"
    dst_port: str = "any"
    descr: str = ""
    enabled: bool = True
    log: bool = False
    is_quick: bool = True
    is_floating: bool = False
    src_inverted: bool = False
    dst_inverted: bool = False


@dataclass
class OmittedItem:
    category: str                   # e.g. "VPN", "Alias", "Firewall", "Plugin", "DNS", "System"
    name: str                       # e.g. "WireGuard Server", "URL-Table Alias"
    reason: str                     # Why this cannot be transferred automatically
    recommendation: str             # How to configure it natively in UniFi OS / UCG-Max
    severity: str = "warning"       # "info", "warning", "action_required"


@dataclass
class OPNsenseDnsHost:
    host: str
    domain: str
    ip: str
    descr: str = ""


@dataclass
class OPNsenseWireGuard:
    name: str
    port: int = 51820
    tunnel_address: str = "10.10.0.1/24"
    public_key: str = ""
    peers: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class OPNsenseTrafficShaper:
    down_rate_kbps: int = 0
    up_rate_kbps: int = 0


@dataclass
class OPNsenseConfig:
    version: str = ""
    interfaces: List[OPNsenseInterface] = field(default_factory=list)
    static_leases: List[OPNsenseStaticLease] = field(default_factory=list)
    dhcp_ranges: List[OPNsenseDhcpRange] = field(default_factory=list)
    aliases: List[OPNsenseAlias] = field(default_factory=list)
    port_forwards: List[OPNsensePortForward] = field(default_factory=list)
    filter_rules: List[OPNsenseFilterRule] = field(default_factory=list)
    dns_hosts: List[OPNsenseDnsHost] = field(default_factory=list)
    wireguard_servers: List[OPNsenseWireGuard] = field(default_factory=list)
    traffic_shaper: Optional[OPNsenseTrafficShaper] = None
    omitted_items: List[OmittedItem] = field(default_factory=list)
    raw_xml: str = ""


# Target UniFi Models

@dataclass
class UniFiDnsRecord:
    key: str                        # FQDN e.g. "printer.home.arpa"
    value: str                      # IP e.g. "192.168.1.50"
    record_type: str = "A"
    enabled: bool = True


@dataclass
class UniFiTrafficRoute:
    name: str
    source_network: str
    target_gateway: str             # e.g. "WAN", "WAN2"
    description: str = ""


@dataclass
class UniFiTrafficRule:
    name: str
    action: str = "BLOCK"           # "BLOCK" or "ALLOW"
    target: str = "DOMAIN"          # "DOMAIN", "REGION", "APP"
    domains: List[str] = field(default_factory=list)
    regions: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class UniFiWireGuardServer:
    name: str
    port: int = 51820
    tunnel_subnet: str = "10.10.0.1/24"
    enabled: bool = True
    peers: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class UniFiSmartQueue:
    enabled: bool = False
    down_rate_kbps: int = 0
    up_rate_kbps: int = 0


@dataclass
class UniFiNetwork:
    name: str
    vlan_id: int
    gateway_cidr: str               # e.g. "192.168.10.1/24"
    purpose: str = "corporate"      # "corporate" or "guest"
    dhcp_enabled: bool = True
    dhcp_start: str = ""
    dhcp_stop: str = ""
    domain_name: str = "local"
    dns_servers: List[str] = field(default_factory=list)


@dataclass
class UniFiFirewallGroup:
    name: str
    group_type: str                 # "address-group" or "port-group"
    members: List[str] = field(default_factory=list)
    group_id: Optional[str] = None


@dataclass
class UniFiFirewallRule:
    name: str
    ruleset: str                    # "LAN_IN", "WAN_IN", "LAN_LOCAL", "GUEST_IN"
    action: str                     # "accept", "drop", "reject"
    rule_index: int                 # e.g. 2000, 2001
    enabled: bool = True
    protocol: str = "all"           # "all", "tcp", "udp", "tcp_udp", "icmp"
    src_firewall_group_names: List[str] = field(default_factory=list)
    dst_firewall_group_names: List[str] = field(default_factory=list)
    src_address: Optional[str] = None
    dst_address: Optional[str] = None
    dst_port: Optional[str] = None
    state_established: bool = False
    state_related: bool = False
    state_new: bool = False
    state_invalid: bool = False
    logging: bool = False
    description: str = ""
    status: str = "accepted"         # "accepted", "discarded", "modified"
    origin: str = "OPNsense"         # "OPNsense", "Floating Rule", "Default-Deny Protection", etc.
    llm_notes: str = ""


@dataclass
class UniFiFixedIp:
    mac: str
    name: str
    fixed_ip: str
    network_name: str


@dataclass
class UniFiPortForward:
    name: str
    fwd_ip: str
    fwd_port: str
    dst_port: str
    protocol: str                   # "tcp", "udp", "both"
    src_ip: str = "any"
    enabled: bool = True


@dataclass
class UniFiTargetConfig:
    networks: List[UniFiNetwork] = field(default_factory=list)
    firewall_groups: List[UniFiFirewallGroup] = field(default_factory=list)
    firewall_rules: List[UniFiFirewallRule] = field(default_factory=list)
    fixed_ips: List[UniFiFixedIp] = field(default_factory=list)
    port_forwards: List[UniFiPortForward] = field(default_factory=list)
    dns_records: List[UniFiDnsRecord] = field(default_factory=list)
    traffic_routes: List[UniFiTrafficRoute] = field(default_factory=list)
    traffic_rules: List[UniFiTrafficRule] = field(default_factory=list)
    wireguard_servers: List[UniFiWireGuardServer] = field(default_factory=list)
    smart_queue: Optional[UniFiSmartQueue] = None
    omitted_items: List[OmittedItem] = field(default_factory=list)
