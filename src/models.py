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
class OPNsenseModemManagement:
    detected: bool = False
    interface_id: str = ""           # e.g. "opt1", "modem"
    interface_descr: str = ""        # e.g. "MODEM", "DrayTek"
    parent_if: str = ""              # e.g. "igb1" (shared with WAN)
    modem_ip: str = "192.168.2.1"     # Target WebUI IP
    gateway_ip: str = "192.168.2.2"   # Gateway IP on router side
    subnet: str = "24"               # e.g. "24"
    existing_vlan: Optional[int] = None # If already had a VLAN tag in OPNsense
    allocated_vlan: int = 99         # Dedicated VLAN for UniFi
    reason: str = ""


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
class OPNsenseSourceNat:
    interface: str                  # e.g. "wan"
    source_net: str                 # e.g. "192.168.1.0/24" or alias
    source_port: str = "any"
    destination_net: str = "any"
    destination_port: str = "any"
    target: str = ""                # Target IP / Translation address (e.g. WAN IP, VIP)
    target_port: str = ""
    static_nat_port: bool = False   # Preserve original source port (VoIP / Gaming)
    descr: str = ""
    enabled: bool = True
    nonat: bool = False             # Do NOT translate (exception rule)


@dataclass
class OPNsenseOneToOneNat:
    interface: str                  # e.g. "wan"
    internal_net: str               # Internal IP / subnet
    external_net: str               # External IP / subnet
    nat_type: str = "binat"         # "binat" or "nat"
    descr: str = ""
    enabled: bool = True


@dataclass
class OPNsenseNptv6:
    interface: str                  # e.g. "wan"
    source_prefix: str              # Internal IPv6 prefix (e.g. fd00:...)
    destination_prefix: str         # External IPv6 prefix
    track_interface: str = ""       # Dynamic prefix tracking interface
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
    rule_inverted: bool = False


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
class OPNsenseDnsDomainOverride:
    domain: str
    ip: str
    descr: str = ""


@dataclass
class OPNsenseDynDns:
    service: str                    # e.g. "cloudflare", "strato", "duckdns", "dyndns", "custom"
    host: str                       # e.g. "vpn.example.com"
    username: str = ""
    password: str = ""
    interface: str = "wan"          # "wan", "opt1", etc.
    server: str = ""                # custom server url if any
    mx: str = ""
    checkip: str = ""
    descr: str = ""
    enabled: bool = True


@dataclass
class OPNsenseStaticRoute:
    network: str                    # e.g. "10.200.0.0/16"
    gateway: str                    # e.g. "192.168.1.254" or gateway name
    descr: str = ""
    enabled: bool = True


@dataclass
class OPNsenseGatewayGroup:
    name: str                       # e.g. "WAN_FAILOVER" or "WAN_LOADBALANCE"
    members: List[Dict[str, Any]] = field(default_factory=list)  # [{"gateway": "WAN_DHCP", "tier": 1, "weight": 1}]
    trigger: str = "down"           # "down", "loss", "latency", "lossordown"
    descr: str = ""


@dataclass
class OPNsenseSystemNtp:
    timeservers: List[str] = field(default_factory=list)  # ["0.opnsense.pool.ntp.org", "ptbtime1.ptb.de"]
    interfaces: List[str] = field(default_factory=list)   # listening interfaces
    dhcp_ntp_servers: Dict[str, List[str]] = field(default_factory=dict) # iface_id -> [ntp_ip]


@dataclass
class OPNsenseSyslog:
    server: str = ""                # remote syslog server IP/hostname
    port: int = 514
    protocol: str = "udp"           # "udp" or "tls"
    enabled: bool = False


@dataclass
class OPNsenseSnmp:
    community: str = "public"
    contact: str = ""
    location: str = ""
    enabled: bool = False


@dataclass
class OPNsenseMdns:
    enabled: bool = False
    interfaces: List[str] = field(default_factory=list)   # ["lan", "opt2"]


@dataclass
class OPNsenseUpnp:
    enabled: bool = False
    wan_interface: str = "wan"
    lan_interfaces: List[str] = field(default_factory=list)


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
    source_nats: List[OPNsenseSourceNat] = field(default_factory=list)
    onetoone_nats: List[OPNsenseOneToOneNat] = field(default_factory=list)
    nptv6_rules: List[OPNsenseNptv6] = field(default_factory=list)
    filter_rules: List[OPNsenseFilterRule] = field(default_factory=list)
    dns_hosts: List[OPNsenseDnsHost] = field(default_factory=list)
    dns_domain_overrides: List[OPNsenseDnsDomainOverride] = field(default_factory=list)
    dynamic_dns: List[OPNsenseDynDns] = field(default_factory=list)
    static_routes: List[OPNsenseStaticRoute] = field(default_factory=list)
    gateway_groups: List[OPNsenseGatewayGroup] = field(default_factory=list)
    system_ntp: Optional[OPNsenseSystemNtp] = None
    syslog: Optional[OPNsenseSyslog] = None
    snmp: Optional[OPNsenseSnmp] = None
    multicast: Optional[OPNsenseMdns] = None
    upnp: Optional[OPNsenseUpnp] = None
    wireguard_servers: List[OPNsenseWireGuard] = field(default_factory=list)
    traffic_shaper: Optional[OPNsenseTrafficShaper] = None
    omitted_items: List[OmittedItem] = field(default_factory=list)
    modem_management: Optional[OPNsenseModemManagement] = None
    system_domain: str = ""
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
    is_management: bool = False


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
    src_inverted: bool = False       # Match opposite / negated source
    dst_inverted: bool = False       # Match opposite / negated destination
    rule_inverted: bool = False      # Inverted rule logic / action


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
class UniFiNatRule:
    name: str
    nat_type: str                   # "snat", "masquerade", "1to1", "dnat"
    interface: str = "WAN"          # e.g. "WAN", "WAN2"
    source_address: str = "any"
    destination_address: str = "any"
    translated_ip: str = ""
    translated_port: str = ""
    static_port: bool = False
    enabled: bool = True
    description: str = ""
    origin: str = "OPNsense Source NAT"
    status: str = "accepted"        # "accepted", "native", "omitted"


@dataclass
class UniFiWlan:
    name: str                       # SSID
    security: str = "wpapsk"        # "wpapsk", "wpa2", "wpa3", "open"
    x_passphrase: str = ""          # Pre-Shared Key
    vlan_id: Optional[int] = None   # Target VLAN tag
    is_guest: bool = False
    enabled: bool = True
    network_id: Optional[str] = None


@dataclass
class UniFiDevice:
    name: str
    mac: str
    model: str = ""
    ip: str = ""
    device_type: str = "uap"        # "uap", "usw", "ugw", etc.
    adopted: bool = True


@dataclass
class UniFiSourceState:
    source_type: str                # "ucg_max", "uos_server", "json_import"
    host: str = ""
    version: str = ""
    networks: List[Dict[str, Any]] = field(default_factory=list)
    wlans: List[UniFiWlan] = field(default_factory=list)
    devices: List[UniFiDevice] = field(default_factory=list)
    clients: List[Dict[str, Any]] = field(default_factory=list)
    firewall_rules: List[Dict[str, Any]] = field(default_factory=list)
    raw_summary: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconciliationItem:
    category: str                   # "network", "wlan", "client", "firewall_rule"
    key: str                        # Identifier e.g. "VLAN 20 (IOT)", "SSID Home-Net"
    opnsense_val: Optional[str] = None
    ucg_val: Optional[str] = None
    uos_val: Optional[str] = None
    status: str = "aligned"         # "aligned", "create", "update", "conflict", "import_uos", "preserve_ucg", "excluded"
    action: str = ""                # Strategy applied
    explanation: str = ""
    item_id: str = ""               # Stable identifier, e.g. "network:20", "wlan:Home", "client:aa:bb:..."
    exclusion: Optional[Dict[str, Any]] = None  # Exclusion entry if the item is not migrated
    matched_ucg_vlan: Optional[int] = None


@dataclass
class ReconciliationReport:
    ucg_connected: bool = False
    uos_connected: bool = False
    ucg_version: str = ""
    uos_version: str = ""
    items: List[ReconciliationItem] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    conflict_priority: str = "manual"


@dataclass
class UniFiDynDns:
    service: str                    # "cloudflare", "dyndns", "strato", "duckdns", "custom", etc.
    host_name: str                  # FQDN
    login: str = ""
    password: str = ""
    interface: str = "WAN"          # "WAN" or "WAN2"
    server: str = ""                # custom server
    enabled: bool = True
    description: str = ""
    status: str = "accepted"        # "accepted", "excluded", "modified"


@dataclass
class UniFiStaticRoute:
    name: str
    network: str                    # CIDR destination
    next_hop: str                   # Next-hop gateway IP
    distance: int = 1               # Route metric
    enabled: bool = True
    status: str = "accepted"        # "accepted", "excluded"


@dataclass
class UniFiDnsForwarding:
    domain: str                     # e.g. "corp.internal"
    forward_to_ip: str              # DNS IP
    enabled: bool = True
    status: str = "accepted"


@dataclass
class UniFiMultiWan:
    mode: str = "failover"          # "failover" or "distributed"
    load_balance_percentage: int = 50 # if distributed, e.g. 50 (50/50)
    wan1_echo_server: str = "1.1.1.1"
    wan2_echo_server: str = "8.8.8.8"
    wan2_port: str = "Port 4"       # UCG-Max remapped port
    status: str = "accepted"


@dataclass
class UniFiNtpSetting:
    upstream_servers: List[str] = field(default_factory=list)
    dhcp_option42_enabled: bool = True
    status: str = "accepted"


@dataclass
class UniFiSyslog:
    enabled: bool = False
    server: str = ""
    port: int = 514
    status: str = "accepted"


@dataclass
class UniFiSnmp:
    enabled: bool = False
    community: str = "public"
    status: str = "accepted"


@dataclass
class UniFiMulticast:
    mdns_enabled: bool = True
    igmp_snooping_enabled: bool = True
    status: str = "accepted"


@dataclass
class UniFiUpnp:
    enabled: bool = False
    wan_interface: str = "WAN"
    lan_networks: List[str] = field(default_factory=list)
    status: str = "accepted"


@dataclass
class UniFiTargetConfig:
    networks: List[UniFiNetwork] = field(default_factory=list)
    firewall_groups: List[UniFiFirewallGroup] = field(default_factory=list)
    firewall_rules: List[UniFiFirewallRule] = field(default_factory=list)
    fixed_ips: List[UniFiFixedIp] = field(default_factory=list)
    port_forwards: List[UniFiPortForward] = field(default_factory=list)
    nat_rules: List[UniFiNatRule] = field(default_factory=list)
    dns_records: List[UniFiDnsRecord] = field(default_factory=list)
    dns_forwardings: List[UniFiDnsForwarding] = field(default_factory=list)
    dynamic_dns: List[UniFiDynDns] = field(default_factory=list)
    static_routes: List[UniFiStaticRoute] = field(default_factory=list)
    multi_wan: Optional[UniFiMultiWan] = None
    ntp_settings: Optional[UniFiNtpSetting] = None
    syslog_settings: Optional[UniFiSyslog] = None
    snmp_settings: Optional[UniFiSnmp] = None
    multicast_settings: Optional[UniFiMulticast] = None
    upnp_settings: Optional[UniFiUpnp] = None
    traffic_routes: List[UniFiTrafficRoute] = field(default_factory=list)
    traffic_rules: List[UniFiTrafficRule] = field(default_factory=list)
    wireguard_servers: List[UniFiWireGuardServer] = field(default_factory=list)
    smart_queue: Optional[UniFiSmartQueue] = None
    omitted_items: List[OmittedItem] = field(default_factory=list)
    wlans: List[UniFiWlan] = field(default_factory=list)
    modem_management: Optional[OPNsenseModemManagement] = None
    reconciliation_report: Optional[ReconciliationReport] = None

