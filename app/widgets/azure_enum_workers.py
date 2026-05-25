# app/widgets/azure_enum_workers.py
"""
Azure Network and Identity Enumeration Workers
Implements the enumeration phases from the Azure Penetration Testing plan.
"""

from PyQt6.QtCore import QObject
from app.core.base_worker import WorkerSignals
from app.core.html_utils import h
import json
import urllib.request
import ssl
import logging

logger = logging.getLogger(__name__)


class AzureNetworkEnumWorker(QObject):
    """Worker for Azure network topology enumeration"""

    def __init__(self, tool_id: str, subscription_id: str,
                 token: str, resource_group: str = ""):
        super().__init__()
        self.signals = WorkerSignals()
        self.tool_id = tool_id
        self.subscription_id = subscription_id
        self.token = token
        self.resource_group = resource_group
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def run(self):
        try:
            self.signals.output.emit(
                "<p style='color: #00BFFF;'>[NETWORK ENUMERATION]</p>"
            )
            if self.tool_id == "full_network":
                self._enum_vnets()
                self._enum_nsgs()
                self._enum_public_ips()
                self._enum_peerings()
                self._enum_load_balancers()
                self._enum_vpn_gateways()
                self._enum_firewalls()
            elif self.tool_id == "vnet_enum":
                self._enum_vnets()
            elif self.tool_id == "nsg_enum":
                self._enum_nsgs()
            elif self.tool_id == "peering_enum":
                self._enum_peerings()
            elif self.tool_id == "public_ip_enum":
                self._enum_public_ips()
            elif self.tool_id == "lb_enum":
                self._enum_load_balancers()
            elif self.tool_id == "firewall_enum":
                self._enum_firewalls()
            elif self.tool_id == "vpn_enum":
                self._enum_vpn_gateways()
            elif self.tool_id == "exposed_ports":
                self._enum_nsgs()
                self._analyze_exposed_ports()

            self.signals.output.emit(
                "<p style='color: #00FF41;'>Network enumeration complete.</p>"
            )
            self.signals.finished.emit()
        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>Error: {h(str(e))}</p>"
            )
            self.signals.error.emit(str(e))

    def _call_arm(self, path: str, api_version: str = "2023-05-01"):
        """Call Azure Resource Manager API"""
        url = (f"https://management.azure.com/subscriptions/"
               f"{self.subscription_id}{path}?api-version={api_version}")
        try:
            req = urllib.request.Request(url, headers=self.headers)
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            return json.loads(resp.read().decode())
        except Exception as e:
            return {'error': str(e)}

    def _enum_vnets(self):
        """Enumerate Virtual Networks and Subnets"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[VNet & Subnet Mapping]</p>"
        )
        result = self._call_arm("/providers/Microsoft.Network/virtualNetworks")
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}</p>"
            )
            return

        vnets = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Found {len(vnets)} Virtual Networks</p>"
        )
        for vnet in vnets:
            name = vnet.get('name', 'Unknown')
            location = vnet.get('location', 'Unknown')
            addr_space = vnet.get('properties', {}).get(
                'addressSpace', {}).get('addressPrefixes', [])
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} "
                f"({h(location)}) - {h(', '.join(addr_space))}</p>"
            )
            # List subnets
            subnets = vnet.get('properties', {}).get('subnets', [])
            for subnet in subnets:
                sn_name = subnet.get('name', '')
                sn_prefix = subnet.get('properties', {}).get(
                    'addressPrefix', '')
                nsg_id = subnet.get('properties', {}).get(
                    'networkSecurityGroup', {})
                nsg_name = nsg_id.get('id', '').split('/')[-1] if nsg_id else 'None'
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>    └ {h(sn_name)}: "
                    f"{h(sn_prefix)} (NSG: {h(nsg_name)})</p>"
                )

    def _enum_nsgs(self):
        """Enumerate Network Security Groups and rules"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[NSG Rule Analysis]</p>"
        )
        result = self._call_arm(
            "/providers/Microsoft.Network/networkSecurityGroups"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}</p>"
            )
            return

        nsgs = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Found {len(nsgs)} NSGs</p>"
        )
        self._dangerous_rules = []
        for nsg in nsgs:
            name = nsg.get('name', 'Unknown')
            rules = nsg.get('properties', {}).get('securityRules', [])
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} "
                f"({len(rules)} custom rules)</p>"
            )
            for rule in rules:
                rname = rule.get('name', '')
                props = rule.get('properties', {})
                direction = props.get('direction', '')
                access = props.get('access', '')
                src = props.get('sourceAddressPrefix', '')
                dst_port = props.get('destinationPortRange', '')
                priority = props.get('priority', 0)

                # Flag dangerous rules
                if (access == 'Allow' and direction == 'Inbound'
                        and src in ('*', '0.0.0.0/0', 'Internet')):
                    self.signals.output.emit(
                        f"<p style='color: #FF6B6B;'>    ⚠️ {h(rname)}: "
                        f"ALLOW Inbound from {h(src)} → port {h(dst_port)} "
                        f"(priority {h(str(priority))})</p>"
                    )
                    self._dangerous_rules.append({
                        'nsg': name, 'rule': rname,
                        'port': dst_port, 'source': src
                    })
                elif access == 'Allow' and direction == 'Inbound':
                    self.signals.output.emit(
                        f"<p style='color: #DCDCDC;'>    {h(rname)}: "
                        f"Allow {h(src)} → port {h(dst_port)}</p>"
                    )

    def _analyze_exposed_ports(self):
        """Analyze exposed ports from NSG rules"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Exposed Ports Analysis]</p>"
        )
        if not hasattr(self, '_dangerous_rules') or not self._dangerous_rules:
            self.signals.output.emit(
                "<p style='color: #00FF41;'>  No wide-open inbound rules found</p>"
            )
            return

        critical_ports = {
            '22': 'SSH', '3389': 'RDP', '445': 'SMB',
            '1433': 'MSSQL', '3306': 'MySQL', '5432': 'PostgreSQL',
            '27017': 'MongoDB', '6379': 'Redis', '9200': 'Elasticsearch'
        }
        self.signals.output.emit(
            f"<p style='color: #FF6B6B;'>  ⚠️ {len(self._dangerous_rules)} "
            f"dangerous inbound rules detected:</p>"
        )
        for rule in self._dangerous_rules:
            port = rule['port']
            svc = critical_ports.get(port, 'Unknown service')
            severity = "CRITICAL" if port in critical_ports else "HIGH"
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  [{h(severity)}] "
                f"NSG: {h(rule['nsg'])} → Port {h(port)} ({h(svc)}) "
                f"open to {h(rule['source'])}</p>"
            )

    def _enum_public_ips(self):
        """Enumerate Public IP addresses"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Public IP & DNS Mapping]</p>"
        )
        result = self._call_arm(
            "/providers/Microsoft.Network/publicIPAddresses"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}</p>"
            )
            return

        ips = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Found {len(ips)} Public IPs</p>"
        )
        for ip in ips:
            name = ip.get('name', 'Unknown')
            props = ip.get('properties', {})
            address = props.get('ipAddress', 'Not assigned')
            fqdn = props.get('dnsSettings', {}).get(
                'fqdn', 'No DNS') if props.get('dnsSettings') else 'No DNS'
            alloc = props.get('publicIPAllocationMethod', '')
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)}: {h(address)} "
                f"({h(alloc)}) DNS: {h(fqdn)}</p>"
            )

    def _enum_peerings(self):
        """Enumerate VNet peerings"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[VNet Peering Discovery]</p>"
        )
        # First get all VNets, then check peerings
        result = self._call_arm(
            "/providers/Microsoft.Network/virtualNetworks"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}</p>"
            )
            return

        vnets = result.get('value', [])
        peering_count = 0
        for vnet in vnets:
            peerings = vnet.get('properties', {}).get(
                'virtualNetworkPeerings', [])
            if peerings:
                vnet_name = vnet.get('name', 'Unknown')
                for peer in peerings:
                    peer_name = peer.get('name', '')
                    props = peer.get('properties', {})
                    state = props.get('peeringState', 'Unknown')
                    remote = props.get(
                        'remoteVirtualNetwork', {}).get('id', '').split('/')[-1]
                    allow_forwarding = props.get(
                        'allowForwardedTraffic', False)
                    allow_gateway = props.get(
                        'allowGatewayTransit', False)
                    self.signals.output.emit(
                        f"<p style='color: #DCDCDC;'>  • {h(vnet_name)} ↔ "
                        f"{h(remote)} ({h(state)})</p>"
                    )
                    if allow_forwarding:
                        self.signals.output.emit(
                            "<p style='color: #FFAA00;'>    "
                            "⚠️ Forwarded traffic allowed</p>"
                        )
                    if allow_gateway:
                        self.signals.output.emit(
                            "<p style='color: #FFAA00;'>    "
                            "⚠️ Gateway transit enabled</p>"
                        )
                    peering_count += 1

        if peering_count == 0:
            self.signals.output.emit(
                "<p style='color: #DCDCDC;'>  No VNet peerings found</p>"
            )
        else:
            self.signals.output.emit(
                f"<p style='color: #00FF41;'>  Total peerings: "
                f"{peering_count}</p>"
            )

    def _enum_load_balancers(self):
        """Enumerate Load Balancers and Application Gateways"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Load Balancers & Gateways]</p>"
        )
        # Load Balancers
        result = self._call_arm(
            "/providers/Microsoft.Network/loadBalancers"
        )
        if 'error' not in result:
            lbs = result.get('value', [])
            self.signals.output.emit(
                f"<p style='color: #00FF41;'>  Load Balancers: {len(lbs)}</p>"
            )
            for lb in lbs:
                name = lb.get('name', 'Unknown')
                sku = lb.get('sku', {}).get('name', 'Unknown')
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>  • {h(name)} "
                    f"(SKU: {h(sku)})</p>"
                )

        # Application Gateways
        result = self._call_arm(
            "/providers/Microsoft.Network/applicationGateways"
        )
        if 'error' not in result:
            gws = result.get('value', [])
            self.signals.output.emit(
                f"<p style='color: #00FF41;'>  App Gateways: {len(gws)}</p>"
            )
            for gw in gws:
                name = gw.get('name', 'Unknown')
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>  • {h(name)}</p>"
                )

    def _enum_vpn_gateways(self):
        """Enumerate VPN Gateways"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[VPN Gateway Discovery]</p>"
        )
        result = self._call_arm(
            "/providers/Microsoft.Network/virtualNetworkGateways"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}</p>"
            )
            return

        gws = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  VPN Gateways: {len(gws)}</p>"
        )
        for gw in gws:
            name = gw.get('name', 'Unknown')
            gw_type = gw.get('properties', {}).get('gatewayType', '')
            vpn_type = gw.get('properties', {}).get('vpnType', '')
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} "
                f"({h(gw_type)}/{h(vpn_type)})</p>"
            )

    def _enum_firewalls(self):
        """Enumerate Azure Firewalls"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Azure Firewall Rules]</p>"
        )
        result = self._call_arm(
            "/providers/Microsoft.Network/azureFirewalls"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FFAA00;'>  No Azure Firewalls found "
                f"or access denied</p>"
            )
            return

        firewalls = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Azure Firewalls: "
            f"{len(firewalls)}</p>"
        )
        for fw in firewalls:
            name = fw.get('name', 'Unknown')
            props = fw.get('properties', {})
            threat_intel = props.get('threatIntelMode', 'Unknown')
            rules_count = len(props.get('networkRuleCollections', []))
            app_rules = len(props.get('applicationRuleCollections', []))
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} "
                f"(Threat Intel: {h(threat_intel)}, "
                f"Network Rules: {rules_count}, "
                f"App Rules: {app_rules})</p>"
            )


class AzureIdentityEnumWorker(QObject):
    """Worker for Azure Identity & Access enumeration via Graph API"""

    def __init__(self, tool_id: str, token: str, tenant: str = ""):
        super().__init__()
        self.signals = WorkerSignals()
        self.tool_id = tool_id
        self.token = token
        self.tenant = tenant
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

    def run(self):
        try:
            self.signals.output.emit(
                "<p style='color: #6F42C1;'>[IDENTITY & ACCESS ENUMERATION]"
                "</p>"
            )
            if self.tool_id == "full_identity":
                self._enum_users()
                self._enum_groups()
                self._enum_service_principals()
                self._enum_directory_roles()
                self._enum_conditional_access()
                self._enum_app_registrations()
            elif self.tool_id == "user_enum":
                self._enum_users()
            elif self.tool_id == "group_enum":
                self._enum_groups()
            elif self.tool_id == "sp_enum":
                self._enum_service_principals()
            elif self.tool_id == "role_enum":
                self._enum_directory_roles()
            elif self.tool_id == "rbac_enum":
                self._enum_rbac_assignments()
            elif self.tool_id == "ca_enum":
                self._enum_conditional_access()
            elif self.tool_id == "app_reg_enum":
                self._enum_app_registrations()
            elif self.tool_id == "msi_enum":
                self._enum_managed_identities()
            elif self.tool_id == "guest_enum":
                self._enum_guest_accounts()
            elif self.tool_id == "priv_esc_paths":
                self._analyze_priv_esc_paths()

            self.signals.output.emit(
                "<p style='color: #00FF41;'>Identity enumeration complete."
                "</p>"
            )
            self.signals.finished.emit()
        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>Error: {h(str(e))}</p>"
            )
            self.signals.error.emit(str(e))

    def _call_graph(self, path: str):
        """Call Microsoft Graph API"""
        url = f"https://graph.microsoft.com/v1.0{path}"
        try:
            req = urllib.request.Request(url, headers=self.headers)
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            return json.loads(resp.read().decode())
        except Exception as e:
            return {'error': str(e)}

    def _enum_users(self):
        """Enumerate Azure AD users"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[User Enumeration]</p>"
        )
        result = self._call_graph(
            "/users?$select=displayName,userPrincipalName,"
            "accountEnabled,userType,createdDateTime&$top=100"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        users = result.get('value', [])
        enabled = [u for u in users if u.get('accountEnabled')]
        guests = [u for u in users if u.get('userType') == 'Guest']

        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Total users: {len(users)} "
            f"(Enabled: {len(enabled)}, Guests: {len(guests)})</p>"
        )
        if guests:
            self.signals.output.emit(
                f"<p style='color: #FFAA00;'>  ⚠️ {len(guests)} guest "
                f"accounts found (potential weak MFA)</p>"
            )
        for user in users[:15]:
            upn = user.get('userPrincipalName', 'Unknown')
            display = user.get('displayName', '')
            enabled_str = "✓" if user.get('accountEnabled') else "✗"
            utype = user.get('userType', 'Member')
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  {h(enabled_str)} "
                f"{h(display)} ({h(upn)}) [{h(utype)}]</p>"
            )
        if len(users) > 15:
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  ... and "
                f"{len(users) - 15} more</p>"
            )

    def _enum_groups(self):
        """Enumerate Azure AD groups"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Group Membership]</p>"
        )
        result = self._call_graph(
            "/groups?$select=displayName,description,groupTypes,"
            "securityEnabled,mailEnabled&$top=50"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        groups = result.get('value', [])
        security_groups = [g for g in groups if g.get('securityEnabled')]
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Total groups: {len(groups)} "
            f"(Security: {len(security_groups)})</p>"
        )
        for group in groups[:20]:
            name = group.get('displayName', 'Unknown')
            desc = group.get('description', '')[:50]
            gtype = "Security" if group.get('securityEnabled') else "M365"
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} [{h(gtype)}]"
                f" {h(desc)}</p>"
            )

    def _enum_service_principals(self):
        """Enumerate Service Principals"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Service Principals]</p>"
        )
        result = self._call_graph(
            "/servicePrincipals?$select=displayName,appId,"
            "servicePrincipalType,accountEnabled&$top=50"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        sps = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Service Principals: {len(sps)}"
            "</p>"
        )
        for sp in sps[:20]:
            name = sp.get('displayName', 'Unknown')
            app_id = sp.get('appId', '')
            sp_type = sp.get('servicePrincipalType', '')
            enabled = sp.get('accountEnabled', True)
            status = "" if enabled else " [DISABLED]"
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} "
                f"({h(sp_type)}) AppId: {h(app_id[:8])}..."
                f"{h(status)}</p>"
            )

    def _enum_directory_roles(self):
        """Enumerate Directory Roles and their members"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Directory Roles]</p>"
        )
        result = self._call_graph("/directoryRoles")
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        roles = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Active Directory Roles: "
            f"{len(roles)}</p>"
        )

        high_priv_roles = [
            'Global Administrator', 'Privileged Role Administrator',
            'Application Administrator', 'Cloud Application Administrator',
            'Exchange Administrator', 'Security Administrator',
            'User Administrator', 'Helpdesk Administrator'
        ]

        for role in roles:
            role_name = role.get('displayName', 'Unknown')
            role_id = role.get('id', '')
            is_high_priv = role_name in high_priv_roles

            # Get members of this role
            members_result = self._call_graph(
                f"/directoryRoles/{role_id}/members"
            )
            members = members_result.get('value', []) if 'error' not in members_result else []

            if members:
                color = "#FF6B6B" if is_high_priv else "#DCDCDC"
                prefix = "⚠️ " if is_high_priv else ""
                self.signals.output.emit(
                    f"<p style='color: {color};'>  {prefix}"
                    f"{h(role_name)} ({len(members)} members):</p>"
                )
                for member in members[:5]:
                    m_name = member.get('displayName', 'Unknown')
                    m_upn = member.get('userPrincipalName', '')
                    self.signals.output.emit(
                        f"<p style='color: #DCDCDC;'>    • {h(m_name)}"
                        f" ({h(m_upn)})</p>"
                    )
                if len(members) > 5:
                    self.signals.output.emit(
                        f"<p style='color: #DCDCDC;'>    ... and "
                        f"{len(members) - 5} more</p>"
                    )

    def _enum_conditional_access(self):
        """Enumerate Conditional Access policies"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Conditional Access Policies]</p>"
        )
        result = self._call_graph(
            "/identity/conditionalAccess/policies"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FFAA00;'>  Cannot read CA policies "
                f"(requires Policy.Read.All): {h(result['error'][:80])}</p>"
            )
            return

        policies = result.get('value', [])
        enabled_policies = [
            p for p in policies
            if p.get('state') == 'enabled'
        ]
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  CA Policies: {len(policies)} "
            f"(Enabled: {len(enabled_policies)})</p>"
        )
        for policy in policies:
            name = policy.get('displayName', 'Unknown')
            state = policy.get('state', 'Unknown')
            conditions = policy.get('conditions', {})
            grant = policy.get('grantControls', {})

            state_color = "#00FF41" if state == "enabled" else "#FFAA00"
            self.signals.output.emit(
                f"<p style='color: {state_color};'>  • {h(name)} "
                f"[{h(state)}]</p>"
            )

            # Check if MFA is required
            built_in = grant.get('builtInControls', []) if grant else []
            if 'mfa' in built_in:
                self.signals.output.emit(
                    "<p style='color: #DCDCDC;'>    → Requires MFA</p>"
                )

            # Check user scope
            users = conditions.get('users', {})
            include_users = users.get('includeUsers', [])
            if 'All' in include_users:
                self.signals.output.emit(
                    "<p style='color: #DCDCDC;'>    → Applies to: "
                    "All users</p>"
                )

    def _enum_rbac_assignments(self):
        """Enumerate RBAC role assignments (ARM scope)"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[RBAC Assignments]</p>"
        )
        self.signals.output.emit(
            "<p style='color: #FFAA00;'>  Note: RBAC requires ARM token "
            "(management.azure.com scope)</p>"
        )
        # Try ARM API for role assignments
        url = ("https://management.azure.com/providers/"
               "Microsoft.Authorization/roleAssignments"
               "?api-version=2022-04-01&$filter=atScope()")
        try:
            req = urllib.request.Request(url, headers=self.headers)
            ctx = ssl.create_default_context()
            resp = urllib.request.urlopen(req, timeout=15, context=ctx)
            result = json.loads(resp.read().decode())
            assignments = result.get('value', [])
            self.signals.output.emit(
                f"<p style='color: #00FF41;'>  Role Assignments: "
                f"{len(assignments)}</p>"
            )
            for assignment in assignments[:20]:
                props = assignment.get('properties', {})
                role_id = props.get('roleDefinitionId', '').split('/')[-1]
                principal = props.get('principalId', '')
                scope = props.get('scope', '')
                self.signals.output.emit(
                    f"<p style='color: #DCDCDC;'>  • Principal: "
                    f"{h(principal[:12])}... → Role: {h(role_id[:12])}... "
                    f"Scope: {h(scope[-40:])}</p>"
                )
        except Exception as e:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  RBAC query failed: "
                f"{h(str(e)[:80])}</p>"
            )

    def _enum_app_registrations(self):
        """Enumerate App Registrations"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[App Registrations]</p>"
        )
        result = self._call_graph(
            "/applications?$select=displayName,appId,"
            "passwordCredentials,keyCredentials,"
            "requiredResourceAccess&$top=50"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        apps = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  App Registrations: {len(apps)}"
            "</p>"
        )
        apps_with_secrets = []
        for app in apps:
            name = app.get('displayName', 'Unknown')
            app_id = app.get('appId', '')
            pwd_creds = app.get('passwordCredentials', [])
            key_creds = app.get('keyCredentials', [])

            cred_info = ""
            if pwd_creds:
                cred_info += f" 🔑{len(pwd_creds)} secrets"
                apps_with_secrets.append(name)
            if key_creds:
                cred_info += f" 📜{len(key_creds)} certs"

            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)} "
                f"(AppId: {h(app_id[:8])}...){h(cred_info)}</p>"
            )

        if apps_with_secrets:
            self.signals.output.emit(
                f"<p style='color: #FFAA00;'>  ⚠️ {len(apps_with_secrets)} "
                f"apps have client secrets (check expiry & rotation)</p>"
            )

    def _enum_managed_identities(self):
        """Enumerate Managed Identities"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Managed Identities]</p>"
        )
        result = self._call_graph(
            "/servicePrincipals?$filter=servicePrincipalType eq "
            "'ManagedIdentity'&$select=displayName,appId,"
            "alternativeNames&$top=50"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        identities = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Managed Identities: "
            f"{len(identities)}</p>"
        )
        for identity in identities[:20]:
            name = identity.get('displayName', 'Unknown')
            alt_names = identity.get('alternativeNames', [])
            resource = ''
            for alt in alt_names:
                if 'Microsoft.' in alt:
                    resource = alt.split('/')[-1]
                    break
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  • {h(name)}"
                f"{' → ' + h(resource) if resource else ''}</p>"
            )

    def _enum_guest_accounts(self):
        """Enumerate guest accounts specifically"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Guest Accounts]</p>"
        )
        result = self._call_graph(
            "/users?$filter=userType eq 'Guest'"
            "&$select=displayName,userPrincipalName,"
            "accountEnabled,createdDateTime&$top=100"
        )
        if 'error' in result:
            self.signals.output.emit(
                f"<p style='color: #FF6B6B;'>  Error: {h(result['error'])}"
                "</p>"
            )
            return

        guests = result.get('value', [])
        self.signals.output.emit(
            f"<p style='color: #00FF41;'>  Guest Accounts: {len(guests)}"
            "</p>"
        )
        if guests:
            self.signals.output.emit(
                "<p style='color: #FFAA00;'>  ⚠️ Guest accounts often "
                "have weaker MFA enforcement</p>"
            )
        for guest in guests[:20]:
            name = guest.get('displayName', 'Unknown')
            upn = guest.get('userPrincipalName', '')
            enabled = "✓" if guest.get('accountEnabled') else "✗"
            created = guest.get('createdDateTime', '')[:10]
            self.signals.output.emit(
                f"<p style='color: #DCDCDC;'>  {h(enabled)} {h(name)} "
                f"({h(upn)}) created: {h(created)}</p>"
            )

    def _analyze_priv_esc_paths(self):
        """Analyze potential privilege escalation paths"""
        self.signals.output.emit(
            "<p style='color: #87CEEB;'>[Privilege Escalation Path "
            "Analysis]</p>"
        )
        self.signals.output.emit(
            "<p style='color: #FFAA00;'>  Checking for common "
            "escalation vectors...</p>"
        )

        # Check for apps with dangerous permissions
        result = self._call_graph(
            "/applications?$select=displayName,appId,"
            "requiredResourceAccess&$top=100"
        )
        dangerous_perms = [
            'Application.ReadWrite.All',
            'RoleManagement.ReadWrite.Directory',
            'AppRoleAssignment.ReadWrite.All',
            'Directory.ReadWrite.All',
        ]

        if 'error' not in result:
            apps = result.get('value', [])
            for app in apps:
                name = app.get('displayName', 'Unknown')
                resources = app.get('requiredResourceAccess', [])
                for resource in resources:
                    # Check resource access entries
                    accesses = resource.get('resourceAccess', [])
                    if len(accesses) > 5:
                        self.signals.output.emit(
                            f"<p style='color: #FFAA00;'>  ⚠️ {h(name)} "
                            f"has {len(accesses)} permission requests "
                            f"(review for over-privilege)</p>"
                        )

        # Check service principals with credentials
        sp_result = self._call_graph(
            "/servicePrincipals?$select=displayName,appId,"
            "passwordCredentials,appRoleAssignments&$top=50"
        )
        if 'error' not in sp_result:
            sps = sp_result.get('value', [])
            cred_sps = [
                sp for sp in sps
                if sp.get('passwordCredentials')
            ]
            if cred_sps:
                self.signals.output.emit(
                    f"<p style='color: #FF6B6B;'>  🔑 "
                    f"{len(cred_sps)} service principals have "
                    f"password credentials</p>"
                )
                self.signals.output.emit(
                    "<p style='color: #FF6B6B;'>  → If compromised, "
                    "attacker can authenticate as these apps</p>"
                )

        self.signals.output.emit(
            "<p style='color: #87CEEB;'>  Recommendations:</p>"
        )
        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>  • Use AzureHound/BloodHound "
            "for full path analysis</p>"
        )
        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>  • Review apps with "
            "Application.ReadWrite.All</p>"
        )
        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>  • Check for SP credentials "
            "that can be rotated by non-admins</p>"
        )
        self.signals.output.emit(
            "<p style='color: #DCDCDC;'>  • Verify PIM is enforced "
            "for all privileged roles</p>"
        )
