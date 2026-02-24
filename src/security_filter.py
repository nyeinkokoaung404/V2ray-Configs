import json
import os
import sys
import logging
import base64
import re
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, parse_qs, unquote

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SecurityFilter:
    def __init__(self, input_file: str, output_file: str, xray_output_file: str):
        self.input_file = input_file
        self.output_file = output_file
        self.xray_output_file = xray_output_file
        self.utility_tags = {'direct', 'block', 'dns'}
        self.group_tags = {'👽 Best Ping 🚀', '🌐 Anonymous Multi'}
        
        self.SECURE_SS_METHODS = {
            'aes-128-gcm',
            'aes-192-gcm',
            'aes-256-gcm',
            'chacha20-ietf-poly1305',
            'xchacha20-ietf-poly1305',
            '2022-blake3-aes-128-gcm',
            '2022-blake3-aes-256-gcm'
        }

    def load_config(self) -> Optional[Dict]:
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Input file not found: {self.input_file}")
            return None
        except json.JSONDecodeError:
            logger.error(f"Failed to decode JSON from {self.input_file}")
            return None
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return None

    @staticmethod
    def get_xray_template() -> Dict:
        return {
            "log": {
                "loglevel": "warning"
            },
            "remarks": "👽 Anonymous Multi Balanced - Secure Configs",
            "dns": {
                "servers": [
                    "https://dns.google/dns-query",
                    "https://cloudflare-dns.com/dns-query",
                    {
                        "address": "1.1.1.2",
                        "domains": [
                            "domain:ir",
                            "geosite:category-ir"
                        ],
                        "skipFallback": True,
                        "tag": "domestic-dns"
                    }
                ]
            },
            "fakedns": [
                {
                    "ipPool": "198.18.0.0/15",
                    "poolSize": 10000
                }
            ],
            "inbounds": [
                {
                    "port": 10808,
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True,
                        "userLevel": 8
                    },
                    "sniffing": {
                        "destOverride": [
                            "http",
                            "tls",
                            "fakedns"
                        ],
                        "enabled": True,
                        "routeOnly": False
                    },
                    "tag": "socks"
                }
            ],
            "observatory": {
                "enableConcurrency": True,
                "probeInterval": "3m",
                "probeUrl": "https://www.gstatic.com/generate_204",
                "subjectSelector": [
                    "proxy-"
                ]
            },
            "outbounds": [],
            "policy": {
                "levels": {
                    "8": {
                        "connIdle": 300,
                        "downlinkOnly": 1,
                        "handshake": 4,
                        "uplinkOnly": 1
                    }
                },
                "system": {
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True
                }
            },
            "routing": {
                "balancers": [
                    {
                        "selector": [
                            "proxy-"
                        ],
                        "strategy": {
                            "type": "leastPing"
                        },
                        "tag": "proxy-round"
                    }
                ],
                "domainStrategy": "AsIs",
                "rules": [
                    {
                        "inboundTag": [
                            "socks"
                        ],
                        "outboundTag": "dns-out",
                        "port": "53",
                        "type": "field"
                    },
                    {
                        "ip": [
                            "geoip:private"
                        ],
                        "outboundTag": "direct",
                        "type": "field"
                    },
                    {
                        "domain": [
                            "geosite:private"
                        ],
                        "outboundTag": "direct",
                        "type": "field"
                    },
                    {
                        "domain": [
                            "domain:ir",
                            "geosite:category-ir"
                        ],
                        "outboundTag": "direct",
                        "type": "field"
                    },
                    {
                        "ip": [
                            "geoip:ir"
                        ],
                        "outboundTag": "direct",
                        "type": "field"
                    },
                    {
                        "inboundTag": [
                            "domestic-dns"
                        ],
                        "outboundTag": "direct",
                        "type": "field"
                    },
                    {
                        "balancerTag": "proxy-round",
                        "network": "tcp,udp",
                        "type": "field"
                    }
                ]
            }
        }

    def singbox_to_xray_vmess(self, sb_outbound: Dict, tag: str) -> Optional[Dict]:
        try:
            server = sb_outbound.get('server')
            server_port = sb_outbound.get('server_port')
            uuid = sb_outbound.get('uuid')
            alter_id = sb_outbound.get('alter_id', 0)
            security = sb_outbound.get('security', 'auto')
            
            if not all([server, server_port, uuid]):
                return None
            
            outbound = {
                "tag": tag,
                "protocol": "vmess",
                "settings": {
                    "vnext": [
                        {
                            "address": server,
                            "port": int(server_port),
                            "users": [
                                {
                                    "id": uuid,
                                    "alterId": int(alter_id),
                                    "security": security,
                                    "level": 8
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none"
                }
            }
            
            transport = sb_outbound.get('transport', {})
            if isinstance(transport, dict):
                transport_type = transport.get('type', 'tcp')
                outbound["streamSettings"]["network"] = transport_type
                
                if transport_type == 'ws':
                    ws_path = transport.get('path', '/')
                    ws_host = transport.get('headers', {}).get('Host', server)
                    outbound["streamSettings"]["wsSettings"] = {
                        "path": ws_path,
                        "headers": {"Host": ws_host}
                    }
            
            tls = sb_outbound.get('tls', {})
            if isinstance(tls, dict) and tls.get('enabled'):
                outbound["streamSettings"]["security"] = "tls"
                sni = tls.get('server_name', server)
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": False
                }
                
                alpn = tls.get('alpn', [])
                if alpn:
                    outbound["streamSettings"]["tlsSettings"]["alpn"] = alpn
                
                utls = tls.get('utls', {})
                if isinstance(utls, dict) and utls.get('enabled'):
                    fp = utls.get('fingerprint', '')
                    if fp:
                        outbound["streamSettings"]["tlsSettings"]["fingerprint"] = fp
            
            return outbound
        except Exception as e:
            logger.warning(f"Failed to convert VMess to Xray: {e}")
            return None

    def singbox_to_xray_vless(self, sb_outbound: Dict, tag: str) -> Optional[Dict]:
        try:
            server = sb_outbound.get('server')
            server_port = sb_outbound.get('server_port')
            uuid = sb_outbound.get('uuid')
            flow = sb_outbound.get('flow', '')
            
            if not all([server, server_port, uuid]):
                return None
            
            outbound = {
                "tag": tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": server,
                            "port": int(server_port),
                            "users": [
                                {
                                    "id": uuid,
                                    "flow": flow,
                                    "encryption": "none",
                                    "level": 8
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none"
                }
            }
            
            transport = sb_outbound.get('transport', {})
            if isinstance(transport, dict):
                transport_type = transport.get('type', 'tcp')
                outbound["streamSettings"]["network"] = transport_type
                
                if transport_type == 'ws':
                    ws_path = transport.get('path', '/')
                    ws_host = transport.get('headers', {}).get('Host', server)
                    outbound["streamSettings"]["wsSettings"] = {
                        "path": ws_path,
                        "headers": {"Host": ws_host}
                    }
            
            tls = sb_outbound.get('tls', {})
            if isinstance(tls, dict) and tls.get('enabled'):
                outbound["streamSettings"]["security"] = "tls"
                sni = tls.get('server_name', server)
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": False
                }
                
                alpn = tls.get('alpn', [])
                if alpn:
                    outbound["streamSettings"]["tlsSettings"]["alpn"] = alpn
                
                utls = tls.get('utls', {})
                if isinstance(utls, dict) and utls.get('enabled'):
                    fp = utls.get('fingerprint', '')
                    if fp:
                        outbound["streamSettings"]["tlsSettings"]["fingerprint"] = fp
            
            return outbound
        except Exception as e:
            logger.warning(f"Failed to convert VLESS to Xray: {e}")
            return None

    def singbox_to_xray_trojan(self, sb_outbound: Dict, tag: str) -> Optional[Dict]:
        try:
            server = sb_outbound.get('server')
            server_port = sb_outbound.get('server_port')
            password = sb_outbound.get('password')
            
            if not all([server, server_port, password]):
                return None
            
            outbound = {
                "tag": tag,
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": server,
                            "port": int(server_port),
                            "password": password,
                            "level": 8
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls"
                }
            }
            
            transport = sb_outbound.get('transport', {})
            if isinstance(transport, dict):
                transport_type = transport.get('type', 'tcp')
                outbound["streamSettings"]["network"] = transport_type
                
                if transport_type == 'ws':
                    ws_path = transport.get('path', '/')
                    ws_host = transport.get('headers', {}).get('Host', server)
                    outbound["streamSettings"]["wsSettings"] = {
                        "path": ws_path,
                        "headers": {"Host": ws_host}
                    }
            
            tls = sb_outbound.get('tls', {})
            if isinstance(tls, dict):
                sni = tls.get('server_name', server)
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": sni,
                    "allowInsecure": False
                }
                
                alpn = tls.get('alpn', [])
                if alpn:
                    outbound["streamSettings"]["tlsSettings"]["alpn"] = alpn
            
            return outbound
        except Exception as e:
            logger.warning(f"Failed to convert Trojan to Xray: {e}")
            return None

    def singbox_to_xray_shadowsocks(self, sb_outbound: Dict, tag: str) -> Optional[Dict]:
        try:
            server = sb_outbound.get('server')
            server_port = sb_outbound.get('server_port')
            method = sb_outbound.get('method')
            password = sb_outbound.get('password')
            
            if not all([server, server_port, method, password]):
                return None
            
            outbound = {
                "tag": tag,
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [
                        {
                            "address": server,
                            "port": int(server_port),
                            "method": method,
                            "password": password,
                            "level": 8
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp"
                }
            }
            
            return outbound
        except Exception as e:
            logger.warning(f"Failed to convert Shadowsocks to Xray: {e}")
            return None

    def convert_secure_configs_to_xray(self, secure_outbounds: List[Dict]) -> bool:
        try:
            xray_config = self.get_xray_template()
            xray_outbounds = []
            
            for idx, sb_outbound in enumerate(secure_outbounds, 1):
                outbound_type = sb_outbound.get('type')
                tag = f"proxy-{idx}"
                xray_outbound = None
                
                if outbound_type == 'vmess':
                    xray_outbound = self.singbox_to_xray_vmess(sb_outbound, tag)
                elif outbound_type == 'vless':
                    xray_outbound = self.singbox_to_xray_vless(sb_outbound, tag)
                elif outbound_type == 'trojan':
                    xray_outbound = self.singbox_to_xray_trojan(sb_outbound, tag)
                elif outbound_type == 'shadowsocks':
                    xray_outbound = self.singbox_to_xray_shadowsocks(sb_outbound, tag)
                
                if xray_outbound:
                    xray_outbounds.append(xray_outbound)
            
            if not xray_outbounds:
                logger.warning("No secure configs could be converted to Xray format")
                return False
            
            xray_outbounds.extend([
                {"protocol": "freedom", "settings": {}, "tag": "direct"},
                {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
                {"protocol": "dns", "tag": "dns-out"}
            ])
            
            xray_config["outbounds"] = xray_outbounds
            
            os.makedirs(os.path.dirname(self.xray_output_file) or '.', exist_ok=True)
            with open(self.xray_output_file, 'w', encoding='utf-8') as f:
                json.dump(xray_config, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Successfully converted {len(xray_outbounds) - 3} secure configs to Xray format: {self.xray_output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to convert secure configs to Xray: {e}")
            return False

    def filter_configs(self):
        config_data = self.load_config()
        if not config_data:
            return

        if 'outbounds' not in config_data:
            logger.error("No 'outbounds' key found in the config.")
            return

        insecure_tags_map: Dict[str, str] = {}
        all_proxy_tags: Set[str] = set()

        for outbound in config_data.get('outbounds', []):
            outbound_type = outbound.get('type')
            if not outbound_type or outbound_type in self.utility_tags or outbound_type in {'selector', 'urltest'}:
                continue
            
            tag = outbound.get('tag')
            if not tag:
                continue
                
            all_proxy_tags.add(tag)
            
            tls_settings = outbound.get('tls')
            tls_enabled = isinstance(tls_settings, dict) and tls_settings.get('enabled') == True

            if isinstance(tls_settings, dict) and tls_settings.get('insecure') == True:
                insecure_tags_map[tag] = "TLS insecure=true (certificate validation disabled)"
                continue

            if outbound_type == 'shadowsocks':
                method = outbound.get('method', '').lower()
                if method not in self.SECURE_SS_METHODS:
                    insecure_tags_map[tag] = f"Insecure SS method: {method}"
                    continue

            if outbound_type == 'vless' and not tls_enabled:
                insecure_tags_map[tag] = "VLESS without TLS (not encrypted)"
                continue
                
            if outbound_type == 'trojan' and not tls_enabled:
                insecure_tags_map[tag] = "Trojan without TLS (not encrypted)"
                continue
                
            if outbound_type == 'vmess':
                vmess_security_val = outbound.get('security')
                vmess_security_str = 'auto'
                if vmess_security_val is not None:
                    vmess_security_str = str(vmess_security_val).lower()
                
                if vmess_security_str == 'none':
                    insecure_tags_map[tag] = "VMess with security=none (not encrypted)"
                    continue
                
                alter_id = outbound.get('alter_id')
                if alter_id is not None and alter_id != 0:
                    try:
                        alter_id_int = int(alter_id)
                        if alter_id_int != 0:
                            insecure_tags_map[tag] = f"VMess with MD5 authentication (alter_id={alter_id_int}) - deprecated and insecure"
                            continue
                    except (ValueError, TypeError):
                        pass

            if outbound_type == 'hysteria2':
                if isinstance(tls_settings, dict) and tls_settings.get('insecure') == True:
                    insecure_tags_map[tag] = "Hysteria2 with TLS insecure=true (certificate validation disabled)"
                    continue

        secure_proxy_tags = all_proxy_tags - insecure_tags_map.keys()
        
        if insecure_tags_map:
            logger.warning(f"Found and removed {len(insecure_tags_map)} insecure configs:")
            for tag, reason in insecure_tags_map.items():
                logger.warning(f" - {tag} (Reason: {reason})")
        else:
            logger.info("No insecure configs found. All configs are secure.")
        
        new_outbounds: List[Dict] = []
        secure_outbounds: List[Dict] = []
        
        for outbound in config_data.get('outbounds', []):
            outbound_type = outbound.get('type')
            outbound_tag = outbound.get('tag')

            if outbound_type in self.utility_tags:
                new_outbounds.append(outbound)
                continue

            if outbound_type in {'selector', 'urltest'}:
                original_list = outbound.get('outbounds', [])
                
                known_good_tags = self.utility_tags.union(self.group_tags).union(secure_proxy_tags)
                
                filtered_list = [tag for tag in original_list if tag in known_good_tags]
                
                if filtered_list:
                    outbound['outbounds'] = filtered_list
                    new_outbounds.append(outbound)
                else:
                    logger.warning(f"Removing empty group (no secure configs left): {outbound_tag}")
                continue

            if outbound_tag in secure_proxy_tags:
                new_outbounds.append(outbound)
                secure_outbounds.append(outbound)

        config_data['outbounds'] = new_outbounds
        
        self.save_config(config_data)
        
        self.convert_secure_configs_to_xray(secure_outbounds)

    def save_config(self, config_data: Dict):
        try:
            os.makedirs(os.path.dirname(self.output_file) or '.', exist_ok=True)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            
            secure_count = sum(1 for ob in config_data.get('outbounds', []) if ob.get('type') not in {'selector', 'urltest', 'direct', 'block', 'dns'})
            logger.info(f"Successfully saved {secure_count} secure proxy configs to {self.output_file}")
        except Exception as e:
            logger.error(f"Failed to write output file: {e}")

def main():
    input_path = 'configs/singbox_configs_tested.json'
    output_path = 'configs/singbox_configs_secure.json'
    xray_output_path = 'configs/xray_secure_loadbalanced_config.json'
    
    filter_instance = SecurityFilter(input_path, output_path, xray_output_path)
    filter_instance.filter_configs()

if __name__ == '__main__':
    main()