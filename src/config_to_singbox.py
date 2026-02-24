import json
import base64
import sys
import os
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs
import logging
import config_parser as parser
import transport_builder

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ConfigToSingbox:
    def __init__(self):
        self.output_file = 'configs/singbox_configs.json'

    def convert_to_singbox(self, config: str, index: int, protocol_type: str) -> Optional[Dict]:
        try:
            config_lower = config.lower()
            data = None
            outbound = {}
            
            if config_lower.startswith('vmess://'):
                data = parser.decode_vmess(config)
                if not data: return None
                tag = data.get('name') or f"{protocol_type} {index} - {data['add']}:{data['port']}"
                transport, tls = transport_builder.build_singbox_settings(data)
                outbound = {
                    "type": "vmess", "tag": tag, "server": data['add'], "server_port": int(data['port']),
                    "uuid": data['id'], "security": data.get('scy', 'auto'), "alter_id": int(data.get('aid', 0)),
                    "transport": transport, "tls": tls
                }
            
            elif config_lower.startswith('vless://'):
                data = parser.parse_vless(config)
                if not data: return None
                tag = data.get('name') or f"{protocol_type} {index} - {data['address']}:{data['port']}"
                transport, tls = transport_builder.build_singbox_settings(data)
                outbound = {
                    "type": "vless", "tag": tag, "server": data['address'], "server_port": data['port'],
                    "uuid": data['uuid'], "flow": data.get('flow', ''), "tls": tls, "transport": transport
                }
            
            elif config_lower.startswith('trojan://'):
                data = parser.parse_trojan(config)
                if not data: return None
                tag = data.get('name') or f"{protocol_type} {index} - {data['address']}:{data['port']}"
                transport, tls = transport_builder.build_singbox_settings(data)
                outbound = {
                    "type": "trojan", "tag": tag, "server": data['address'], "server_port": data['port'],
                    "password": data['password'], "tls": tls, "transport": transport
                }
            
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                data = parser.parse_hysteria2(config)
                if not data: return None
                tag = data.get('name') or f"{protocol_type} {index} - {data['address']}:{data['port']}"
                transport, tls = transport_builder.build_singbox_settings(data)
                outbound = {
                    "type": "hysteria2", "tag": tag, "server": data['address'], "server_port": data['port'],
                    "password": data['password'], "tls": tls
                }
         
            elif config_lower.startswith('ss://'):
                data = parser.parse_shadowsocks(config)
                if not data: return None
                tag = data.get('name') or f"{protocol_type} {index} - {data['address']}:{data['port']}"
                outbound = {
                    "type": "shadowsocks", "tag": tag, "server": data['address'], "server_port": data['port'],
                    "method": data['method'], "password": data['password']
                }
            
            return outbound if outbound else None
            
        except Exception as e:
            logger.error(f"Failed during convert_to_singbox for config {config[:30]}...: {e}")
            return None

    def process_configs(self):
        try:
            with open('configs/proxy_configs_tested.txt', 'r', encoding='utf-8') as f:
                configs = [line for line in f.read().strip().split('\n') if line.strip() and not line.strip().startswith('//')]
        except FileNotFoundError:
            logger.error("proxy_configs_tested.txt not found! Exiting.")
            return
        except Exception as e:
            logger.error(f"Error reading proxy_configs_tested.txt: {e}")
            return

        outbounds, valid_tags = [], []
        counters = {"VLESS": 1, "Trojan": 1, "VMess": 1, "SS": 1, "Hysteria2": 1}
        protocol_map = {'vless': 'VLESS', 'trojan': 'Trojan', 'vmess': 'VMess', 'ss': 'SS', 'hysteria2': 'Hysteria2', 'hy2': 'Hysteria2'}

        for config in configs:
            protocol_key = config.split('://')[0].lower()
            protocol_name = protocol_map.get(protocol_key)
            
            if protocol_name:
                converted = self.convert_to_singbox(config, counters[protocol_name], protocol_name)
                if converted:
                    outbounds.append(converted)
                    valid_tags.append(converted['tag'])
                    counters[protocol_name] += 1
        
        if not outbounds:
            logger.error("No valid configurations found after processing.")
            return

        final_config = {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {"type": "https", "server": "8.8.8.8", "detour": "🌐 Anonymous Multi", "tag": "dns-remote"},
                    {"type": "udp", "server": "8.8.8.8", "server_port": 53, "tag": "dns-direct"},
                    {"type": "fakeip", "tag": "dns-fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
                ],
                "rules": [
                    {"domain": ["raw.githubusercontent.com"], "server": "dns-direct"},
                    {"clash_mode": "Direct", "server": "dns-direct"},
                    {"clash_mode": "Global", "server": "dns-remote"},
                    {"type": "logical", "mode": "and", "rules": [{"rule_set": "geosite-ir"}, {"rule_set": "geoip-ir"}], "action": "route", "server": "dns-direct"},
                    {"rule_set": ["geosite-malware", "geosite-phishing", "geosite-cryptominers", "geosite-category-ads-all"], "action": "reject"},
                    {"disable_cache": True, "inbound": "tun-in", "query_type": ["A", "AAAA"], "server": "dns-fake"}
                ],
                "strategy": "ipv4_only",
                "independent_cache": True
            },
            "inbounds": [
                {"type": "tun", "tag": "tun-in", "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"], "mtu": 9000, "auto_route": True, "strict_route": True, "endpoint_independent_nat": True, "stack": "mixed"},
                {"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080}
            ],
            "outbounds": [
                {"type": "selector", "tag": "🌐 Anonymous Multi", "outbounds": ["👽 Best Ping 🚀"] + valid_tags + ["direct"]},
                {"type": "direct", "tag": "direct"},
                {"type": "urltest", "tag": "👽 Best Ping 🚀", "outbounds": valid_tags, "url": "https://www.gstatic.com/generate_204", "interrupt_exist_connections": False, "interval": "30s"}
            ] + outbounds,
            "route": {
                "rules": [
                    {"ip_cidr": "172.18.0.2", "action": "hijack-dns"},
                    {"clash_mode": "Direct", "outbound": "direct"},
                    {"clash_mode": "Global", "outbound": "🌐 Anonymous Multi"},
                    {"action": "sniff"},
                    {"protocol": "dns", "action": "hijack-dns"},
                    {"network": "udp", "action": "reject"},
                    {"rule_set": ["geosite-malware", "geosite-phishing", "geosite-cryptominers", "geosite-category-ads-all"], "action": "reject"},
                    {"rule_set": ["geoip-malware", "geoip-phishing"], "action": "reject"},
                    {"rule_set": ["geosite-ir"], "action": "route", "outbound": "direct"},
                    {"rule_set": ["geoip-ir"], "action": "route", "outbound": "direct"}
                ],
                "rule_set": [
                    {"type": "remote", "tag": "geosite-malware", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geoip-malware", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geosite-phishing", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geoip-phishing", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geosite-cryptominers", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geosite-category-ads-all", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geosite-ir", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs", "download_detour": "direct"},
                    {"type": "remote", "tag": "geoip-ir", "format": "binary", "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs", "download_detour": "direct"}
                ],
                "auto_detect_interface": True,
                "default_domain_resolver": {"server": "dns-direct", "strategy": "prefer_ipv4", "rewrite_ttl": 60},
                "final": "🌐 Anonymous Multi"
            },
            "ntp": {"enabled": True, "server": "time.cloudflare.com", "server_port": 123, "domain_resolver": "dns-direct", "interval": "30m", "write_to_system": False},
            "experimental": {
                "cache_file": {"enabled": True, "store_fakeip": True},
                "clash_api": {"external_controller": "127.0.0.1:9090", "external_ui": "ui", "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip", "external_ui_download_detour": "direct", "default_mode": "Rule"}
            }
        }

        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(final_config, f, indent=4, ensure_ascii=False)
            logger.info(f"Configuration successfully generated at: {self.output_file}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during file writing: {e}")


def main():
    converter = ConfigToSingbox()
    converter.process_configs()

if __name__ == '__main__':
    main()