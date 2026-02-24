from typing import Dict, List, Optional
from datetime import datetime
import re
from urllib.parse import urlparse
from dataclasses import dataclass
import logging
from math import inf

from user_settings import (
    SOURCE_URLS, USE_MAXIMUM_POWER, SPECIFIC_CONFIG_COUNT, ENABLED_PROTOCOLS,
    MAX_CONFIG_AGE_DAYS, ENABLE_SINGBOX_TESTER, SINGBOX_TESTER_MAX_WORKERS,
    SINGBOX_TESTER_TIMEOUT_SECONDS, SINGBOX_TESTER_URLS, ENABLE_XRAY_TESTER,
    XRAY_TESTER_MAX_WORKERS, XRAY_TESTER_TIMEOUT_SECONDS, XRAY_TESTER_URLS,
    LOCATION_APIS
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ChannelMetrics:
    total_configs: int = 0
    valid_configs: int = 0
    unique_configs: int = 0
    avg_response_time: float = 0
    last_success_time: Optional[datetime] = None
    fail_count: int = 0
    success_count: int = 0
    overall_score: float = 0.0
    protocol_counts: Dict[str, int] = None

    
    def __post_init__(self):
        if self.protocol_counts is None:
            self.protocol_counts = {}

class ChannelConfig:
    def __init__(self, url: str):
        self.url = self._validate_url(url)
        self.enabled = True
        self.metrics = ChannelMetrics()
        self.is_telegram = bool(re.match(r'^https://t\.me/s/', self.url))
        self.error_count = 0
        self.last_check_time = None
        
    def _validate_url(self, url: str) -> str:
        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL")
        url = url.strip()
        if not url.startswith(('http://', 'https://', 'ssconf://')):
            raise ValueError("Invalid URL protocol")
        return url
        
    
    def calculate_overall_score(self):
        try:
            total_attempts = max(1, self.metrics.success_count + self.metrics.fail_count)
            reliability_score = (self.metrics.success_count / total_attempts) * 35
            
            total_configs = max(1, self.metrics.total_configs)
            quality_score = (self.metrics.valid_configs / total_configs) * 25
            
            valid_configs = max(1, self.metrics.valid_configs)
            uniqueness_score = (self.metrics.unique_configs / valid_configs) * 25
            
            response_score = 15
            if self.metrics.avg_response_time > 0:
                response_score = max(0, min(15, 15 * (1 - (self.metrics.avg_response_time / 10))))
            
            self.metrics.overall_score = round(reliability_score + quality_score + uniqueness_score + response_score, 2)
        except Exception as e:
            logger.error(f"Error calculating score for {self.url}: {str(e)}")
            self.metrics.overall_score = 0.0

class ProxyConfig:
    def __init__(self):
        self.use_maximum_power = USE_MAXIMUM_POWER
        self.specific_config_count = SPECIFIC_CONFIG_COUNT
        self.MAX_CONFIG_AGE_DAYS = MAX_CONFIG_AGE_DAYS
        
        self.ENABLE_CONFIG_TESTER = ENABLE_SINGBOX_TESTER
        self.TESTER_MAX_WORKERS = SINGBOX_TESTER_MAX_WORKERS
        self.TESTER_TIMEOUT_SECONDS = SINGBOX_TESTER_TIMEOUT_SECONDS
        self.TESTER_URLS = SINGBOX_TESTER_URLS
        
        self.ENABLE_XRAY_TESTER = ENABLE_XRAY_TESTER
        self.XRAY_TESTER_MAX_WORKERS = XRAY_TESTER_MAX_WORKERS
        self.XRAY_TESTER_TIMEOUT_SECONDS = XRAY_TESTER_TIMEOUT_SECONDS
        self.XRAY_TESTER_URLS = XRAY_TESTER_URLS
        
        self.LOCATION_APIS = LOCATION_APIS

        initial_urls = [ChannelConfig(url=url) for url in SOURCE_URLS]
        self.SOURCE_URLS = self._remove_duplicate_urls(initial_urls)
        self.SUPPORTED_PROTOCOLS = self._initialize_protocols()
        self._initialize_settings()
        self._set_smart_limits()

    def _initialize_protocols(self) -> Dict:
        return {
            "wireguard://": {"priority": 1, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("wireguard://", False)},
            "hysteria2://": {"priority": 2, "aliases": ["hy2://"], "enabled": ENABLED_PROTOCOLS.get("hysteria2://", False)},
            "vless://": {"priority": 2, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("vless://", False)},
            "vmess://": {"priority": 1, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("vmess://", False)},
            "ss://": {"priority": 2, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("ss://", False)},
            "trojan://": {"priority": 2, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("trojan://", False)},
            "tuic://": {"priority": 1, "aliases": [], "enabled": ENABLED_PROTOCOLS.get("tuic://", False)}
        }

    def _initialize_settings(self):
        self.CHANNEL_RETRY_LIMIT = min(10, max(1, 5))
        self.CHANNEL_ERROR_THRESHOLD = min(0.9, max(0.1, 0.7))
        self.OUTPUT_FILE = 'configs/proxy_configs.txt'
        self.STATS_FILE = 'configs/channel_stats.json'
        self.MAX_RETRIES = min(10, max(1, 5))
        self.RETRY_DELAY = min(60, max(5, 15))
        self.REQUEST_TIMEOUT = min(120, max(10, 60))
        
        self.HEADERS = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

    def _set_smart_limits(self):
        if self.use_maximum_power:
            self._set_maximum_power_mode()
        else:
            self._set_specific_count_mode()

    def _set_maximum_power_mode(self):
        max_configs = 10000
        
        for protocol in self.SUPPORTED_PROTOCOLS:
            self.SUPPORTED_PROTOCOLS[protocol].update({
                "min_configs": 1,
                "max_configs": max_configs,
                "flexible_max": True
            })
        
        self.MIN_CONFIGS_PER_CHANNEL = 1
        self.MAX_CONFIGS_PER_CHANNEL = max_configs
        self.MAX_RETRIES = min(10, max(1, 10))
        self.CHANNEL_RETRY_LIMIT = min(10, max(1, 10))
        self.REQUEST_TIMEOUT = min(120, max(30, 90))

    def _set_specific_count_mode(self):
        if self.specific_config_count <= 0:
            self.specific_config_count = 50
        
        protocols_count = len(self.SUPPORTED_PROTOCOLS)
        base_per_protocol = max(1, self.specific_config_count // protocols_count)
        
        for protocol in self.SUPPORTED_PROTOCOLS:
            self.SUPPORTED_PROTOCOLS[protocol].update({
                "min_configs": 1,
                "max_configs": min(base_per_protocol * 2, 1000),
                "flexible_max": True
            })
        
        self.MIN_CONFIGS_PER_CHANNEL = 1
        self.MAX_CONFIGS_PER_CHANNEL = min(max(5, self.specific_config_count // 2), 1000)

    def _normalize_url(self, url: str) -> str:
        try:
            if not url:
                raise ValueError("Empty URL")
                
            url = url.strip()
            if url.startswith('ssconf://'):
                url = url.replace('ssconf://', 'https://', 1)
                
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("Invalid URL format")
                
            path = parsed.path.rstrip('/')
            
            if parsed.netloc.startswith('t.me/s/'):
                channel_name = parsed.path.strip('/').lower()
                return f"telegram:{channel_name}"
                
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        except Exception as e:
            logger.error(f"URL normalization error: {str(e)}")
            raise

    def _remove_duplicate_urls(self, channel_configs: List[ChannelConfig]) -> List[ChannelConfig]:
        try:
            seen_urls = {}
            unique_configs = []
            
            for config in channel_configs:
                if not isinstance(config, ChannelConfig):
                    logger.warning(f"Invalid config skipped: {config}")
                    continue
                    
                try:
                    normalized_url = self._normalize_url(config.url)
                    if normalized_url not in seen_urls:
                        seen_urls[normalized_url] = True
                        unique_configs.append(config)
                except Exception:
                    continue
            
            if not unique_configs:
                self.save_empty_config_file()
                logger.error("No valid sources found. Empty config file created.")
                return []
                
            return unique_configs
        except Exception as e:
            logger.error(f"Error removing duplicate URLs: {str(e)}")
            self.save_empty_config_file()
            return []

    def is_protocol_enabled(self, protocol: str) -> bool:
        try:
            if not protocol:
                return False
                
            protocol = protocol.lower().strip()
            
            if protocol in self.SUPPORTED_PROTOCOLS:
                return self.SUPPORTED_PROTOCOLS[protocol].get("enabled", False)
                
            for main_protocol, info in self.SUPPORTED_PROTOCOLS.items():
                if protocol in info.get("aliases", []):
                    return info.get("enabled", False)
                    
            return False
        except Exception:
            return False

    def get_enabled_channels(self) -> List[ChannelConfig]:
        channels = [channel for channel in self.SOURCE_URLS if channel.enabled]
        if not channels:
            self.save_empty_config_file()
            logger.error("No enabled channels found. Empty config file created.")
        return channels

    def update_channel_stats(self, channel: ChannelConfig, success: bool, response_time: float = 0):
        if success:
            channel.metrics.success_count += 1
            channel.metrics.last_success_time = datetime.now()
        else:
            channel.metrics.fail_count += 1
        
        if response_time > 0:
            if channel.metrics.avg_response_time == 0:
                channel.metrics.avg_response_time = response_time
            else:
                channel.metrics.avg_response_time = (channel.metrics.avg_response_time * 0.7) + (response_time * 0.3)
        
        channel.calculate_overall_score()
        
        if channel.metrics.overall_score < 25:
            channel.enabled = False
        
        if not any(c.enabled for c in self.SOURCE_URLS):
            self.save_empty_config_file()
            logger.error("All channels are disabled. Empty config file created.")

    def adjust_protocol_limits(self, channel: ChannelConfig):
        if self.use_maximum_power:
            return
            
        for protocol in channel.metrics.protocol_counts:
            if protocol in self.SUPPORTED_PROTOCOLS:
                current_count = channel.metrics.protocol_counts[protocol]
                if current_count > 0:
                    self.SUPPORTED_PROTOCOLS[protocol]["min_configs"] = min(
                        self.SUPPORTED_PROTOCOLS[protocol]["min_configs"],
                        current_count
                    )

    def save_empty_config_file(self) -> bool:
        try:
            with open(self.OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write("")
            return True
        except Exception:
            return False