import json
import os
import sys
import logging
import base64
import socket
import requests
import time
from typing import Dict, Optional, Tuple, List
from urllib.parse import urlparse, parse_qs
from collections import OrderedDict
from user_settings import LOCATION_APIS
import config_parser as parser

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LRUCache:
    def __init__(self, capacity: int = 1000):
        self.cache = OrderedDict()
        self.capacity = capacity
    
    def get(self, key: str) -> Optional[Tuple[str, str]]:
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]
    
    def put(self, key: str, value: Tuple[str, str]):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)


class ConfigEnricher:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9'
        }
        self.location_cache = LRUCache(capacity=2000)
        self.location_apis = self._initialize_apis()
        self.successful_patterns = {}
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.failed_apis = set()

    def _clean_domain(self, api_input: str) -> str:
        api_input = api_input.strip()
        for prefix in ['https://', 'http://']:
            if api_input.startswith(prefix):
                api_input = api_input[len(prefix):]
        api_input = api_input.rstrip('/')
        if '/' in api_input:
            api_input = api_input.split('/')[0]
        return api_input.lower()

    def _generate_url_patterns(self, domain: str, ip: str) -> List[str]:
        patterns = []
        
        protocols = ['https', 'http']
        
        path_templates = [
            '?ip={ip}',
            '/?ip={ip}',
            '/{ip}',
            '/{ip}/json',
            '/{ip}/json/',
            '/json/{ip}',
            '/json?ip={ip}',
            '/api/{ip}',
            '/api/json/{ip}',
            '/api?ip={ip}',
            '/v1/{ip}',
            '/v1/json/{ip}',
            '/v2/{ip}',
            '/lookup/{ip}',
            '/geoip/{ip}',
            '/locate/{ip}',
            '/ip/{ip}',
            '/query/{ip}',
            '/{ip}.json',
            '/ip-country?ip={ip}',
            '?cmd=ip-country&ip={ip}'
        ]
        
        for protocol in protocols:
            for template in path_templates:
                path = template.format(ip=ip)
                patterns.append(f'{protocol}://{domain}{path}')
        
        return patterns

    def _extract_country_data(self, data: dict) -> Tuple[str, str]:
        if not isinstance(data, dict):
            return '', ''
        
        data_flat = {}
        for key, value in data.items():
            if value is not None:
                data_flat[key.lower()] = value
        
        status_indicators = data_flat.get('status', '').lower()
        if status_indicators in ['fail', 'error', 'failed']:
            return '', ''
        
        if data_flat.get('error') or data_flat.get('error_message'):
            return '', ''
        
        response_code = str(data_flat.get('response_code', ''))
        if response_code and response_code != '200':
            return '', ''
        
        country_code = ''
        country_name = ''
        
        code_fields = [
            'countrycode', 'country_code', 'country_code2', 
            'country_iso_code', 'iso_code', 'cc', 'code', 
            'country_iso', 'iso', 'countryisocode', 'cca2'
        ]
        
        for field in code_fields:
            if field in data_flat:
                value = str(data_flat[field]).strip().upper()
                if value and len(value) == 2 and value.isalpha():
                    country_code = value.lower()
                    break
        
        name_fields = [
            'country', 'country_name', 'countryname', 'name', 
            'country_long', 'countrylong', 'full_country_name'
        ]
        
        for field in name_fields:
            if field in data_flat:
                value = str(data_flat[field]).strip()
                if value and len(value) > 2 and not value.isdigit():
                    country_name = value
                    break
        
        return country_code, country_name

    def _initialize_apis(self) -> List[Dict[str, str]]:
        apis = []
        for api_input in LOCATION_APIS:
            try:
                domain = self._clean_domain(api_input)
                if domain:
                    apis.append({
                        'domain': domain,
                        'original': api_input
                    })
                    logger.info(f"Registered API: {domain}")
            except Exception as e:
                logger.warning(f"Failed to register '{api_input}': {e}")
        
        if not apis:
            logger.error("No location APIs configured!")
        
        return apis

    def _test_url(self, url: str, retries: int = 2) -> Optional[dict]:
        for attempt in range(retries):
            try:
                response = self.session.get(
                    url, 
                    timeout=5, 
                    allow_redirects=True
                )
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    if 'json' in content_type or 'application/json' in content_type:
                        try:
                            return response.json()
                        except json.JSONDecodeError:
                            pass
                    else:
                        try:
                            return response.json()
                        except:
                            pass
            except requests.exceptions.Timeout:
                logger.debug(f"Timeout for {url} (attempt {attempt + 1}/{retries})")
                if attempt < retries - 1:
                    time.sleep(0.5)
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request error for {url}: {e}")
                break
            except Exception as e:
                logger.debug(f"Unexpected error for {url}: {e}")
                break
        
        return None

    def get_location_from_api(self, ip: str, api_config: dict) -> Tuple[str, str]:
        domain = api_config['domain']
        
        if domain in self.failed_apis:
            return '', ''
        
        if domain in self.successful_patterns:
            cached_pattern = self.successful_patterns[domain]
            url = cached_pattern.format(ip=ip)
            data = self._test_url(url)
            if data:
                country_code, country_name = self._extract_country_data(data)
                if country_code and country_name:
                    return country_code, country_name
        
        url_patterns = self._generate_url_patterns(domain, ip)
        
        for url in url_patterns:
            data = self._test_url(url)
            if data:
                country_code, country_name = self._extract_country_data(data)
                
                if country_code and country_name and len(country_code) == 2:
                    template = url.replace(ip, '{ip}')
                    self.successful_patterns[domain] = template
                    logger.debug(f"Success: {domain} -> {template}")
                    return country_code, country_name
        
        logger.debug(f"Failed: {domain} - no working pattern")
        self.failed_apis.add(domain)
        return '', ''

    def get_location(self, address: str) -> tuple:
        cached = self.location_cache.get(address)
        if cached:
            return cached

        try:
            ip = socket.gethostbyname(address)
        except socket.gaierror as e:
            logger.warning(f"Cannot resolve: {address} - {e}")
            result = ("🏳️", "Unknown")
            self.location_cache.put(address, result)
            return result

        for api_config in self.location_apis:
            if api_config['domain'] in self.failed_apis:
                continue
                
            country_code, country = self.get_location_from_api(ip, api_config)
            
            if country_code and country and len(country_code) == 2:
                try:
                    flag = ''.join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in country_code)
                except:
                    flag = "🏳️"
                
                result = (flag, country)
                self.location_cache.put(address, result)
                logger.info(f"{address} -> {flag} {country} (via {api_config['domain']})")
                return result
            
            time.sleep(0.2)
        
        logger.warning(f"Location unknown for {address}")
        result = ("🏳️", "Unknown")
        self.location_cache.put(address, result)
        return result

    def extract_address(self, config: str) -> Optional[str]:
        try:
            config_lower = config.lower()
            data = None
            
            if config_lower.startswith('vmess://'):
                data = parser.decode_vmess(config)
                if data and 'add' in data:
                    return data['add']
            
            elif config_lower.startswith('vless://'):
                data = parser.parse_vless(config)
            
            elif config_lower.startswith('trojan://'):
                data = parser.parse_trojan(config)
            
            elif config_lower.startswith(('hysteria2://', 'hy2://')):
                data = parser.parse_hysteria2(config)
            
            elif config_lower.startswith('ss://'):
                data = parser.parse_shadowsocks(config)
            
            if data and 'address' in data:
                return data['address']
            
            return None
        except Exception as e:
            logger.debug(f"Failed to extract address from config: {e}")
            return None

    def process_configs(self, input_file: str, output_file: str):
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.error(f"{input_file} not found!")
            return
        except Exception as e:
            logger.error(f"Error reading {input_file}: {e}")
            return

        configs = []
        for line in lines:
            line = line.strip()
            if not line.startswith('//') and line:
                configs.append(line)

        unique_addresses = set()
        for config in configs:
            address = self.extract_address(config)
            if address:
                unique_addresses.add(address)

        logger.info(f"Found {len(unique_addresses)} unique server addresses")

        total = len(unique_addresses)
        for idx, address in enumerate(unique_addresses, 1):
            self.get_location(address)
            if idx % 10 == 0 or idx == total:
                logger.info(f"Progress: {idx}/{total} addresses processed")

        cache_dict = {}
        current_cache = self.location_cache.cache
        for key, value in current_cache.items():
            cache_dict[key] = list(value)

        try:
            os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(cache_dict, f, indent=2, ensure_ascii=False)
            logger.info(f"Successfully saved {len(cache_dict)} location entries to {output_file}")
        except IOError as e:
            logger.error(f"Failed to write output file: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred: {e}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python enrich_configs.py <input.txt> <output.json>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    enricher = ConfigEnricher()
    enricher.process_configs(input_file, output_file)

if __name__ == '__main__':
    main()