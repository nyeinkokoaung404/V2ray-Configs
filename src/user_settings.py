# Please modify the settings below according to your needs.

# List of source URLs to fetch proxy configurations from.
# Add or remove URLs as needed. All URLs in this list are automatically enabled.
SOURCE_URLS = [
    "https://t.me/s/v2rayfree",
    "https://t.me/s/PrivateVPNs",
    "https://t.me/s/prrofile_purple",
    "https://t.me/s/DirectVPN",
    "https://t.me/s/persianvpnhub",
    "https://t.me/v2nodes",
    "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/parvinxs/Submahsanetxsparvin/refs/heads/main/Sub.mahsa.xsparvin",
    "https://raw.githubusercontent.com/Freedom-Guard-Builder/FL/refs/heads/main/config/Fast.txt",
    "https://raw.githubusercontent.com/Ashkan-m/v2ray/main/Sub.txt",
    "https://raw.githubusercontent.com/davudsedft/purvpn/refs/heads/main/links/purkow.txt",
]

# Set to True to fetch the maximum possible number of configurations.
# If True, SPECIFIC_CONFIG_COUNT will be ignored.
USE_MAXIMUM_POWER = False

# Desired number of configurations to fetch.
# This is used only if USE_MAXIMUM_POWER is False.
SPECIFIC_CONFIG_COUNT = 2500

# Dictionary of protocols to enable or disable.
# Set each protocol to True to enable, False to disable.
ENABLED_PROTOCOLS = {
    "wireguard://": False,
    "hysteria2://": True,
    "vless://": True,
    "vmess://": True,
    "ss://": True,
    "trojan://": True,
    "tuic://": False,
}

# Maximum age of configurations in days.
# Configurations older than this will be considered invalid.
MAX_CONFIG_AGE_DAYS = 1

# --- Sing-box Config Tester Settings ---

# Set to True to enable testing of configs using sing-box.
# If True, sing-box will be used to test all fetched configs and create a 'tested' config file.
# If False, the testing step will be skipped.
ENABLE_SINGBOX_TESTER = True

# Number of parallel workers to use for testing sing-box configs.
# A higher number means faster testing but uses more CPU/RAM.
SINGBOX_TESTER_MAX_WORKERS = 8

# Maximum time (in seconds) to wait for a sing-box config to respond during testing.
# Configs that take longer than this will be marked as failed.
SINGBOX_TESTER_TIMEOUT_SECONDS = 10

# List of URLs to test sing-box configs against.
# The tester will try each URL in order until one succeeds.
SINGBOX_TESTER_URLS = [
    'https://www.youtube.com/generate_204'
    #'https://www.gstatic.com/generate_204'
]

# --- Xray Config Tester Settings ---

# Set to True to enable testing of configs using Xray core.
# If True, Xray will be used to test all fetched configs before conversion and create a 'tested' config file.
# If False, the testing step will be skipped.
ENABLE_XRAY_TESTER = True

# Number of parallel workers to use for testing Xray configs.
# A higher number means faster testing but uses more CPU/RAM.
XRAY_TESTER_MAX_WORKERS = 8

# Maximum time (in seconds) to wait for an Xray config to respond during testing.
# Configs that take longer than this will be marked as failed.
XRAY_TESTER_TIMEOUT_SECONDS = 10

# List of URLs to test Xray configs against.
# The tester will try each URL in order until one succeeds.
XRAY_TESTER_URLS = [
    'https://www.youtube.com/generate_204'
    #'https://www.gstatic.com/generate_204'
]

# --- Location API Settings ---

# List of free IP geolocation APIs to identify server countries.
# The system tries APIs in order from top to bottom (first = highest priority).
# If one API fails or is rate-limited, the system automatically tries the next one.
#
# HOW TO ADD AN API:
# Simply add the domain name or full URL. Examples:
#   freeipapi.com
#   ip-api.com
#   https://ipapi.co
#   api.iplocation.net
#
# The system automatically detects the correct API format and endpoint.
# No API key is required for the APIs listed below.
#
# RECOMMENDED FREE APIs (ranked by reliability and rate limits):
#
# 1. freeipapi.com - 60 requests/minute, very fast, no registration
# 2. ip-api.com - 45 requests/minute, very reliable, widely used
# 3. ipapi.co - 1000 requests/day (~30k/month), good accuracy
# 4. ipwhois.app - 10000 requests/month, decent speed
# 5. api.iplocation.net - unlimited, fast, accurate
#
LOCATION_APIS = [
    'api.iplocation.net',
    'freeipapi.com',
    'ip-api.com',
    'ipapi.co'
]
