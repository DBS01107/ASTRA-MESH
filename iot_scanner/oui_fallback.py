OUI_DICT = {
    # Espressif (ESP8266/ESP32 common in IoT)
    "24:A1:60": "Espressif Systems",
    "24:0A:C4": "Espressif Systems",
    "30:AE:A4": "Espressif Systems",
    "3C:71:BF": "Espressif Systems",
    "54:5A:A6": "Espressif Systems",
    "5C:CF:7F": "Espressif Systems",
    "60:01:94": "Espressif Systems",
    "68:C6:3A": "Espressif Systems",
    "80:7D:3A": "Espressif Systems",
    "84:0D:8E": "Espressif Systems",
    "84:F3:EB": "Espressif Systems",
    "90:97:D5": "Espressif Systems",
    "A0:20:A6": "Espressif Systems",
    "A4:7B:9D": "Espressif Systems",
    "AC:D0:74": "Espressif Systems",
    "B4:E6:2D": "Espressif Systems",
    "C4:4F:33": "Espressif Systems",
    "CC:50:E3": "Espressif Systems",
    "D8:A0:1D": "Espressif Systems",
    "EC:FA:BC": "Espressif Systems",
    
    # Tuya Smart
    "10:D5:61": "Tuya Smart",
    "50:E2:04": "Tuya Smart",
    "70:89:76": "Tuya Smart",
    "D4:A6:51": "Tuya Smart",
    
    # Philips Lighting (Signify)
    "00:17:88": "Philips Lighting",
    
    # Belkin (Wemo)
    "C4:41:1E": "Belkin International",
    "94:10:3E": "Belkin International",
    
    # Wyze Labs
    "2C:AA:8E": "Wyze Labs",
    "7C:78:3F": "Wyze Labs",
    
    # TP-Link (Kasa / Tapo)
    "B0:95:75": "TP-Link",
    "50:C7:BF": "TP-Link",
    "14:CC:20": "TP-Link",
    "E8:DE:27": "TP-Link",
    "5C:A6:E6": "TP-Link",
    
    # Xiaomi / Yeelight
    "04:CF:8C": "Xiaomi",
    "28:6C:07": "Xiaomi",
    "34:CE:00": "Xiaomi",
    "50:EC:50": "Xiaomi",
    "54:48:E6": "Xiaomi",
    "64:09:80": "Xiaomi",
    "74:A1:C0": "Xiaomi",
    "78:11:DC": "Xiaomi",
    "C8:02:8F": "Xiaomi",
    "F8:24:41": "Xiaomi",
    "F8:8A:5E": "Xiaomi",
    
    # Ring
    "48:F1:7F": "Ring",
    "5C:0F:7F": "Ring",
    "88:4A:EA": "Ring",
    "8C:36:8A": "Ring",
    "9C:1D:58": "Ring",
    "B0:BD:11": "Ring",
    "C4:B0:39": "Ring",
    
    # Nest
    "18:B4:30": "Nest Labs",
    "64:16:66": "Nest Labs",
    "FE:6A:1A": "Nest Labs",
    
    # Apple
    "00:1C:B3": "Apple Inc.",
    "00:1E:52": "Apple Inc.",
    "00:23:12": "Apple Inc.",
    "00:23:6C": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "00:26:08": "Apple Inc.",
    "00:26:4A": "Apple Inc.",
    "00:3E:E1": "Apple Inc."
}

def lookup_vendor(mac_address: str) -> str:
    """Returns the vendor name or None for a given MAC address."""
    if not mac_address:
        return None
        
    normalized = mac_address.upper().replace("-", ":")
    prefix = normalized[:8]
    
    return OUI_DICT.get(prefix)
