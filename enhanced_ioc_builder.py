# AUTHOR: Enhanced by AI Assistant based on original by RADIVAN - RHOVELZ
# VERSION: 2.0 - Improved for perfection and Kaspersky KATA compatibility

import uuid
import datetime
import re
import json
import os
from xml.etree.ElementTree import Element, SubElement, tostring
import xml.dom.minidom
import logging

# Setup logging for better debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def gen_uuid():
    return str(uuid.uuid4())

def current_utc():
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")  # ISO 8601 with Z for UTC

def detect_type(value):
    value = value.strip().lower()
    
    # Prefix-based detections (custom for IOCs)
    if value.startswith("filesize:"):
        return "FILESIZE"
    elif value.startswith("sni:"):
        return "SNI"
    elif value.startswith("mutex:"):
        return "MUTEX"
    elif value.startswith("reg:"):
        return "REGISTRY"
    elif value.startswith("yara:"):  # New: Basic YARA rule detection
        return "YARA"
    
    # Hash detections
    if re.fullmatch(r"[a-f0-9]{32}", value): return "MD5"
    if re.fullmatch(r"[a-f0-9]{40}", value): return "SHA1"
    if re.fullmatch(r"[a-f0-9]{64}", value): return "SHA256"
    
    # Network detections
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value): return "IP"
    if re.fullmatch(r"([a-z0-9\-]+\.)+[a-z]{2,}", value): return "DOMAIN"
    if re.fullmatch(r"[^@]+@[^@]+\.[^@]+", value): return "EMAIL"
    if re.match(r"https?://[^\s]+", value): return "URL"  # New: URL detection
    if re.fullmatch(r"\d{1,5}", value) and 1 <= int(value) <= 65535: return "PORT"  # New: Port detection
    
    # File/Path detections
    if "\\" in value or "/" in value:
        if value.lower().endswith((".exe", ".dll", ".bat", ".sh", ".ps1")):
            return "FILENAME"
        return "BINARY"
    
    return None

def create_indicator_item(doc_type, search_path, value, value_type="string", condition="is"):
    item = Element("IndicatorItem", {"id": gen_uuid(), "condition": condition})
    context = SubElement(item, "Context")
    context.set("search", search_path)
    context.set("type", "sigs")
    context.set("doc_namespace", f"http://schemas.mandiant.com/2010/ioc")  # Kaspersky-compatible namespace
    context.set("doc_name", doc_type)
    
    content = SubElement(item, "Content")
    content.set("type", value_type)
    content.text = value.strip()
    return item

def build_indicator(val, type_detected):
    val_clean = val.split(":")[0] if ":" in val else val  # Clean prefixes for content
    if type_detected == "MD5":
        return create_indicator_item("File", "File/MD5", val_clean, "bytes")
    elif type_detected == "SHA1":
        return create_indicator_item("File", "File/SHA1", val_clean, "bytes")
    elif type_detected == "SHA256":
        return create_indicator_item("File", "File/SHA256", val_clean, "bytes")
    elif type_detected == "IP":
        return create_indicator_item("Network", "Network/DestinationAddress/IPv4-addr", val_clean, "string")
    elif type_detected == "DOMAIN":
        return create_indicator_item("Network", "Network/DNSQuestion/name", val_clean, "string")
    elif type_detected == "FILENAME":
        return create_indicator_item("File", "File/FileName", val_clean, "string")
    elif type_detected == "BINARY":
        return create_indicator_item("File", "File/FullPath", val_clean, "string")
    elif type_detected == "MUTEX":
        mutex_val = val.split("mutex:")[1] if "mutex:" in val else val_clean
        return create_indicator_item("SyncObjects", "SyncObjects/Mutex/Name", mutex_val, "string")
    elif type_detected == "REGISTRY":
        reg_val = val.split("reg:")[1] if "reg:" in val else val_clean
        return create_indicator_item("Registry", "Registry/Key", reg_val, "string")
    elif type_detected == "FILESIZE":
        size_val = val.split("filesize:")[1] if "filesize:" in val else val_clean
        try:
            int(size_val)  # Validate as int
            return create_indicator_item("File", "File/SizeInBytes", size_val, "integer")
        except ValueError:
            logging.warning(f"Invalid file size: {size_val}")
            return None
    elif type_detected == "SNI":
        sni_val = val.split("sni:")[1] if "sni:" in val else val_clean
        return create_indicator_item("Network", "Network/TLSClientHello/SNI", sni_val, "string")
    elif type_detected == "EMAIL":
        return create_indicator_item("Email", "Email/FromAddress", val_clean, "string")
    elif type_detected == "URL":  # New
        return create_indicator_item("Network", "Network/URI", val_clean, "string")
    elif type_detected == "PORT":  # New
        return create_indicator_item("Network", "Network/DestinationPort", val_clean, "integer")
    elif type_detected == "YARA":  # New: Basic YARA
        yara_val = val.split("yara:")[1] if "yara:" in val else val_clean
        return create_indicator_item("File", "File/YARA", yara_val, "string")
    return None

def create_ioc(indicators, author, short_desc, desc, severity="Medium", malware_family=""):
    if not indicators:
        raise ValueError("No indicators provided")
    
    root = Element("ioc", {
        "id": gen_uuid(),
        "last-modified": current_utc(),
        "version": "1.1",  # Standard OpenIOC version for Kaspersky
        "xmlns": "http://schemas.mandiant.com/2010/ioc",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xsi:schemaLocation": "http://schemas.mandiant.com/2010/ioc ioc.xsd"
    })
    
    SubElement(root, "short_description").text = short_desc
    SubElement(root, "description").text = f"{desc} | Severity: {severity} | Family: {malware_family}"
    keywords = SubElement(root, "keywords")
    SubElement(keywords, "Keyword").text = f"{malware_family} {severity}"
    SubElement(root, "authored_by").text = author
    SubElement(root, "authored_date").text = current_utc()
    links = SubElement(root, "links")
    SubElement(links, "Link", {"href": "https://otx.alienvault.com/"}).text = "OTX Reference"  # Example for TI sharing
    
    definition = SubElement(root, "definition")
    top_indicator = SubElement(definition, "Indicator", {"operator": "OR", "id": gen_uuid()})
    
    for indicator in indicators:
        if indicator is not None:
            top_indicator.append(indicator)
    
    # Pretty XML
    xml_str = tostring(root, encoding="utf-8", method="xml")
    return xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")

def create_stix_json(indicators, author, short_desc, desc, severity, malware_family):
    """Simple STIX 2.0-like JSON for Kaspersky KATA integration"""
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{gen_uuid()}",
        "objects": [
            {
                "type": "indicator",
                "id": f"indicator--{gen_uuid()}",
                "created": current_utc(),
                "modified": current_utc(),
                "name": short_desc,
                "description": desc,
                "indicator_types": ["malicious-activity"],
                "pattern": f"[file:hashes.'{indicators[0].find('Content').text}']",  # Simplified pattern
                "pattern_type": "stix",
                "valid_from": current_utc(),
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
                "labels": [malware_family, severity.lower()],
                "created_by_ref": f"identity--{gen_uuid()}"
            }
        ]
    }
    return json.dumps(stix_bundle, indent=2)

def load_indicators_from_file(filepath):
    indicators = []
    if not os.path.exists(filepath):
        logging.error(f"File not found: {filepath}")
        return indicators
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                val = line.strip()
                if not val:
                    continue
                type_detected = detect_type(val)
                if not type_detected:
                    logging.warning(f"Line {line_num}: Skipped unrecognized: {val}")
                    continue
                built = build_indicator(val, type_detected)
                if built:
                    indicators.append(built)
                else:
                    logging.warning(f"Line {line_num}: Failed to build indicator: {val}")
    except Exception as e:
        logging.error(f"Error reading file {filepath}: {e}")
    logging.info(f"Loaded {len(indicators)} indicators from {filepath}")
    return indicators

def remove_duplicates(indicators):
    """Remove duplicate indicators based on Content text"""
    seen = set()
    unique = []
    for ind in indicators:
        content = ind.find("Content").text
        if content not in seen:
            seen.add(content)
            unique.append(ind)
    return unique

def main():
    print("-------------------------------------------------------------------------")
    print("                         👑 ENHANCED IOC BUILDER 👑                      ")
    print("-------------------------------------------------------------------------")
    print("🔐 FULL IOC BUILDER (OpenIOC + STIX JSON) - Kaspersky KATA Compatible   ")
    print("Supports: Hashes, IPs, Domains, Emails, URLs, Ports, Mutex, Registry, etc.")
    print("-------------------------------------------------------------------------")

    author = input("👤 Author: ").strip() or "Unknown"
    short_desc = input("📝 Short Description: ").strip() or "Generated IOC"
    description = input("🧾 Detailed Description: ").strip() or "Auto-generated IOC"
    severity = input("🚨 Severity (Low/Medium/High): ").strip().title() or "Medium"
    malware_family = input("🧬 Malware Family (optional): ").strip() or ""

    file_input = input("\n📂 Load indicators from .txt file(s)? (y/n, comma-separate for multiple): ").lower().strip()
    indicators = []

    if file_input == "y":
        file_paths = input("📄 Enter .txt filename(s): ").strip().split(",")
        for fp in file_paths:
            fp = fp.strip()
            if fp:
                indicators.extend(load_indicators_from_file(fp))

    print("\n💡 Add manual indicators (one per line). Type 'done' to finish.\n")
    while True:
        val = input(">> ").strip()
        if val.lower() == "done":
            break
        if not val:
            continue
        type_detected = detect_type(val)
        if not type_detected:
            print("⚠️  Could not detect type. Enter a valid IOC (e.g., hash, IP, domain).")
            continue
        built = build_indicator(val, type_detected)
        if built:
            indicators.append(built)
            print(f"✅ Added: {type_detected} - {val}")
        else:
            print("⚠️  Failed to build indicator.")

    if not indicators:
        print("❌ No valid indicators entered.")
        return

    # Remove duplicates
    indicators = remove_duplicates(indicators)
    logging.info(f"Final unique indicators: {len(indicators)}")

    try:
        # Generate OpenIOC
        ioc_xml = create_ioc(indicators, author, short_desc, description, severity, malware_family)
        ioc_file = "enhanced_ioc_output.ioc"
        with open(ioc_file, "w", encoding="utf-8") as f:
            f.write(ioc_xml)
        print(f"\n✅ OpenIOC file created: {ioc_file} (Kaspersky-compatible)")

        # Generate STIX JSON for KATA
        stix_json = create_stix_json(indicators, author, short_desc, description, severity, malware_family)
        json_file = "enhanced_ioc_stix.json"
        with open(json_file, "w", encoding="utf-8") as f:
            f.write(stix_json)
        print(f"✅ STIX JSON created: {json_file} (For KATA/Advanced TI import)")

    except Exception as e:
        logging.error(f"Error generating output: {e}")
        print("❌ Failed to generate IOC. Check logs.")

if __name__ == "__main__":
    main()

