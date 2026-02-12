# AUTHOR: RADIVAN - XV4NZ7


import uuid
import datetime
import re
from xml.etree.ElementTree import Element, SubElement, tostring
import xml.dom.minidom
import os

def gen_uuid():
    return str(uuid.uuid4())

def current_utc():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S")

def detect_type(value):
    value = value.strip()

    if value.startswith("filesize:"):
        return "FILESIZE"
    elif value.startswith("sni:"):
        return "SNI"
    elif value.startswith("mutex:"):
        return "MUTEX"
    elif value.startswith("reg:"):
        return "REGISTRY"

    if re.fullmatch(r"[a-fA-F0-9]{32}", value): return "MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value): return "SHA1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value): return "SHA256"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", value): return "IP"
    if re.fullmatch(r"([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}", value): return "DOMAIN"
    if re.fullmatch(r"[^@]+@[^@]+\.[^@]+", value): return "EMAIL"
    if "\\" in value or "/" in value:
        if value.lower().endswith((".exe", ".dll", ".bat", ".sh")):
            return "FILENAME"
        return "BINARY"
    return None

def create_indicator_item(doc, search_path, value, value_type="string", condition="is"):
    item = Element("IndicatorItem", {"id": gen_uuid(), "condition": condition})
    SubElement(item, "Context", {
        "document": doc,
        "search": search_path,
        "type": "mir"
    })
    SubElement(item, "Content", {"type": value_type}).text = value.strip()
    return item

#def build_indicator(val, type_detected):
#    if type_detected == "MD5":
#        return create_indicator_item("FileItem", "FileItem/Md5sum", val, "md5")
#    elif type_detected == "SHA1":
#        return create_indicator_item("FileItem", "FileItem/Sha1sum", val)
#    elif type_detected == "SHA256":
#        return create_indicator_item("FileItem", "FileItem/Sha256sum", val)
#    elif type_detected == "IP":
#        return create_indicator_item("ArpEntryItem", "ArpEntryItem/IPv4Address", val, "IP")
#    elif type_detected == "DOMAIN":
#        return create_indicator_item("Network", "DNSQuery.Question.Name", val)
#    elif type_detected == "FILENAME":
#        return create_indicator_item("FileItem", "FileItem/FileName", val)
#    elif type_detected == "BINARY":
#        return create_indicator_item("ProcessItem", "ProcessItem/ImagePath", val)
#    elif type_detected == "MUTEX":
#        return create_indicator_item("MutexItem", "MutexItem/Mutex", val.split("mutex:")[1])
#    elif type_detected == "REGISTRY":
#        return create_indicator_item("RegistryItem", "RegistryItem/Path", val.split("reg:")[1])
#    elif type_detected == "FILESIZE":
#        size_val = val.split("filesize:")[1]
#        return create_indicator_item("FileItem", "FileItem/SizeInBytes", size_val, value_type="int")
#    elif type_detected == "SNI":
#        return create_indicator_item("Network", "HTTPSession/SNI", val.split("sni:")[1])
#    elif type_detected == "EMAIL":
#        return create_indicator_item("EmailMessage", "EmailMessage/From", val)

def build_indicator(val, type_detected):
    if type_detected == "MD5":
        return create_indicator_item("FileItem", "FileItem/Md5sum", val, "md5")
    elif type_detected == "SHA1":
        return create_indicator_item("FileItem", "FileItem/Sha1sum", val, "sha1")
    elif type_detected == "SHA256":
        return create_indicator_item("FileItem", "FileItem/Sha256sum", val, "sha256")
    elif type_detected == "IP":
        return create_indicator_item("ArpEntryItem", "ArpEntryItem/IPv4Address", val, "IP")
    elif type_detected == "DOMAIN":
        return create_indicator_item("DnsEntryItem", "DnsEntryItem/Host", val, "string")
    elif type_detected == "FILENAME":
        return create_indicator_item("FileItem", "FileItem/FileName", val, "string")
    elif type_detected == "BINARY":
        return create_indicator_item("FileItem", "FileItem/FullPath", val, "string")
    elif type_detected == "MUTEX":
        return create_indicator_item("MutexItem", "MutexItem/Name", val.split("mutex:")[1], "string")
    elif type_detected == "REGISTRY":
        return create_indicator_item("RegistryItem", "RegistryItem/Path", val.split("reg:")[1], "string")
    elif type_detected == "FILESIZE":
        size_val = val.split("filesize:")[1]
        return create_indicator_item("FileItem", "FileItem/SizeInBytes", size_val, value_type="int")
    elif type_detected == "SNI":
        return create_indicator_item("Network", "Network/SNI", val.split("sni:")[1], "string")
    elif type_detected == "EMAIL":
        return create_indicator_item("EmailMessage", "EmailMessage/From", val, "string")


def create_ioc(indicators, author, short_desc, desc, severity="Medium", malware_family=""):
    root = Element("ioc", {
        "id": gen_uuid(),
        "last-modified": current_utc(),
        "xmlns": "http://schemas.mandiant.com/2010/ioc",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        "xmlns:xsd": "http://www.w3.org/2001/XMLSchema"
    })

    SubElement(root, "short_description").text = short_desc
    SubElement(root, "description").text = f"{desc} | Severity: {severity} | Family: {malware_family}"
    SubElement(root, "keywords")
    SubElement(root, "authored_by").text = author
    SubElement(root, "authored_date").text = current_utc()
    SubElement(root, "links")

    definition = SubElement(root, "definition")
    top_indicator = SubElement(definition, "Indicator", {
        "operator": "OR", "id": gen_uuid()
    })

    for indicator in indicators:
        top_indicator.append(indicator)

    xml_str = tostring(root, encoding="utf-8")
    return xml.dom.minidom.parseString(xml_str).toprettyxml(indent="  ")

def load_indicators_from_file(filepath):
    indicators = []
    if not os.path.exists(filepath):
        print(f"❌ File not found: {filepath}")
        return indicators
    with open(filepath, "r") as f:
        for line in f:
            val = line.strip()
            if not val:
                continue
            type_detected = detect_type(val)
            if not type_detected:
                print(f"⚠️  Skipped unrecognized: {val}")
                continue
            indicators.append(build_indicator(val, type_detected))
    return indicators

def main():
    print("-------------------------------------------------------------------------")
    print("                         👑 OWNED BY XV4NZ7 👑                           ")
    print("-------------------------------------------------------------------------")
    print("🔐 FULL IOC BUILDER (hashes, IPs, domains, emails, mutex, registry, etc)")
    print("-------------------------------------------------------------------------")

    author = input("👤 Author: ")
    short_desc = input("📝 Short Description: ")
    description = input("🧾 Detailed Description: ")
    severity = input("🚨 Severity (Low/Medium/High): ")
    malware_family = input("🧬 Malware Family (optional): ")

    file_input = input("\n📂 Load indicators from .txt file? (y/n): ").lower()
    indicators = []

    if file_input == "y":
        file_path = input("📄 Enter .txt filename: ").strip()
        indicators += load_indicators_from_file(file_path)

    print("\n💡 You can also add more indicators manually. Type 'done' to finish.\n")
    while True:
        val = input(">> ").strip()
        if val.lower() == "done":
            break
        type_detected = detect_type(val)
        if not type_detected:
            print("⚠️  Could not detect type. Skipped.")
            continue
        indicators.append(build_indicator(val, type_detected))

    if not indicators:
        print("❌ No valid indicators entered.")
        return

    output = create_ioc(indicators, author, short_desc, description, severity, malware_family)
    out_file = "full_ioc_output.ioc"
    with open(out_file, "w") as f:
        f.write(output)

    print(f"\n✅ IOC file created: {out_file}")

if __name__ == "__main__":
    main()

