# Author: Radivan - XV4NZ7

import re

def validate_yara(yara_text):
    # Very basic checks — for deeper validation use `yara-python` module
    required_sections = ["rule", "strings:", "condition:"]
    for section in required_sections:
        if section not in yara_text:
            return False, f"Missing required section: {section}"
    return True, "Basic structure looks good."

def save_yara_file(yara_text, filename="0x__ransomware.yara"):
    with open(filename, "w") as f:
        f.write(yara_text)
    print(f"✅ YARA rule saved to: {filename}")
    print("📤 You can now import this file into Kaspersky Security Center.")

def main():
    print("📥 Paste your full YARA rule below (end with a line 'done'):")
    yara_lines = []
    while True:
        line = input()
        if line.strip().lower() == "done":
            break
        yara_lines.append(line)

    yara_text = "\n".join(yara_lines)
    valid, message = validate_yara(yara_text)

    if not valid:
        print(f"❌ Error: {message}")
        return

    save_yara_file(yara_text)

if __name__ == "__main__":
    main()

