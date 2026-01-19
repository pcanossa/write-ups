import json
import re
from pathlib import Path

json_file = Path("decoded_formatted.json")
html_file = Path("../html/Index-home.html")

TOKEN_REGEX = re.compile(r"[a-zA-Z0-9_\-]{4,}")

def extract_strings_from_json(obj):
    strings = set()
    if isinstance(obj, dict):
        for v in obj.values():
            strings |= extract_strings_from_json(v)
    elif isinstance(obj, list):
        for i in obj:
            strings |= extract_strings_from_json(i)
    elif isinstance(obj, str):
        strings |= set(TOKEN_REGEX.findall(obj.lower()))
    return strings

with json_file.open(encoding="utf-8", errors="ignore") as f:
    json_data = json.load(f)

json_strings = extract_strings_from_json(json_data)

html_content = html_file.read_text(encoding="utf-8", errors="ignore").lower()
html_strings = set(TOKEN_REGEX.findall(html_content))

common_strings = sorted(json_strings & html_strings)

total_correlations = f"[+] Strings correlacionadas: {len(common_strings)}\n"
print(total_correlations)

relatorio_path = Path("correlation_report.txt")
with relatorio_path.open("w", encoding="utf-8") as report:
    report.write(total_correlations)
    for s in common_strings:
        if s in html_content:
            report.write(f"\n=== {s} ===\n")
            print(f"\n=== {s} ===")
            for i, line in enumerate(html_content.splitlines(), 1):
                if s in line:
                    report.write(f"Linha {i}: {line.strip()}\n")
                    print(f"Linha {i}: {line.strip()}")
