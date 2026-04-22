# langgraph-app\src\ingestion\preview_cwe_core.py
import xml.etree.ElementTree as ET
from pathlib import Path

XML_PATH = Path("datasets/cwec_v4.19.1.xml")


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = " ".join(value.split())
    return value if value else None


def get_text(elem, tag, ns):
    child = elem.find(f"cwe:{tag}", ns)
    if child is None:
        return None
    return clean_text("".join(child.itertext()))


def main():
    tree = ET.parse(XML_PATH)
    root = tree.getroot()

    ns_uri = root.tag[root.tag.find("{") + 1 : root.tag.find("}")]
    ns = {"cwe": ns_uri}

    weaknesses = root.find("cwe:Weaknesses", ns)
    if weaknesses is None:
        raise RuntimeError("Could not find <Weaknesses> section in XML.")

    rows = []

    for weakness in weaknesses.findall("cwe:Weakness", ns):
        cwe_id = f"CWE-{weakness.attrib['ID']}"
        row = {
            "id": cwe_id,
            "name": clean_text(weakness.attrib.get("Name")),
            "description": get_text(weakness, "Description", ns),
            "extended_description": get_text(weakness, "Extended_Description", ns),
            "abstraction": clean_text(weakness.attrib.get("Abstraction")),
            "status": clean_text(weakness.attrib.get("Status")),
        }
        rows.append(row)

    print("TOTAL CWE WEAKNESSES:", len(rows))
    print()

    for row in rows[:3]:
        print("=" * 80)
        for key, value in row.items():
            print(f"{key}: {value}")
        print()

if __name__ == "__main__":
    main()