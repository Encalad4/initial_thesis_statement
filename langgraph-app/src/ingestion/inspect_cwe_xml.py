#langgraph-app\src\ingestion\inspect_cwe_xml.py

import xml.etree.ElementTree as ET
from pathlib import Path

xml_path = Path("datasets\cwec_v4.19.1.xml")

tree = ET.parse(xml_path)
root = tree.getroot()

print("ROOT TAG:", root.tag)
print("ROOT ATTRS:", root.attrib)

for child in root[:10]:
    print("CHILD TAG:", child.tag)

ns_uri = root.tag[root.tag.find("{") + 1 : root.tag.find("}")]
print("NAMESPACE URI:", ns_uri)

weaknesses = root.find(f"{{{ns_uri}}}Weaknesses")
print("WEAKNESSES TAG:", weaknesses.tag if weaknesses is not None else None)

if weaknesses is not None:
    first = list(weaknesses)[0]
    print("FIRST WEAKNESS TAG:", first.tag)
    print("FIRST WEAKNESS ATTRS:", first.attrib)

    for elem in list(first)[:15]:
        print("  SUBTAG:", elem.tag)