import json

with open("pipeline_results.json") as f:
    d = json.load(f)

m1 = d["module1"]
a = m1["asn_details"][0]
print(f"M1: ASN={a['asn']} Org={a['organization'][:50]} Country={a['country']}")
print(f"    ISP={m1['isp_profile']['name'][:50]}")
print(f"    Risk={m1['ai_risk_summary']['risk_level']} ({m1['ai_risk_summary']['risk_score']})")

m2 = d["module2"]
hosts = m2["active_hosts"]
print(f"M2: {len(hosts)} hosts")
for h in hosts:
    print(f"    IP={h['ip_address']} Method={h['discovery_method']}")

m3 = d["module3"]
defs = m3["perimeter_defenses"]
print(f"M3: FW={defs['firewall']['detected']} IDS={defs['ids_ips']['detected']} WAF={defs['waf']['detected']}")
print(f"    Risk={m3['overall_security_posture']['risk_level']}")

m4 = d["module4"]
print(f"M4: {len(m4['surveillance_devices'])} devices")

m5 = d["module5"]
print(f"M5: {len(m5['access_points'])} APs, {len(m5['enumerated_clients'])} clients")
print(f"    Auth={m5['authentication_analysis']['primary_auth_method']}")

m6 = d["module6"]
s = m6["ai_analytics_summary"]
print(f"M6: devices={s['total_devices_analyzed']} health={s['network_health_score']}")
if m6["device_classifications"]:
    c = m6["device_classifications"][0]
    print(f"    Device: {c['predicted_device_type']} ({c['predicted_os']}) risk={c['risk_category']}")
