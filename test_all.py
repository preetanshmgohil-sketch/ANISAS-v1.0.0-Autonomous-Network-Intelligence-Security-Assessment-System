import asyncio
import json
import sys

# Test Module 1
print("=" * 60)
print("MODULE 1: ASN & ISP Intelligence")
print("=" * 60)
try:
    from anisas.engine import run_engine
    m1 = asyncio.run(run_engine("1.1.1.1"))
    d1 = m1.model_dump()
    print(f"  ASN: {d1['asn_details'][0].get('asn') if d1.get('asn_details') else 'EMPTY'}")
    print(f"  Org: {d1['asn_details'][0].get('organization') if d1.get('asn_details') else 'EMPTY'}")
    print(f"  Country: {d1['asn_details'][0].get('country') if d1.get('asn_details') else 'EMPTY'}")
    print(f"  Registry: {d1['asn_details'][0].get('registry') if d1.get('asn_details') else 'EMPTY'}")
    print(f"  ISP: {d1.get('isp_profile', {}).get('name')}")
    print(f"  Abuse: {d1.get('isp_profile', {}).get('abuse_contact')}")
    print(f"  Prefixes: {d1.get('ip_prefixes')}")
    print(f"  Risk: {d1.get('ai_risk_summary', {}).get('risk_level')} {d1.get('ai_risk_summary', {}).get('risk_score')}")
except Exception as e:
    print(f"  FAILED: {e}")

# Test Module 2
print()
print("=" * 60)
print("MODULE 2: Network Reconnaissance")
print("=" * 60)
try:
    from anisas.recon.engine import NetworkReconEngine
    m2_engine = NetworkReconEngine()
    m2 = m2_engine.run("1.1.1.0/30")
    d2 = m2.model_dump()
    print(f"  Subnets: {len(d2.get('discovered_subnets', []))}")
    print(f"  Hosts: {len(d2.get('active_hosts', []))}")
    for h in d2.get('active_hosts', [])[:3]:
        print(f"    {h.get('ip_address')} - {h.get('status')} - ports: {len(h.get('open_ports', []))}")
    print(f"  Metadata: {d2.get('scan_metadata', {}).get('total_hosts_found')} hosts, {d2.get('scan_metadata', {}).get('scan_duration_seconds')}s")
except Exception as e:
    print(f"  FAILED: {e}")

# Test Module 3
print()
print("=" * 60)
print("MODULE 3: Security Perimeter Detection")
print("=" * 60)
try:
    from anisas.perimeter.engine import SecurityPerimeterEngine
    m3_engine = SecurityPerimeterEngine()
    m3 = m3_engine.run("1.1.1.1")
    d3 = m3.model_dump()
    defs = d3.get('perimeter_defenses', {})
    print(f"  Firewall: {defs.get('firewall', {}).get('detected')} - {defs.get('firewall', {}).get('type')}")
    print(f"  IDS/IPS: {defs.get('ids_ips', {}).get('detected')} - {defs.get('ids_ips', {}).get('action_observed')}")
    print(f"  DMZ: {defs.get('dmz', {}).get('detected')} - {defs.get('dmz', {}).get('exposure_boundary')}")
    print(f"  WAF: {defs.get('waf', {}).get('detected')} - {defs.get('waf', {}).get('vendor')}")
    print(f"  Posture: {d3.get('overall_security_posture', {}).get('risk_level')}")
except Exception as e:
    print(f"  FAILED: {e}")

# Test Module 4
print()
print("=" * 60)
print("MODULE 4: IoT/Surveillance Fingerprinting")
print("=" * 60)
try:
    from anisas.iot.engine import IoTSurveillanceEngine
    m4_engine = IoTSurveillanceEngine()
    m4 = m4_engine.run("1.1.1.0/30")
    d4 = m4.model_dump()
    print(f"  Devices: {len(d4.get('surveillance_devices', []))}")
    for dev in d4.get('surveillance_devices', [])[:3]:
        print(f"    {dev.get('ip_address')} - {dev.get('classification')} - {dev.get('identified_vendor')}")
    print(f"  Summary: {d4.get('summary')}")
except Exception as e:
    print(f"  FAILED: {e}")

# Test Module 5
print()
print("=" * 60)
print("MODULE 5: Wireless Network Intelligence")
print("=" * 60)
try:
    from anisas.wireless.engine import WirelessIntelligenceEngine
    m5_engine = WirelessIntelligenceEngine()
    m5 = m5_engine.run()
    d5 = m5.model_dump()
    print(f"  APs: {len(d5.get('access_points', []))}")
    for ap in d5.get('access_points', [])[:3]:
        print(f"    {ap.get('ssid')} - {ap.get('bssid')} - {ap.get('encryption_type')}")
    print(f"  Clients: {len(d5.get('enumerated_clients', []))}")
    auth = d5.get('authentication_analysis', {})
    print(f"  Auth: {auth.get('primary_auth_method')}")
    print(f"  Anomalies: {len(d5.get('ai_anomaly_detection', {}).get('anomalous_devices_flagged', []))}")
except Exception as e:
    print(f"  FAILED: {e}")

# Test Module 6
print()
print("=" * 60)
print("MODULE 6: AI/ML Analytics Engine")
print("=" * 60)
try:
    from anisas.ai_engine.engine import AIMLEngine
    m6_engine = AIMLEngine()
    m6 = m6_engine.run(module_data={"module1": d1, "module2": d2, "module3": d3, "module4": d4, "module5": d5})
    d6 = m6.model_dump()
    print(f"  Devices: {d6.get('ai_analytics_summary', {}).get('total_devices_analyzed')}")
    print(f"  Anomalies: {d6.get('ai_analytics_summary', {}).get('anomalies_detected_count')}")
    print(f"  Health: {d6.get('ai_analytics_summary', {}).get('network_health_score')}")
    print(f"  Classifications: {len(d6.get('device_classifications', []))}")
    print(f"  Executive: {d6.get('executive_nl_summary', {}).get('overview_paragraph', '')[:100]}...")
except Exception as e:
    print(f"  FAILED: {e}")

print()
print("=" * 60)
print("ALL MODULES TESTED")
print("=" * 60)
