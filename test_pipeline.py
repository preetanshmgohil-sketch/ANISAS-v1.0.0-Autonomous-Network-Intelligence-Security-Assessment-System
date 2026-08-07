import asyncio
import json
import time
import sys

async def test_full_pipeline():
    from anisas.dashboard.orchestrator import create_scan, run_pipeline, get_scan

    target = '1.1.1.1'
    print(f'Testing full pipeline for {target}...')
    scan_id = create_scan(target)

    start = time.time()
    result = await run_pipeline(scan_id)
    elapsed = time.time() - start

    print(f'Pipeline completed in {elapsed:.1f}s')
    print()

    scan = get_scan(scan_id)

    for mod, info in scan['modules'].items():
        status = info['status']
        print(f'  {mod}: {status}')

    print()

    for mod_key in ['module1', 'module2', 'module3', 'module4', 'module5', 'module6']:
        data = result.get(mod_key, {})
        if 'error' in data:
            err = data['error'][:80]
            print(f'{mod_key}: ERROR - {err}')
        elif mod_key == 'module1':
            asn = data.get('asn_details', [])
            if asn:
                a = asn[0]
                print(f'{mod_key}: ASN={a.get("asn","?")} Org={a.get("organization","?")[:40]} Country={a.get("country","?")}')
            else:
                print(f'{mod_key}: NO DATA')
        elif mod_key == 'module2':
            hosts = data.get('active_hosts', [])
            subnets = data.get('discovered_subnets', [])
            topo = data.get('topology_graph', {})
            nodes = topo.get('nodes', []) if isinstance(topo, dict) else []
            print(f'{mod_key}: {len(hosts)} hosts, {len(subnets)} subnets, {len(nodes)} topo nodes')
        elif mod_key == 'module3':
            defenses = data.get('perimeter_defenses', {})
            fw = defenses.get('firewall', {}).get('detected', '?')
            ids = defenses.get('ids_ips', {}).get('detected', '?')
            print(f'{mod_key}: Firewall={fw} IDS={ids}')
        elif mod_key == 'module4':
            devs = data.get('surveillance_devices', [])
            print(f'{mod_key}: {len(devs)} devices')
        elif mod_key == 'module5':
            aps = data.get('access_points', [])
            clients = data.get('enumerated_clients', [])
            print(f'{mod_key}: {len(aps)} APs, {len(clients)} clients')
        elif mod_key == 'module6':
            summary = data.get('ai_analytics_summary', {})
            print(f'{mod_key}: devices_analyzed={summary.get("total_devices_analyzed",0)} health={summary.get("network_health_score","?")}')

    # Check logs
    logs = scan.get('logs', [])
    failed = [l for l in logs if l['status'] == 'FAILED']
    if failed:
        print('\n--- FAILED MODULES ---')
        for l in failed:
            print(f'  {l["module"]}: {l["log_message"][:100]}')

    # Dump full results for verification
    import json
    with open('pipeline_results.json', 'w') as f:
        json.dump(result, f, indent=2, default=str)
    print('\nFull results saved to pipeline_results.json')

    return scan['status'] == 'COMPLETE'

if __name__ == '__main__':
    success = asyncio.run(test_full_pipeline())
    sys.exit(0 if success else 1)
