import asyncio
import time

async def test():
    from anisas.dashboard.orchestrator import create_scan, run_pipeline, get_scan
    
    target = "117.254.227.27"
    print(f"Testing {target}...")
    scan_id = create_scan(target)
    start = time.time()
    result = await run_pipeline(scan_id)
    elapsed = time.time() - start
    
    scan = get_scan(scan_id)
    all_complete = all(m["status"] == "COMPLETE" for m in scan["modules"].values())
    
    for mod, info in scan["modules"].items():
        status = info["status"]
        print(f"  {mod}: {status}")
    
    print(f"All complete: {all_complete}")
    print(f"Time: {elapsed:.1f}s")

asyncio.run(test())
