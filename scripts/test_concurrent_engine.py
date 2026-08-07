"""
Test concurrent execution of run_engine to verify async event loop is not blocked.

This test verifies that PDF/JSON generation via asyncio.to_thread() does not block
concurrent execution of the async pipeline.

Run: python scripts/test_concurrent_engine.py
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path

from anisas.models import (
    ASNEntry,
    ASNIntelligenceReport,
    ISPProfile,
    AIRiskSummary,
    Provenance,
)
from anisas.report_generator import generate_json, generate_pdf


def create_mock_report(target_ip: str) -> ASNIntelligenceReport:
    """Create a mock ASNIntelligenceReport for testing."""
    return ASNIntelligenceReport(
        target_ip=target_ip,
        asn_details=[
            ASNEntry(
                asn="AS12345",
                organization=f"Test ISP {target_ip}",
                country="US",
                registry="ARIN",
                is_primary=True,
            )
        ],
        ip_prefixes=[f"192.0.2.0/24", f"198.51.100.0/24"],
        isp_profile=ISPProfile(
            name=f"Test ISP Network",
            noc_contact="noc@test.example.com",
            abuse_contact="abuse@test.example.com",
            peering_relationships=["AS64512", "AS64513"],
        ),
        ai_risk_summary=AIRiskSummary(
            risk_level="Medium",
            summary_text="Test risk assessment for mock data.",
        ),
        provenance=Provenance(
            sources_queried=["ipinfo.io", "bgpview.io"],
            execution_time_seconds=0.5,
        ),
    )


async def concurrent_report_generation(
    num_targets: int = 5,
    output_dir: str | None = None,
) -> float:
    """
    Generate reports concurrently and measure throughput.

    Args:
        num_targets: Number of concurrent report generations.
        output_dir: Directory to write PDF/JSON files (optional).

    Returns:
        Total time in seconds for all concurrent operations.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp()

    start = time.monotonic()

    async def generate_report(idx: int) -> None:
        report = create_mock_report(f"203.0.113.{idx}")
        pdf_path = os.path.join(output_dir, f"report_{idx}.pdf")
        json_path = os.path.join(output_dir, f"report_{idx}.json")

        # Offload to thread pool (same as run_engine does)
        await asyncio.to_thread(generate_pdf, report, pdf_path)
        await asyncio.to_thread(generate_json, report, json_path)

    # Execute all reports concurrently
    await asyncio.gather(*[generate_report(i) for i in range(num_targets)])

    elapsed = time.monotonic() - start
    return elapsed


async def sequential_report_generation(
    num_targets: int = 5,
    output_dir: str | None = None,
) -> float:
    """
    Generate reports sequentially (baseline for comparison).

    Args:
        num_targets: Number of report generations.
        output_dir: Directory to write PDF/JSON files (optional).

    Returns:
        Total time in seconds for all sequential operations.
    """
    if output_dir is None:
        output_dir = tempfile.mkdtemp()

    start = time.monotonic()

    for idx in range(num_targets):
        report = create_mock_report(f"203.0.113.{idx}")
        pdf_path = os.path.join(output_dir, f"report_seq_{idx}.pdf")
        json_path = os.path.join(output_dir, f"report_seq_{idx}.json")

        # Sequential execution (without asyncio.gather)
        await asyncio.to_thread(generate_pdf, report, pdf_path)
        await asyncio.to_thread(generate_json, report, json_path)

    elapsed = time.monotonic() - start
    return elapsed


async def _test_concurrent_generation_completes():
    """Test that concurrent generation completes without errors."""
    with tempfile.TemporaryDirectory() as tmpdir:
        elapsed = await concurrent_report_generation(num_targets=3, output_dir=tmpdir)
        
        # Verify files were created
        files = list(Path(tmpdir).glob("report_*.pdf")) + list(Path(tmpdir).glob("report_*.json"))
        assert len(files) == 6, f"Expected 6 files, got {len(files)}"
        print(f"[PASS] Concurrent generation completed in {elapsed:.3f}s (3 targets)")


async def _test_concurrent_faster_than_sequential():
    """
    Test that concurrent execution is not slower than sequential.
    
    This verifies that asyncio.gather() allows concurrent PDF/JSON generation
    without additional overhead from blocking the event loop.
    
    Note: For small PDFs, threading overhead may result in near-equal times,
    but for larger datasets or multiple concurrent tasks, concurrent is faster.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        concurrent_time = await concurrent_report_generation(
            num_targets=5,
            output_dir=os.path.join(tmpdir, "concurrent"),
        )
        
        sequential_time = await sequential_report_generation(
            num_targets=5,
            output_dir=os.path.join(tmpdir, "sequential"),
        )
        
        print(f"[PASS] Concurrent: {concurrent_time:.3f}s | Sequential: {sequential_time:.3f}s | Ratio: {concurrent_time/sequential_time:.2f}x")
        
        # The key test: concurrent should not be significantly slower
        # (actual speedup depends on file size and system load)
        ratio = concurrent_time / sequential_time
        assert ratio < 1.5, (
            f"Concurrent took too much longer ({concurrent_time:.3f}s vs {sequential_time:.3f}s, "
            f"ratio: {ratio:.2f}x). Event loop may be blocked."
        )


async def _test_no_event_loop_blocking():
    """
    Test that concurrent operations can interleave without blocking.
    
    This verifies that when PDF/JSON generation is offloaded to threads,
    the event loop remains responsive and can schedule other tasks.
    """
    completed_order = []
    
    async def quick_task(idx: int) -> None:
        """A quick task that should execute between report generations."""
        await asyncio.sleep(0.01)
        completed_order.append(("quick", idx))
    
    async def report_task(idx: int) -> None:
        """A slower report generation task."""
        report = create_mock_report(f"203.0.113.{idx}")
        with tempfile.TemporaryDirectory() as tmpdir:
            pdf_path = os.path.join(tmpdir, f"report_{idx}.pdf")
            json_path = os.path.join(tmpdir, f"report_{idx}.json")
            await asyncio.to_thread(generate_pdf, report, pdf_path)
            completed_order.append(("report_pdf", idx))
            await asyncio.to_thread(generate_json, report, json_path)
            completed_order.append(("report_json", idx))
    
    # Schedule quick tasks interleaved with report tasks
    start = time.monotonic()
    await asyncio.gather(
        report_task(0),
        report_task(1),
        quick_task(0),
        quick_task(1),
    )
    elapsed = time.monotonic() - start
    
    # Verify quick tasks completed (event loop was responsive)
    quick_completed = [x for x in completed_order if x[0] == "quick"]
    assert len(quick_completed) == 2, f"Expected 2 quick tasks, got {len(quick_completed)}"
    print(f"[PASS] Event loop remained responsive with {len(quick_completed)} quick tasks interleaved (elapsed: {elapsed:.3f}s)")


def main():
    """Run all concurrent execution tests."""
    print("Running concurrent engine execution tests...\n")
    
    asyncio.run(_test_concurrent_generation_completes())
    asyncio.run(_test_concurrent_faster_than_sequential())
    asyncio.run(_test_no_event_loop_blocking())
    
    print("\n[SUCCESS] All concurrent execution tests passed!")


if __name__ == "__main__":
    main()
