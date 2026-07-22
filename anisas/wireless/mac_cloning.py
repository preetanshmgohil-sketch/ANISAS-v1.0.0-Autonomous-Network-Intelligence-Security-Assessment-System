"""MAC address cloning proof-of-concept for authorized lab environments."""

from __future__ import annotations

import logging
import platform
import subprocess

logger = logging.getLogger(__name__)


def _get_default_interface() -> str:
    """Get the default network interface name."""
    system = platform.system().lower()
    try:
        if system == "linux":
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "dev" in line:
                    parts = line.split()
                    dev_idx = parts.index("dev")
                    if dev_idx + 1 < len(parts):
                        return parts[dev_idx + 1]
            return "eth0"
        elif system == "windows":
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "Connected" in line and "Dedicated" in line:
                    parts = line.split()
                    return parts[-1] if parts else "Ethernet"
            return "Ethernet"
        elif system == "darwin":
            result = subprocess.run(
                ["route", "get", "default"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "interface:" in line:
                    return line.split(":")[-1].strip()
            return "en0"
    except Exception:
        pass
    return "eth0"


def _get_current_mac(interface: str) -> str | None:
    """Get the current MAC address of an interface."""
    system = platform.system().lower()
    try:
        if system == "linux":
            result = subprocess.run(
                ["ip", "link", "show", interface],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "link/ether" in line:
                    return line.split("link/ether")[1].strip().split()[0]
        elif system == "windows":
            result = subprocess.run(
                ["getmac", "/fo", "csv", "/nh"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.strip('"').split('","')
                if len(parts) >= 3:
                    return parts[1].replace("-", ":")
        elif system == "darwin":
            result = subprocess.run(
                ["ifconfig", interface],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                if "ether" in line:
                    return line.split("ether")[1].strip()
    except Exception:
        pass
    return None


def clone_mac(
    target_mac: str,
    interface: str | None = None,
    dry_run: bool = True,
) -> dict:
    """Clone a MAC address on a network interface.

    WARNING: This modifies network interface configuration.
    Must only be run in authorized lab environments.

    Args:
        target_mac: MAC address to clone to.
        interface: Network interface (auto-detected if None).
        dry_run: If True, only simulate the operation.

    Returns dict with success, original_mac, interface_used, details.
    """
    if interface is None:
        interface = _get_default_interface()

    original_mac = _get_current_mac(interface) or "unknown"

    result = {
        "target_mac": target_mac,
        "original_mac": original_mac,
        "lab_interface_used": interface,
        "cloning_successful": False,
        "access_granted_post_clone": False,
        "dry_run": dry_run,
        "details": "",
    }

    if dry_run:
        result["details"] = (
            f"DRY RUN: Would clone MAC {original_mac} -> {target_mac} on interface {interface}. "
            f"Actual cloning requires --no-dry-run flag and admin privileges."
        )
        return result

    system = platform.system().lower()

    try:
        if system == "linux":
            # Bring interface down
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "down"],
                capture_output=True, timeout=5,
            )
            # Set new MAC
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "address", target_mac],
                capture_output=True, timeout=5,
            )
            # Bring interface up
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                capture_output=True, timeout=5,
            )
            new_mac = _get_current_mac(interface)
            result["cloning_successful"] = (new_mac or "").lower() == target_mac.lower()
            result["details"] = f"MAC cloned on Linux interface {interface}."

        elif system == "windows":
            # Windows requires registry modification
            result["details"] = (
                "Windows MAC cloning requires registry modification. "
                "Use Device Manager -> Network Adapter -> Advanced -> Network Address."
            )
            result["cloning_successful"] = False

        elif system == "darwin":
            subprocess.run(
                ["sudo", "ifconfig", interface, "ether", target_mac],
                capture_output=True, timeout=5,
            )
            new_mac = _get_current_mac(interface)
            result["cloning_successful"] = (new_mac or "").lower() == target_mac.lower()
            result["details"] = f"MAC cloned on macOS interface {interface}."

    except Exception as e:
        result["details"] = f"Clone failed: {e}"

    return result


def restore_mac(interface: str | None = None, original_mac: str | None = None) -> bool:
    """Restore original MAC address after cloning test.

    Safety routine to restore default configuration.
    """
    if interface is None:
        interface = _get_default_interface()

    if original_mac:
        return clone_mac(original_mac, interface, dry_run=False)["cloning_successful"]

    system = platform.system().lower()
    try:
        if system == "linux":
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "down"],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "address", "random"],
                capture_output=True, timeout=5,
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                capture_output=True, timeout=5,
            )
            return True
    except Exception:
        pass
    return False
