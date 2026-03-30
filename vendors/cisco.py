from __future__ import annotations

from typing import Any, Optional

from .common import substitute_params


def find_cisco_arp_interface_by_vlan(output: str, vlan: str) -> Optional[str]:
    """
    Найти один интерфейс из вывода `sh arp | include <vlan>`, соответствующий VLAN.
    VLAN берём как число после последней точки в имени интерфейса:
    `GigabitEthernet0/0/1.1255` -> 1255.
    """
    vlan_req = str(vlan).strip()
    if not vlan_req.isdigit():
        return None
    vlan_req_int = int(vlan_req)

    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Protocol"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue

        iface = parts[-1]
        if "." not in iface:
            continue
        suffix = iface.rsplit(".", 1)[-1]
        if suffix.isdigit() and int(suffix) == vlan_req_int:
            return iface

    return None


def filter_cisco_arp_output_by_interface(output: str, interface: str) -> str:
    """
    Оставить только строки ARP, где последняя колонка (интерфейс)
    строго равна заданному interface.
    """
    iface_req = (interface or "").strip()
    if not iface_req:
        return ""

    kept: list[str] = []
    for raw in (output or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("Protocol"):
            continue
        parts = line.split()
        if parts and parts[-1] == iface_req:
            kept.append(line)
    return "\n".join(kept)


def run_cisco_arp_clear_then_show(
    conn: Any,
    params: dict[str, Any],
    full_output_lines: list[str],
    read_timeout: int = 120,
) -> None:
    """
    Макрос:
    - sh arp | include {vlan}
    - один раз находит интерфейс по VLAN
    - логирует только строки этого интерфейса
    - clear arp-cache int <interface> 8 раз
    - повторяет sh arp | include {vlan} и логирует строки того же интерфейса
    """
    vlan = str(params.get("client_vlan", "") or params.get("vlan", ""))
    arp_cmd = substitute_params("sh arp | include {vlan}", params)
    full_output_lines.append(f"\n--- Команда: {arp_cmd} ---\n")

    out = conn.send_command(arp_cmd, read_timeout=read_timeout)
    interface = find_cisco_arp_interface_by_vlan(out, vlan)
    if not interface:
        full_output_lines.append(
            f"(после команды sh arp | include {vlan}: подходящий интерфейс не найден, clear не выполняется)\n"
        )
        return

    filtered = filter_cisco_arp_output_by_interface(out, interface)
    if filtered.strip():
        full_output_lines.append(filtered)

    clear_cmd = f"clear arp-cache int {interface}"
    full_output_lines.append(f"\n--- Выполняем 8×: {clear_cmd} ---\n")
    for i in range(8):
        full_output_lines.append(f"  [{i + 1}/8] ")
        o = conn.send_command(clear_cmd, read_timeout=read_timeout)
        full_output_lines.append(o.strip() or "(ok)")

    full_output_lines.append(f"\n--- Команда: {arp_cmd} (повторно) ---\n")
    out2 = conn.send_command(arp_cmd, read_timeout=read_timeout)
    filtered2 = filter_cisco_arp_output_by_interface(out2, interface)
    if filtered2.strip():
        full_output_lines.append(filtered2)

