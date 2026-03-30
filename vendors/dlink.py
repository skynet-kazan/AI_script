from __future__ import annotations

import re
import time
from typing import Any

from vendors.mac_table import extract_unique_macs_from_cli_table

POST_ENABLE_DELAY_SEC = 5


def dlink_port_is_enabled(show_ports_output: str, port: str) -> bool:
    """
    Определяет по выводу `show ports <port>`, что порт имеет состояние Enabled.

    Используется для DES-коммутаторов (D-Link).
    """
    port = str(port).strip()
    if not port:
        return False

    port_re = re.compile(r"\{\s*" + re.escape(port) + r"\b", re.IGNORECASE)
    for line in show_ports_output.splitlines():
        if port_re.search(line) and "enabled" in line.lower():
            if "[ enabled ]" in line.lower() or "enabled" in line.lower():
                return True
        if port in line and "Enabled" in line:
            return True

    return False


def is_dlink_state_enable_command(device_type: str, cmd_lower: str) -> bool:
    return (
        device_type == "dlink_ds"
        and cmd_lower.startswith("config ports")
        and "state enable" in cmd_lower
    )


def is_dlink_show_fdb_vlan_command(device_type: str, cmd_lower: str) -> bool:
    return device_type == "dlink_ds" and cmd_lower.startswith("show fdb vlan")


def dlink_run_fdb_vlan_mac_poll(conn: Any, cmd: str, read_timeout: int) -> str:
    """До 20 попыток раз в 1 с, пока в выводе не будет ровно 2 уникальных MAC."""
    last_out = ""
    final_out = ""
    for attempt in range(20):
        out_i = conn.send_command(cmd, read_timeout=read_timeout)
        last_out = out_i
        if len(extract_unique_macs_from_cli_table(out_i)) == 2:
            final_out = out_i
            break
        if attempt < 19:
            time.sleep(1)
    return final_out if final_out else last_out


def dlink_post_state_enable_flow(
    conn: Any,
    enable_cmd: str,
    actual_port: str,
    read_timeout: int,
) -> bool:
    """
    После `config ports … state enable`: пауза, show ports, при необходимости один повтор enable.
    Возвращает True, если порт в Enabled (для последующего опроса FDB).
    """
    time.sleep(POST_ENABLE_DELAY_SEC)
    show_ports_cmd = f"show ports {actual_port}"
    check_out = conn.send_command(show_ports_cmd, read_timeout=read_timeout)
    port_enabled = dlink_port_is_enabled(check_out, actual_port)
    if not port_enabled:
        conn.send_command(enable_cmd, read_timeout=read_timeout)
        time.sleep(POST_ENABLE_DELAY_SEC)
        check_out = conn.send_command(show_ports_cmd, read_timeout=read_timeout)
        port_enabled = dlink_port_is_enabled(check_out, actual_port)
    return port_enabled
