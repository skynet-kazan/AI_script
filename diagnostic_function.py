"""
Общие примитивы диагностики: подстановка параметров, парсинг MAC, отправка команд Netmiko,
макросы Cisco ARP, логика D-Link и Raisecom/ISCOM.
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional

# --- Общее ---


def substitute_params(command: str, params: dict[str, Any]) -> str:
    """Подставляет в строку команды значения из словаря вместо плейсхолдеров {ключ}."""
    for key, value in params.items():
        command = command.replace("{" + key + "}", str(value))
    return command


def extract_unique_macs_from_cli_table(output: str) -> set[str]:
    """Из вывода таблицы MAC (fdb / l2) извлекает MAC и возвращает множество уникальных (lower)."""
    dot_mac_re = re.compile(r"\b[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\b")
    colon_mac_re = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")
    macs: set[str] = set()
    for m in dot_mac_re.findall(output or ""):
        macs.add(m.lower())
    for m in colon_mac_re.findall(output or ""):
        macs.add(m.lower())
    return macs


def netmiko_send_adaptive(
    conn: Any,
    cmd: str,
    *,
    device_type: str,
    use_timing: bool,
    expect_string: Optional[str],
    read_timeout: int,
) -> str:
    """Обычная отправка команды: timing для cisco_ios / raisecom_telnet, иначе send_command."""
    if use_timing:
        last_read = 3.0 if device_type == "raisecom_telnet" else 2.5
        return conn.send_command_timing(
            cmd,
            last_read=last_read,
            read_timeout=read_timeout,
            strip_prompt=False,
            strip_command=False,
        )
    kwargs: dict[str, Any] = {"read_timeout": read_timeout}
    if expect_string:
        kwargs["expect_string"] = expect_string
    if device_type in ("raisecom_roap", "raisecom_telnet"):
        kwargs["delay_factor"] = 2
    return conn.send_command(cmd, **kwargs)


# --- Cisco ARP ---


def find_cisco_arp_interface_by_vlan(
    output: str, vlan: str, outer_vlan: str | None = None
) -> Optional[str]:
    """
    Ищет интерфейс в выводе sh arp по суффиксу subinterface.

    Без OuterVlan: TenGigabitEthernet0/1/0.1006 — суффикс равен основному VLAN.
    С OuterVlan: TenGigabitEthernet0/1/0.30011006 — 4 цифры OuterVlan + основной VLAN.
    """
    main_vlan = str(vlan).strip()
    if not main_vlan.isdigit():
        return None
    outer = str(outer_vlan or "").strip()
    if outer:
        if not outer.isdigit():
            return None
        expected_suffix = f"{outer}{main_vlan}"
    else:
        expected_suffix = main_vlan

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
        if not suffix.isdigit():
            continue
        if outer:
            if suffix == expected_suffix:
                return iface
        elif int(suffix) == int(main_vlan):
            return iface
    return None


def filter_cisco_arp_output_by_interface(output: str, interface: str) -> str:
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
    vlan = str(params.get("client_vlan", "") or params.get("vlan", ""))
    outer_vlan = str(params.get("outer_vlan", "") or "").strip() or None
    arp_cmd = substitute_params("sh arp | include {vlan}", params)
    full_output_lines.append(f"\n--- Команда: {arp_cmd} ---\n")
    out = conn.send_command(arp_cmd, read_timeout=read_timeout)
    interface = find_cisco_arp_interface_by_vlan(out, vlan, outer_vlan=outer_vlan)
    if not interface:
        if outer_vlan:
            hint = f"outer={outer_vlan}, vlan={vlan} (ожидается .{outer_vlan}{vlan})"
        else:
            hint = f"vlan={vlan}"
        full_output_lines.append(
            f"(после команды sh arp | include {vlan}: подходящий интерфейс не найден "
            f"({hint}), clear не выполняется)\n"
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


def handle_cisco_arp_clear_then_show_command(
    conn: Any,
    *,
    host: str,
    params: dict[str, Any],
    full_output_lines: list[str],
    read_timeout: int,
) -> None:
    """Исполняет команду-макрос `@cisco_arp_clear_then_show` с логированием в общий вывод."""
    print(f"  [{host}] Команда: @cisco_arp_clear_then_show")
    run_cisco_arp_clear_then_show(conn, params, full_output_lines, read_timeout=read_timeout)
    print(f"  [{host}] Результат: макрос выполнен.")


# --- D-Link ---

POST_ENABLE_DELAY_SEC = 5


def dlink_port_is_enabled(show_ports_output: str, port: str) -> bool:
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


def dlink_run_fdb_vlan_mac_poll(conn: Any, cmd: str, read_timeout: int) -> str:
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


# --- Raisecom / ISCOM ---


def raisecom_send_iscom2624_dynamic_mac_with_retry(
    conn: Any,
    cmd: str,
    read_timeout: int,
) -> str:
    out = ""
    last = ""
    for attempt in range(3):
        last = conn.send_command_timing(
            cmd,
            last_read=6.0,
            read_timeout=read_timeout,
            strip_prompt=False,
            strip_command=False,
        )
        if extract_unique_macs_from_cli_table(last):
            out = last
            break
        if attempt < 2:
            time.sleep(1)
    return out or last


def raisecom_sleep_after_no_shutdown_iscom2624_workflow(device_type: str, cmd_lower: str) -> None:
    """Пауза только в сценарии ISCOM2624; вызывать из алгоритма этой модели."""
    if device_type == "raisecom_roap" and cmd_lower == "no shutdown":
        time.sleep(POST_ENABLE_DELAY_SEC)


def raisecom_run_mac_table_poll_until_two_macs(conn: Any, cmd: str, read_timeout: int) -> str:
    """
    Raisecom/ISCOM: повтор команды MAC-таблицы до 20 раз (или пока не появится >=2 MAC).

    Используется для команд вида:
      - sh mac-address-table l2 vlan X
      - sh mac-address-table l2 port Y
    """
    last_out = ""
    final_out = ""
    for attempt in range(20):
        out_i = conn.send_command(cmd, read_timeout=read_timeout)
        last_out = out_i
        if len(extract_unique_macs_from_cli_table(out_i)) >= 2:
            final_out = out_i
            break
        if attempt < 19:
            time.sleep(1)
    return final_out if final_out else last_out


def raisecom_run_port_list_poll_until_operate_up(
    conn: Any,
    cmd: str,
    port: str,
    read_timeout: int,
) -> str:
    """
    Raisecom/ISCOM: повторяем `sh int port-list {port}` до тех пор, пока
    в строке порта не появится Operate=up(...), либо пока не кончится 20 итераций.

    Условие для "up": в строке порта встречается подстрока `up(`.
    """
    port_req = str(port).strip()
    if not port_req:
        return conn.send_command(cmd, read_timeout=read_timeout)

    last_out = ""
    final_out = ""
    port_req_lower = port_req.lower()
    port_prefix1 = f"p{port_req_lower}"  # обычно: P4
    port_prefix2 = f"port{port_req_lower}"  # на всякий случай

    for attempt in range(20):
        out_i = conn.send_command(cmd, read_timeout=read_timeout)
        last_out = out_i

        for raw in (out_i or "").splitlines():
            line = raw.strip()
            if not line:
                continue
            lower = line.lower()
            # Ищем именно строку порта, а не просто "up(" где-то в выводе.
            if lower.startswith(port_prefix1) or lower.startswith(port_prefix2):
                if "up(" in lower:
                    final_out = out_i
                    break
            # fallback: если формат строки чуть другой, но P{port} и up( есть на одной строке
            if port_req_lower in lower and "up(" in lower and "port-list" not in lower:
                final_out = out_i
                break

        if final_out:
            break
        if attempt < 19:
            time.sleep(1)

    return final_out if final_out else last_out
