"""
Алгоритмы диагностики по имени модели (файл сценария).
Каждая модель — своя функция; выбор функции по модели (match/case) — в equipment_diagnostics._run_device_diagnostics.
Каждая diagnostics_* возвращает список строк вывода (без общего заголовка сессии).
"""
from __future__ import annotations

import time
from typing import Any

from diagnostic_function import (
    dlink_post_state_enable_flow as post_state_enable_flow,
    dlink_run_fdb_vlan_mac_poll as run_fdb_vlan_mac_poll,
    handle_cisco_arp_clear_then_show_command,
    netmiko_send_adaptive,
    raisecom_run_mac_table_poll_until_two_macs as raisecom_mac_table_poll_two,
    raisecom_run_port_list_poll_until_operate_up as raisecom_port_list_poll_operate_up,
    raisecom_send_iscom2624_dynamic_mac_with_retry as send_iscom2624_dynamic_mac_retry,
    raisecom_sleep_after_no_shutdown_iscom2624_workflow as sleep_after_no_shutdown_iscom2624,
)
from netmiko.exceptions import NetmikoAuthenticationException


def _commands_loop_default(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    run_params = commands_ctx["run_params"]
    lines: list[str] = []
    for cmd in commands_ctx["commands"]:
        print(f"  [{host}] Команда: {cmd}")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        out = netmiko_send_adaptive(
            conn,
            cmd,
            device_type=device_type,
            use_timing=use_timing,
            expect_string=expect_string,
            read_timeout=read_timeout,
        )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
    return lines


def diagnostics_bdcom_gp3600_04(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_bdcom_gp3600_08(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_bdcom_gp3600_16(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_des_1228_me(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    run_params = commands_ctx["run_params"]
    actual_port_value = commands_ctx["actual_port_value"]
    lines: list[str] = []
    fdb_poll_allowed = False
    for cmd in commands_ctx["commands"]:
        print(f"  [{host}] Команда: {cmd}")
        cmd_lower = cmd.strip().lower()
        # DES 1228-ME: выбор спец-обработки по содержимому команды.
        # Функция вызывается только для DES-сценария, поэтому достаточно распознать тип команды.
        enable_state_cmd = cmd_lower.startswith("config ports") and "state enable" in cmd_lower
        show_fdb_vlan_cmd = cmd_lower.startswith("show fdb vlan")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        if show_fdb_vlan_cmd and fdb_poll_allowed:
            out = run_fdb_vlan_mac_poll(conn, cmd, read_timeout)
            fdb_poll_allowed = False
        else:
            out = netmiko_send_adaptive(
                conn,
                cmd,
                device_type=device_type,
                use_timing=use_timing,
                expect_string=expect_string,
                read_timeout=read_timeout,
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
        if enable_state_cmd:
            fdb_poll_allowed = post_state_enable_flow(conn, cmd, actual_port_value, read_timeout)
    return lines


def diagnostics_iscom_5508_olt_gp4a(
    conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]
) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_iscom2110ea_ma(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_iscom2128ea_ma(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_iscom2624g_4ge_ac(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    lines: list[str] = []
    for cmd in commands_ctx["commands"]:
        print(f"  [{host}] Команда: {cmd}")
        cmd_lower = cmd.strip().lower()
        lines.append(f"\n--- Команда: {cmd} ---\n")
        if cmd_lower.startswith("sh mac-address dynamic"):
            out = send_iscom2624_dynamic_mac_retry(conn, cmd, read_timeout)
        else:
            out = netmiko_send_adaptive(
                conn,
                cmd,
                device_type=device_type,
                use_timing=use_timing,
                expect_string=expect_string,
                read_timeout=read_timeout,
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
        sleep_after_no_shutdown_iscom2624(device_type, cmd_lower)
    return lines


def _parse_raisecom_product_from_show_version(show_ver_output: str) -> str:
    """
    Извлекает Product Name из вывода `sh ver`.
    Поддерживает варианты регистра и написания: Product Name / Product name.
    """
    for raw_line in show_ver_output.splitlines():
        line = raw_line.strip()
        lower = line.lower()
        if lower.startswith("product name:"):
            return line.split(":", 1)[1].strip()
    return ""


def _select_iscom2624g_4c_ac_variant(product_name: str) -> str:
    """
    Выбирает ветку диагностики для номенклатуры ISCOM2624G-4C-AC по Product Name.
    Возвращает ключ варианта:
      - "standard_2624g_4c_ac"
      - "variant_2924gf_4c_ac"
      - "variant_2924gf_legacy"
    """
    normalized = (product_name or "").strip().lower()
    compact = normalized.replace("_", "").replace(" ", "")

    # Семейство 2924GF-4x-AC/* (в т.ч. встречающиеся варианты 4C и 4GE):
    # - ISCOM2924GF-4C-AC_DC
    # - ISCOM2924GF-4C-AC/D
    # - ISCOM2924GF-4GE-AC/D
    if "iscom2924gf-4ge-ac/d" in compact:
        return "variant_2924gf_4ge_ac_d"
    if "iscom2924gf-4" in compact and ("ac/d" in compact or "acdc" in compact):
        return "variant_2924gf_4c_ac"

    # Старый 2924GF без суффикса 4x-AC/*
    if "iscom2924gf" in compact:
        return "variant_2924gf_legacy"
    return "standard_2624g_4c_ac"


def _run_iscom2924gf_4c_ac_post_ver_commands(
    conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]
) -> list[str]:
    """
    Неполный сценарий для ISCOM2924GF-4C-AC_DC и ISCOM2924GF-4C-AC/D:
    выполняется только часть ПОСЛЕ `sh ver`.
    """
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    run_params = commands_ctx["run_params"]
    lines: list[str] = []
    # Неполный хвост сценария ISCOM2924GF-4C-AC/DC после `sh ver`:
    # (без повторного `terminal page-break disable` и `sh ver`, потому что это уже выполнено
    #  базовым прогоном ISCOM2624G-4C-AC до вызова этой функции)
    commands = [
        "sh int port {port}",
        "sh int port {port} st",
        "sh mac-address-table l2 vlan {vlan}",
        "conf",
        "int port {port}",
        "shutdown",
        "no shutdown",
        "exit",
        "exit",
        "sh int port {port}",
        "sh int port {port} st",
        "sh mac-address-table l2 vlan {vlan}",
        "sh mac-address-table l2 port {port}",
        'sh logging file | include "port{port}"',
    ]
    for cmd_tmpl in commands:
        cmd = cmd_tmpl.format(**run_params)
        print(f"  [{host}] Команда: {cmd}")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        cmd_lower = cmd.strip().lower()
        if cmd_lower.startswith("sh int port ") and " st" not in cmd_lower:
            out = raisecom_port_list_poll_operate_up(
                conn,
                cmd,
                str(run_params.get("port", "")),
                read_timeout,
            )
        elif cmd_lower.startswith("sh mac-address-table l2"):
            out = raisecom_mac_table_poll_two(conn, cmd, read_timeout)
        else:
            out = netmiko_send_adaptive(
                conn,
                cmd,
                device_type=device_type,
                use_timing=use_timing,
                expect_string=expect_string,
                read_timeout=read_timeout,
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
        if cmd_lower == "shutdown":
            time.sleep(5)
    return lines


def _run_iscom2924gf_4ge_ac_d_post_ver_commands(
    conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]
) -> list[str]:
    """
    Неполный сценарий для ISCOM2924GF-4GE-AC/D:
    - порт проверяется через `sh int port-list`
    - команду `sh logging file ...` НЕ выполняем (требование).
    """
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    run_params = commands_ctx["run_params"]
    lines: list[str] = []
    commands = [
        "sh int port-list {port}",
        "sh int port-list {port} st",
        "sh mac-address-table l2 vlan {vlan}",
        "conf",
        "int port {port}",
        "shutdown",
        "no shutdown",
        "exit",
        "exit",
        "sh int port-list {port}",
        "sh int port-list {port} st",
        "sh mac-address-table l2 vlan {vlan}",
        "sh mac-address-table l2 port {port}",
    ]
    for cmd_tmpl in commands:
        cmd = cmd_tmpl.format(**run_params)
        print(f"  [{host}] Команда: {cmd}")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        cmd_lower = cmd.strip().lower()
        if cmd_lower.startswith("sh int port-list") and " st" not in cmd_lower:
            out = raisecom_port_list_poll_operate_up(conn, cmd, str(run_params.get("port", "")), read_timeout)
        elif cmd_lower.startswith("sh mac-address-table l2"):
            out = raisecom_mac_table_poll_two(conn, cmd, read_timeout)
        else:
            out = netmiko_send_adaptive(
                conn,
                cmd,
                device_type=device_type,
                use_timing=use_timing,
                expect_string=expect_string,
                read_timeout=read_timeout,
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
        if cmd_lower == "shutdown":
            time.sleep(5)
    return lines


def _run_iscom2924gf_legacy_post_ver_commands(
    conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]
) -> list[str]:
    """
    Неполный сценарий для старого ISCOM2924GF:
    используется хвост сценария ISCOM2128EA-MA (после `sh ver`).
    """
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    run_params = commands_ctx["run_params"]
    lines: list[str] = []
    commands = [
        "sh int port {port}",
        "sh int port {port} st",
        "sh mac-address-table l2 vlan {vlan}",
        "int port {port}",
        "shutdown",
        "no shutdown",
        "exit",
        "sh int port {port}",
        "sh int port {port} st",
        "sh mac-address-table l2 vlan {vlan}",
        "sh mac-address-table l2 port {port}",
        'sh logging file | include "port {port}"',
    ]
    for cmd_tmpl in commands:
        cmd = cmd_tmpl.format(**run_params)
        print(f"  [{host}] Команда: {cmd}")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        cmd_lower = cmd.strip().lower()
        if cmd_lower.startswith("sh int port ") and " st" not in cmd_lower:
            out = raisecom_port_list_poll_operate_up(
                conn,
                cmd,
                str(run_params.get("port", "")),
                read_timeout,
            )
        elif cmd_lower.startswith("sh mac-address-table l2"):
            out = raisecom_mac_table_poll_two(conn, cmd, read_timeout)
        else:
            out = netmiko_send_adaptive(
                conn,
                cmd,
                device_type=device_type,
                use_timing=use_timing,
                expect_string=expect_string,
                read_timeout=read_timeout,
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
        if cmd_lower == "shutdown":
            time.sleep(5)
    return lines


def diagnostics_iscom2624g_4c_ac(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    """
    Базовый прогон как у ISCOM2624G-4GE-AC, но после `sh ver`:
    - парсит Product Name,
    - выбирает ветку сценария,
    - для нештатных моделей выполняет отдельный неполный хвост сценария.
    """
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    lines: list[str] = []
    product_variant = "standard_2624g_4c_ac"

    for cmd in commands_ctx["commands"]:
        print(f"  [{host}] Команда: {cmd}")
        cmd_lower = cmd.strip().lower()
        lines.append(f"\n--- Команда: {cmd} ---\n")
        if cmd_lower.startswith("sh mac-address dynamic"):
            out = send_iscom2624_dynamic_mac_retry(conn, cmd, read_timeout)
        else:
            out = netmiko_send_adaptive(
                conn,
                cmd,
                device_type=device_type,
                use_timing=use_timing,
                expect_string=expect_string,
                read_timeout=read_timeout,
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")

        if cmd_lower == "sh ver":
            product_name = _parse_raisecom_product_from_show_version(out)
            product_variant = _select_iscom2624g_4c_ac_variant(product_name)
            lines.append(
                f"\n[auto-detect] Product Name: {product_name or '-'} | variant={product_variant}\n"
            )
            if product_variant == "variant_2924gf_4c_ac":
                lines.extend(_run_iscom2924gf_4c_ac_post_ver_commands(conn, connect_ctx, commands_ctx))
                return lines
            if product_variant == "variant_2924gf_4ge_ac_d":
                lines.extend(_run_iscom2924gf_4ge_ac_d_post_ver_commands(conn, connect_ctx, commands_ctx))
                return lines
            if product_variant == "variant_2924gf_legacy":
                lines.extend(_run_iscom2924gf_legacy_post_ver_commands(conn, connect_ctx, commands_ctx))
                return lines

        sleep_after_no_shutdown_iscom2624(device_type, cmd_lower)

    return lines


def diagnostics_snr_s2960_24g(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_snr_s2985g_24t(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_rb941(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    lines: list[str] = []

    for cmd in commands_ctx["commands"]:
        print(f"  [{host}] Команда: {cmd}")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        out = netmiko_send_adaptive(
            conn,
            cmd,
            device_type=device_type,
            use_timing=use_timing,
            expect_string=expect_string,
            read_timeout=read_timeout,
        )
        low = (out or "").lower()
        # Защита от ситуации, когда устройство вернулось в login-поток:
        # не продолжаем отправлять следующие команды как "username".
        if (
            "login:" in low
            or "password:" in low
            or "incorrect username or password" in low
            or "login failed" in low
        ):
            raise NetmikoAuthenticationException(
                "RB941 telnet session is not authenticated (device returned login/password prompt)"
            )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
    return lines


def diagnostics_zte_c620(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_cisco_ios(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_cisco_asr1002(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    host = connect_ctx["host"]
    device_type = connect_ctx["device_type"]
    read_timeout = connect_ctx["read_timeout"]
    use_timing = connect_ctx["use_timing"]
    expect_string = connect_ctx["expect_string"]
    run_params = commands_ctx["run_params"]
    lines: list[str] = []
    for cmd in commands_ctx["commands"]:
        if cmd.strip() == "@cisco_arp_clear_then_show":
            handle_cisco_arp_clear_then_show_command(
                conn,
                host=host,
                params=run_params,
                full_output_lines=lines,
                read_timeout=read_timeout,
            )
            continue
        print(f"  [{host}] Команда: {cmd}")
        lines.append(f"\n--- Команда: {cmd} ---\n")
        out = netmiko_send_adaptive(
            conn,
            cmd,
            device_type=device_type,
            use_timing=use_timing,
            expect_string=expect_string,
            read_timeout=read_timeout,
        )
        lines.append(out)
        print(f"  [{host}] Результат: {len(out)} символов")
    return lines


def diagnostics_generic(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)
