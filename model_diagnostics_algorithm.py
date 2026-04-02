"""
Алгоритмы диагностики по имени модели (файл сценария).
Каждая модель — своя функция; выбор функции по модели (match/case) — в equipment_diagnostics._run_device_diagnostics.
Каждая diagnostics_* возвращает список строк вывода (без общего заголовка сессии).
"""
from __future__ import annotations

from typing import Any

from diagnostic_function import (
    dlink_post_state_enable_flow as post_state_enable_flow,
    dlink_run_fdb_vlan_mac_poll as run_fdb_vlan_mac_poll,
    handle_cisco_arp_clear_then_show_command,
    netmiko_send_adaptive,
    raisecom_send_iscom2624_dynamic_mac_with_retry as send_iscom2624_dynamic_mac_retry,
    raisecom_sleep_after_no_shutdown_iscom2624_workflow as sleep_after_no_shutdown_iscom2624,
)


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


def diagnostics_snr_s2960_24g(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


def diagnostics_snr_s2985g_24t(conn: Any, connect_ctx: dict[str, Any], commands_ctx: dict[str, Any]) -> list[str]:
    return _commands_loop_default(conn, connect_ctx, commands_ctx)


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
