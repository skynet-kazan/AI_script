from __future__ import annotations

import re
import time
from typing import Any, Optional

from vendors.mac_table import extract_unique_macs_from_cli_table

POST_ENABLE_DELAY_SEC = 5

ISCOM2128_SCENARIO = "ISCOM2128EA-MA"
ISCOM2624_SCENARIO = "ISCOM2624G-4GE-AC"


def is_iscom_raisecom_switch_model(model_for_filename: str) -> bool:
    return model_for_filename in (ISCOM2128_SCENARIO, ISCOM2624_SCENARIO)


def is_iscom2128_model(model_for_filename: str) -> bool:
    return model_for_filename == ISCOM2128_SCENARIO


def is_iscom2624_model(model_for_filename: str) -> bool:
    return model_for_filename == ISCOM2624_SCENARIO


def raisecom_port_link_up_from_st(output: str) -> bool:
    """По выводу `sh int port <n> st` — порт/линк в состоянии up."""
    t = (output or "").lower()
    if re.search(r"link\s*[: ]+\s*up\b", t):
        return True
    if "operational" in t and re.search(r"operational\s+\S*\s*up\b", t):
        return True
    if "line protocol is up" in t:
        return True
    return False


def raisecom_port_link_up_from_interface(output: str) -> bool:
    """
    Для моделей вроде ISCOM2624: строка вида
    'gigaethernet1/1/2 is UP, administrative status is UP'
    """
    t = (output or "").lower()
    return bool(re.search(r"\bis\s+up,\s+administrative status is\s+up\b", t))


def is_iscom_mac_vlan_command(
    model_for_filename: str,
    device_type: str,
    cmd_lower: str,
) -> bool:
    if not is_iscom_raisecom_switch_model(model_for_filename):
        return False
    if device_type != "raisecom_roap":
        return False
    return cmd_lower.startswith("sh mac-address-table l2 vlan") or cmd_lower.startswith(
        "sh mac-address dynamic vlan"
    )


def is_iscom2624_dynamic_mac_command(
    model_for_filename: str,
    device_type: str,
    cmd_lower: str,
) -> bool:
    return (
        is_iscom2624_model(model_for_filename)
        and device_type == "raisecom_roap"
        and cmd_lower.startswith("sh mac-address dynamic")
    )


def raisecom_run_iscom_mac_vlan_poll(
    conn: Any,
    cmd: str,
    read_timeout: int,
    expect_string: Optional[str],
) -> str:
    last_out = ""
    final_out = ""
    for attempt in range(20):
        out_i = conn.send_command(
            cmd,
            read_timeout=read_timeout,
            expect_string=expect_string,
            delay_factor=2,
        )
        last_out = out_i
        if len(extract_unique_macs_from_cli_table(out_i)) == 2:
            final_out = out_i
            break
        if attempt < 19:
            time.sleep(1)
    return final_out if final_out else last_out


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


def raisecom_sleep_after_no_shutdown_iscom2624(
    device_type: str,
    model_for_filename: str,
    cmd_lower: str,
) -> None:
    if (
        is_iscom2624_model(model_for_filename)
        and device_type == "raisecom_roap"
        and cmd_lower == "no shutdown"
    ):
        time.sleep(POST_ENABLE_DELAY_SEC)


def raisecom_post_no_shutdown_iscom_port_flow(
    conn: Any,
    model_for_filename: str,
    device_type: str,
    actual_port: str,
    read_timeout: int,
    expect_string: Optional[str],
) -> bool:
    """
    После `no shutdown` на ISCOM2128/ISCOM2624 (когда включён опрос MAC): пауза, проверка линка,
    при необходимости повтор int / no shut / exit.
    Возвращает True, если линк up и можно опрашивать MAC по VLAN.
    """
    if not is_iscom_raisecom_switch_model(model_for_filename):
        return False
    if device_type != "raisecom_roap":
        return False

    time.sleep(POST_ENABLE_DELAY_SEC)
    if is_iscom2128_model(model_for_filename):
        status_cmd = f"sh int port {actual_port} st"
    else:
        status_cmd = f"sh int gigaethernet 1/1/{actual_port}"

    check_out = conn.send_command(
        status_cmd,
        read_timeout=read_timeout,
        expect_string=expect_string,
        delay_factor=2,
    )
    port_up = (
        raisecom_port_link_up_from_st(check_out)
        if is_iscom2128_model(model_for_filename)
        else raisecom_port_link_up_from_interface(check_out)
    )
    if not port_up:
        int_cmd = (
            f"int port {actual_port}"
            if is_iscom2128_model(model_for_filename)
            else f"int gigaethernet 1/1/{actual_port}"
        )
        conn.send_command(
            int_cmd,
            read_timeout=read_timeout,
            expect_string=expect_string,
            delay_factor=2,
        )
        conn.send_command(
            "no shutdown",
            read_timeout=read_timeout,
            expect_string=expect_string,
            delay_factor=2,
        )
        conn.send_command(
            "exit",
            read_timeout=read_timeout,
            expect_string=expect_string,
            delay_factor=2,
        )
        time.sleep(POST_ENABLE_DELAY_SEC)
        check_out = conn.send_command(
            status_cmd,
            read_timeout=read_timeout,
            expect_string=expect_string,
            delay_factor=2,
        )
        port_up = (
            raisecom_port_link_up_from_st(check_out)
            if is_iscom2128_model(model_for_filename)
            else raisecom_port_link_up_from_interface(check_out)
        )
    return port_up
