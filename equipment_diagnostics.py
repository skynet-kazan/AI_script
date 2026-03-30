"""
Модуль диагностики оборудования по SSH.
Читает сценарии из папки equipment_scenario, подставляет параметры, выполняет команды,
возвращает полный вывод в текстовый файл в папку diagnostics_output (рядом с equipment_scenario).
"""
from __future__ import annotations

import os
import time
import threading
from datetime import datetime
from typing import Any, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from vendors.common import substitute_params
from vendors.cisco import run_cisco_arp_clear_then_show
from vendors.dlink import (
    dlink_post_state_enable_flow,
    dlink_run_fdb_vlan_mac_poll,
    is_dlink_show_fdb_vlan_command,
    is_dlink_state_enable_command,
)
from vendors.raisecom import (
    is_iscom2624_dynamic_mac_command,
    is_iscom_mac_vlan_command,
    is_iscom_raisecom_switch_model,
    raisecom_post_no_shutdown_iscom_port_flow,
    raisecom_run_iscom_mac_vlan_poll,
    raisecom_send_iscom2624_dynamic_mac_with_retry,
    raisecom_sleep_after_no_shutdown_iscom2624,
)


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCENARIO_DIR = os.path.join(_SCRIPT_DIR, "equipment_scenario")
OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "diagnostics_output")
_OUTPUT_FILE_LOCK = threading.Lock()


def _next_output_filename(out_dir: str) -> str:
    """
    Функция нумерации лог-файлов
    ОПТИМИЗИРОВАНА
    """
    with os.scandir(out_dir) as entries:
        numbers = (
            int(entry.name[:-4])
            for entry in entries
            if entry.is_file()
            and entry.name.endswith(".txt")
            and len(entry.name) == 14
            and entry.name[:-4].isdigit()
        )
        max_num = max(numbers, default=0)
    return f"{max_num + 1:010d}.txt"


def _parse_scenario(path: str) -> tuple[dict[str, str], list[str]]:
    """
    Функция парсинга файлов сценариев диагностики
    ОПТИМИЗИРОВАНА
    """
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    head, _, commands_block = content.partition("---")

    credentials: dict[str, str] = {}
    for line in head.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            credentials[key.strip()] = value.strip()

    commands = [
        line.strip() for line in commands_block.strip().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return credentials, commands


def _run_device_diagnostics(
    model: str,
    host: str,
    params: dict[str, Any],
    read_timeout: int = 120,
) -> list[str]:
    """
    Подключается к одному устройству (host), выполняет сценарий в зависимости от модели, возвращает список строк вывода.
    Не пишет файл. Используется для объединённой диагностики оборудования и маршрутизатора.
    """
    model_for_filename = (model or "").replace("/", "-")

    scenario_path = os.path.join(SCENARIO_DIR, f"{model_for_filename}.txt")
    if not os.path.isfile(scenario_path):
        raise FileNotFoundError(f"Сценарий не найден: {scenario_path}")

    credentials, raw_commands = _parse_scenario(scenario_path)
    device_type = credentials.get("device_type", "linux")
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    secret = credentials.get("secret", "")

    run_params = {**params, "model": model_for_filename}
    commands = [substitute_params(cmd, run_params) for cmd in raw_commands]
    actual_port_value = str(params.get("port", "") or "")

    dlink_port_enabled_for_fdb_loop = False
    iscom_port_up_for_mac_loop = False
    ENABLE_ISCOM_MAC_POLLING = False

    conn_port = 23 if "telnet" in device_type.lower() else 22
    device: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": conn_port,
        "global_delay_factor": 2,
    }
    if secret:
        device["secret"] = secret

    full_output_lines: list[str] = []
    full_output_lines.append(f"=== {model} | {host} | {datetime.now().isoformat()} ===\n")

    use_timing = device_type in ("cisco_ios", "raisecom_telnet")
    if device_type == "raisecom_telnet":
        read_timeout = max(read_timeout, 300)
    expect_flexible = device_type == "raisecom_roap"
    expect_string = r'\S+[>#]\s*$|\(\w+[^)]*\)#\s*$' if expect_flexible else None

    print(f"  [{host}] Подключение к устройству...")
    with ConnectHandler(**device) as conn:
        print(f"  [{host}] Подключение успешно.")
        if use_timing:
            time.sleep(2 if device_type == "cisco_ios" else 1)
        for i, cmd in enumerate(commands):
            if cmd.strip() == "@cisco_arp_clear_then_show":
                print(f"  [{host}] Команда: @cisco_arp_clear_then_show")
                run_cisco_arp_clear_then_show(conn, run_params, full_output_lines, read_timeout=read_timeout)
                print(f"  [{host}] Результат: макрос выполнен.")
                continue
            print(f"  [{host}] Команда: {cmd}")

            cmd_lower = cmd.strip().lower()
            is_dlink_enable_cmd = is_dlink_state_enable_command(device_type, cmd_lower)
            is_dlink_fdb_vlan_cmd = is_dlink_show_fdb_vlan_command(device_type, cmd_lower)
            is_iscom_mac_vlan_cmd = is_iscom_mac_vlan_command(
                model_for_filename, device_type, cmd_lower
            )
            is_iscom2624_dynamic_mac_cmd = is_iscom2624_dynamic_mac_command(
                model_for_filename, device_type, cmd_lower
            )

            full_output_lines.append(f"\n--- Команда: {cmd} ---\n")

            mac_poll_dlink = is_dlink_fdb_vlan_cmd and dlink_port_enabled_for_fdb_loop
            mac_poll_iscom = (
                ENABLE_ISCOM_MAC_POLLING
                and is_iscom_mac_vlan_cmd
                and iscom_port_up_for_mac_loop
            )
            if mac_poll_dlink or mac_poll_iscom:
                if mac_poll_dlink:
                    out = dlink_run_fdb_vlan_mac_poll(conn, cmd, read_timeout)
                    dlink_port_enabled_for_fdb_loop = False
                else:
                    out = raisecom_run_iscom_mac_vlan_poll(
                        conn, cmd, read_timeout, expect_string
                    )
                    iscom_port_up_for_mac_loop = False
            else:
                if is_iscom2624_dynamic_mac_cmd:
                    out = raisecom_send_iscom2624_dynamic_mac_with_retry(
                        conn, cmd, read_timeout
                    )
                elif use_timing:
                    last_read = 3.0 if device_type == "raisecom_telnet" else 2.5
                    out = conn.send_command_timing(
                        cmd,
                        last_read=last_read,
                        read_timeout=read_timeout,
                        strip_prompt=False,
                        strip_command=False,
                    )
                else:
                    kwargs = {"read_timeout": read_timeout}
                    if expect_string:
                        kwargs["expect_string"] = expect_string
                    if device_type in ("raisecom_roap", "raisecom_telnet"):
                        kwargs["delay_factor"] = 2
                    out = conn.send_command(cmd, **kwargs)

            full_output_lines.append(out)
            print(f"  [{host}] Результат: {len(out)} символов")

            raisecom_sleep_after_no_shutdown_iscom2624(
                device_type, model_for_filename, cmd_lower
            )

            if is_dlink_enable_cmd:
                dlink_port_enabled_for_fdb_loop = dlink_post_state_enable_flow(
                    conn, cmd, actual_port_value, read_timeout
                )

            if (
                is_iscom_raisecom_switch_model(model_for_filename)
                and device_type == "raisecom_roap"
                and cmd_lower == "no shutdown"
                and ENABLE_ISCOM_MAC_POLLING
            ):
                iscom_port_up_for_mac_loop = raisecom_post_no_shutdown_iscom_port_flow(
                    conn,
                    model_for_filename,
                    device_type,
                    actual_port_value,
                    read_timeout,
                    expect_string,
                )

    return full_output_lines


def run_diagnostics(
    model: str,
    equipment_ip: str,
    client_ip: str,
    client_vlan: str,
    port: str,
    output_dir: Optional[str] = None,
    router_model: Optional[str] = None,
    router_ip: Optional[str] = None,
) -> tuple[str, str]:
    """
    Диагностика: только конечное оборудование или оборудование + маршрутизатор.
    При указании router_model и router_ip выполняются оба сценария, результат пишется в один файл.

    :param model: модель конечного оборудования (имя сценария без .txt)
    :param equipment_ip: IP или хост конечного оборудования
    :param client_ip: IP клиента
    :param client_vlan: VLAN клиента
    :param port: порт на оборудовании
    :param output_dir: директория для файла вывода (по умолчанию — diagnostics_output)
    :param router_model: модель маршрутизатора (имя сценария без .txt); при пустом — только оборудование
    :param router_ip: IP или хост маршрутизатора
    :return: пара (полный текст вывода, путь к сохранённому файлу)
    """
    port_olt = port.rsplit("/", 1)[0] if port and port.count("/") >= 2 else (port or "")
    params = {
        "model": model,
        "equipment_ip": equipment_ip,
        "router_ip": router_ip or "",
        "client_ip": client_ip,
        "vlan": client_vlan,
        "port": port,
        "port_olt": port_olt,
    }

    all_lines: list[str] = []
    all_lines.append(f"=== Диагностика клиента | {datetime.now().isoformat()} ===\n")
    all_lines.append(f"Клиент: {client_ip}  VLAN: {client_vlan}  Порт: {port}\n")

    try:
        print("--- Оборудование ---")
        equipment_lines = _run_device_diagnostics(model, equipment_ip, params, read_timeout=120)
        all_lines.extend(equipment_lines)

        if router_model and router_ip:
            all_lines.append("\n\n")
            all_lines.append("=" * 60 + "\n")
            all_lines.append("Маршрутизатор (подписка клиента)\n")
            all_lines.append("=" * 60 + "\n")
            print("--- Маршрутизатор ---")
            router_params = {**params, "model": router_model}
            router_lines = _run_device_diagnostics(router_model, router_ip, router_params, read_timeout=120)
            all_lines.extend(router_lines)
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        all_lines.append(f"\nОшибка подключения: {e}\n")
        raise

    full_output = "\n".join(all_lines)

    out_dir = output_dir or OUTPUT_DIR
    os.makedirs(out_dir, exist_ok=True)
    with _OUTPUT_FILE_LOCK:
        filename = _next_output_filename(out_dir)
        out_path = os.path.join(out_dir, filename)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(full_output)

    print(f"Вывод сохранён: {out_path}")
    return full_output, out_path
