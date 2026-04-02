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
from typing import Any

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from diagnostic_function import substitute_params
from model_diagnostics_algorithm import (
    diagnostics_bdcom_gp3600_04,
    diagnostics_bdcom_gp3600_08,
    diagnostics_bdcom_gp3600_16,
    diagnostics_cisco_asr1002,
    diagnostics_cisco_ios,
    diagnostics_des_1228_me,
    diagnostics_generic,
    diagnostics_iscom2110ea_ma,
    diagnostics_iscom2128ea_ma,
    diagnostics_iscom2624g_4ge_ac,
    diagnostics_iscom_5508_olt_gp4a,
    diagnostics_snr_s2960_24g,
    diagnostics_snr_s2985g_24t,
    diagnostics_zte_c620,
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


def reserve_diagnostics_output_file(out_dir: str | None = None) -> tuple[str, str]:
    """
    Резервирует следующий лог-файл (пустой .txt под тем же замком, что и нумерация).
    Возвращает (log_id без расширения, полный путь).
    """
    od = out_dir or OUTPUT_DIR
    os.makedirs(od, exist_ok=True)
    with _OUTPUT_FILE_LOCK:
        filename = _next_output_filename(od)
        path = os.path.join(od, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write("")
    log_id = os.path.splitext(filename)[0]
    return log_id, path


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
    Подключается к одному устройству (host), по model_for_filename выбирает алгоритм (match/case)
    и выполняет сценарий.
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

    session_header = f"=== {model} | {host} | {datetime.now().isoformat()} ===\n"

    if device_type == "raisecom_telnet":
        read_timeout = max(read_timeout, 300)
    use_timing = device_type in ("cisco_ios", "raisecom_telnet")
    expect_flexible = device_type == "raisecom_roap"
    expect_string = r'\S+[>#]\s*$|\(\w+[^)]*\)#\s*$' if expect_flexible else None

    connect_ctx: dict[str, Any] = {
        "host": host,
        "device_type": device_type,
        "read_timeout": read_timeout,
        "use_timing": use_timing,
        "expect_string": expect_string,
    }
    commands_ctx: dict[str, Any] = {
        "commands": commands,
        "run_params": run_params,
        "model_for_filename": model_for_filename,
        "actual_port_value": actual_port_value,
    }

    print(f"  [{host}] Подключение к устройству...")
    with ConnectHandler(**device) as conn:
        print(f"  [{host}] Подключение успешно.")
        if use_timing:
            time.sleep(2 if device_type == "cisco_ios" else 1)

        match model_for_filename:
            case "BDCOM GP3600-04":
                body_lines = diagnostics_bdcom_gp3600_04(conn, connect_ctx, commands_ctx)
            case "BDCOM GP3600-08":
                body_lines = diagnostics_bdcom_gp3600_08(conn, connect_ctx, commands_ctx)
            case "BDCOM GP3600-16":
                body_lines = diagnostics_bdcom_gp3600_16(conn, connect_ctx, commands_ctx)
            case "DES 1228-ME":
                body_lines = diagnostics_des_1228_me(conn, connect_ctx, commands_ctx)
            case "ISCOM 5508 OLT-gp4a":
                body_lines = diagnostics_iscom_5508_olt_gp4a(conn, connect_ctx, commands_ctx)
            case "ISCOM2110EA-MA":
                body_lines = diagnostics_iscom2110ea_ma(conn, connect_ctx, commands_ctx)
            case "ISCOM2128EA-MA":
                body_lines = diagnostics_iscom2128ea_ma(conn, connect_ctx, commands_ctx)
            case "ISCOM2624G-4GE-AC":
                body_lines = diagnostics_iscom2624g_4ge_ac(conn, connect_ctx, commands_ctx)
            case "SNR-S2960-24G":
                body_lines = diagnostics_snr_s2960_24g(conn, connect_ctx, commands_ctx)
            case "SNR-S2985G-24T":
                body_lines = diagnostics_snr_s2985g_24t(conn, connect_ctx, commands_ctx)
            case "ZTE C620":
                body_lines = diagnostics_zte_c620(conn, connect_ctx, commands_ctx)
            case "cisco_ios":
                body_lines = diagnostics_cisco_ios(conn, connect_ctx, commands_ctx)
            case "cisco_asr1002":
                body_lines = diagnostics_cisco_asr1002(conn, connect_ctx, commands_ctx)
            case "generic":
                body_lines = diagnostics_generic(conn, connect_ctx, commands_ctx)
            case _:
                raise ValueError(
                    f"Нет алгоритма диагностики для модели сценария: {model_for_filename!r}. "
                    "Добавьте case и diagnostics_* в equipment_diagnostics.py и model_diagnostics_algorithm.py."
                )

    return [session_header, *body_lines]


def run_diagnostics(params: dict[str, Any], out_path: str | None = None) -> tuple[str, str]:
    """
    Диагностика: только конечное оборудование или оборудование + маршрутизатор.
    При указании router_model и router_ip выполняются оба сценария, результат пишется в один файл.

    Ожидаемые ключи в params:
    - model: модель конечного оборудования (имя сценария без .txt), по умолчанию \"generic\"
    - equipment_ip: обязательно, IP или хост конечного оборудования
    - client_ip, client_vlan, port: параметры клиента/порта (допускаются строки по умолчанию \"-\")
    - output_dir: опционально, директория для файла вывода (по умолчанию diagnostics_output)
    - router_model, router_ip: опционально, вторая цель (маршрутизатор)

    out_path: если задан (зарезервированный путь .txt), результат пишется туда; иначе выделяется новое имя.

    :return: пара (полный текст вывода, путь к сохранённому файлу)
    """
    model = str(params.get("model") or "generic").strip() or "generic"
    equipment_ip = str(params.get("equipment_ip") or "").strip()
    if not equipment_ip:
        raise ValueError("params['equipment_ip'] обязателен")

    client_ip = str(params.get("client_ip") or "-")
    client_vlan = str(params.get("client_vlan") or "-")
    port = str(params.get("port") or "-")
    output_dir = params.get("output_dir")
    output_dir = str(output_dir).strip() if output_dir else None

    rm = params.get("router_model")
    router_model = str(rm).strip() or None if rm is not None else None
    ri = params.get("router_ip")
    router_ip = str(ri).strip() or None if ri is not None else None

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
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        all_lines.append(f"\nОшибка подключения (оборудование): {e}\n")
        raise

    if router_model and router_ip:
        all_lines.append("\n\n")
        all_lines.append("=" * 60 + "\n")
        all_lines.append("Маршрутизатор (подписка клиента)\n")
        all_lines.append("=" * 60 + "\n")
        try:
            print("--- Маршрутизатор ---")
            router_params = {**params, "model": router_model}
            router_lines = _run_device_diagnostics(router_model, router_ip, router_params, read_timeout=120)
            all_lines.extend(router_lines)
        except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
            all_lines.append(f"\nОшибка подключения (маршрутизатор): {e}\n")
            raise

    full_output = "\n".join(all_lines)

    out_dir = output_dir or OUTPUT_DIR
    os.makedirs(out_dir, exist_ok=True)
    if out_path:
        final_path = out_path
        with open(final_path, "w", encoding="utf-8") as f:
            f.write(full_output)
    else:
        with _OUTPUT_FILE_LOCK:
            filename = _next_output_filename(out_dir)
            final_path = os.path.join(out_dir, filename)
        with open(final_path, "w", encoding="utf-8") as f:
            f.write(full_output)

    print(f"Вывод сохранён: {final_path}")
    return full_output, final_path
