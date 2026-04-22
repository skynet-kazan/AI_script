"""
Модуль диагностики оборудования по SSH.
Читает сценарии из папки equipment_scenario, подставляет параметры, выполняет команды,
возвращает полный вывод в текстовый файл в папку diagnostics_output (рядом с equipment_scenario).
"""
from __future__ import annotations

import os
import re
import socket
import sys
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
    diagnostics_iscom2624g_4c_ac,
    diagnostics_iscom2624g_4ge_ac,
    diagnostics_iscom_5508_olt_gp4a,
    diagnostics_rb941,
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
        # На перегруженных/дальних узлах Paramiko иногда даёт "No existing session"
        # при слишком коротком установочном таймауте. Держим явные таймауты подключения.
        "conn_timeout": 20,
        "auth_timeout": 20,
        "banner_timeout": 30,
    }
    if secret:
        device["secret"] = secret

    session_header = f"=== {model} | {host} | {datetime.now().isoformat()} ===\n"

    commands_ctx: dict[str, Any] = {
        "commands": commands,
        "run_params": run_params,
        "model_for_filename": model_for_filename,
        "actual_port_value": actual_port_value,
    }

    def _strip_telnet_iac(data: bytes) -> bytes:
        """Удаляет telnet IAC-последовательности из потока перед декодированием."""
        if not data:
            return data
        out = bytearray()
        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            if b == 255:  # IAC
                i += 1
                if i >= n:
                    break
                cmd = data[i]
                # IAC IAC -> escaped 0xFF
                if cmd == 255:
                    out.append(255)
                    i += 1
                    continue
                # WILL/WONT/DO/DONT + option
                if cmd in (251, 252, 253, 254):
                    i += 2
                    continue
                # SB ... IAC SE
                if cmd == 250:
                    i += 1
                    while i + 1 < n:
                        if data[i] == 255 and data[i + 1] == 240:
                            i += 2
                            break
                        i += 1
                    continue
                i += 1
                continue
            out.append(b)
            i += 1
        return bytes(out)

    def _run_rb941_via_raw_telnet() -> list[str]:
        """
        RB941 fallback: прямой telnet через socket (без Netmiko/telnetlib).
        """
        lines: list[str] = []
        sock = socket.create_connection((host, conn_port), timeout=10)
        sock.settimeout(2.0)

        def _recv_for(seconds: float) -> bytes:
            end = time.time() + seconds
            chunks: list[bytes] = []
            while time.time() < end:
                try:
                    part = sock.recv(4096)
                except socket.timeout:
                    break
                if not part:
                    break
                chunks.append(part)
                if len(part) < 4096:
                    # короткий фрейм: даём шанс дочитать хвост и выходим
                    time.sleep(0.1)
            return b"".join(chunks)

        def _recv_until_markers(markers: list[str], timeout_sec: float) -> str:
            end = time.time() + timeout_sec
            buf = bytearray()
            lower_markers = [m.lower() for m in markers]
            while time.time() < end:
                try:
                    part = sock.recv(4096)
                except socket.timeout:
                    part = b""
                if part:
                    buf.extend(part)
                    clean = _strip_telnet_iac(bytes(buf)).decode("utf-8", errors="replace")
                    low = clean.lower()
                    if any(m in low for m in lower_markers):
                        return clean
                else:
                    time.sleep(0.1)
            return _strip_telnet_iac(bytes(buf)).decode("utf-8", errors="replace")

        try:
            # Считываем initial banner и ДОЖИДАЕМСЯ login prompt.
            # Иначе есть риск отправить первую CLI-команду как username.
            # Подтолкнуть устройство показать prompt (часто баннер приходит только после Enter).
            sock.sendall(b"\r\n")
            banner = _recv_until_markers(
                markers=["login:", "username:", "name:"],
                timeout_sec=6.0,
            )
            # На части RouterOS prompt логина не печатается явно. Пробуем "слепой" ввод username.

            sock.sendall((username + "\r\n").encode("utf-8"))
            pw_phase = _recv_until_markers(
                markers=["password:", "login failed", "incorrect", "failure", ">", "#"],
                timeout_sec=6.0,
            )
            low_pw = pw_phase.lower()
            if any(k in low_pw for k in ("login failed", "incorrect", "failure")):
                raise NetmikoAuthenticationException("RB941 raw-telnet: authentication failed at username step")

            # RouterOS может сразу пустить в shell после username (без password prompt).
            if re.search(r"[>#]\s*$", pw_phase):
                post_auth = pw_phase
            else:
                # На некоторых RouterOS prompt пароля не печатается — отправляем пароль в blind-режиме.
                sock.sendall((password + "\r\n").encode("utf-8"))
                post_auth = _recv_until_markers(
                    markers=[">", "#", "login failed", "incorrect", "failure"],
                    timeout_sec=6.0,
                )
            low_auth = post_auth.lower()
            if any(k in low_auth for k in ("login failed", "incorrect", "failure")):
                raise NetmikoAuthenticationException("RB941 raw-telnet: authentication failed")
            # На MikroTik обычно shell prompt заканчивается на '>' или '#'.
            if not re.search(r"[>#]\s*$", post_auth):
                # Пробуем пробудить prompt Enter-ом.
                sock.sendall(b"\r\n")
                post_auth += _recv_for(1.5).decode("utf-8", errors="replace")
                if not re.search(r"[>#]\s*$", post_auth):
                    # На части RouterOS prompt может не отрисоваться в буфер,
                    # но сессия уже авторизована (видно по server-side logout).
                    # Не роняем диагностику: пробуем выполнить команды.
                    print(
                        f"  [{host}] RB941 raw-telnet: shell prompt not detected, continue anyway; "
                        f"pw_phase={pw_phase[:120]!r}; post_auth={post_auth[:200]!r}",
                        file=sys.stderr,
                    )

            for cmd in commands:
                print(f"  [{host}] Команда: {cmd} (raw-telnet fallback)")
                lines.append(f"\n--- Команда: {cmd} ---\n")
                sock.sendall((cmd + "\r\n").encode("utf-8"))

                deadline = time.time() + min(max(read_timeout, 10), 25)
                last_data_ts = time.time()
                got_any = False
                connection_closed = False
                chunks: list[bytes] = []
                while time.time() < deadline:
                    try:
                        part = sock.recv(4096)
                    except socket.timeout:
                        part = None
                    if part:
                        got_any = True
                        chunks.append(part)
                        last_data_ts = time.time()
                    elif part == b"":
                        # peer закрыл TCP-сессию: дальше ждать бессмысленно
                        connection_closed = True
                        break
                    else:
                        if got_any and (time.time() - last_data_ts) > 0.8:
                            break
                    time.sleep(0.2)

                if connection_closed:
                    raise NetmikoAuthenticationException(
                        f"RB941 raw-telnet: connection closed by peer while running command: {cmd}"
                    )

                clean = _strip_telnet_iac(b"".join(chunks))
                out = clean.decode("utf-8", errors="replace")
                lines.append(out if out else "(нет вывода)\n")
                print(f"  [{host}] Результат: {len(out)} символов (raw-telnet fallback)")
        finally:
            try:
                sock.close()
            except OSError:
                pass
        return lines

    def _build_connect_ctx(current_device_type: str) -> dict[str, Any]:
        rt = max(read_timeout, 300) if current_device_type == "raisecom_telnet" else read_timeout
        use_timing = current_device_type in ("cisco_ios", "raisecom_telnet", "generic_telnet")
        expect_flexible = current_device_type == "raisecom_roap"
        expect_string = r'\S+[>#]\s*$|\(\w+[^)]*\)#\s*$' if expect_flexible else None
        return {
            "host": host,
            "device_type": current_device_type,
            "read_timeout": rt,
            "use_timing": use_timing,
            "expect_string": expect_string,
        }

    def _run_with_device_type(current_device_type: str) -> list[str]:
        device_current = {**device, "device_type": current_device_type}
        connect_ctx = _build_connect_ctx(current_device_type)
        print(f"  [{host}] Подключение к устройству (device_type={current_device_type})...")
        with ConnectHandler(**device_current) as conn:
            print(f"  [{host}] Подключение успешно (device_type={current_device_type}).")
            if connect_ctx["use_timing"]:
                time.sleep(2 if current_device_type == "cisco_ios" else 1)

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
                case "ISCOM2624G-4C-AC":
                    body_lines = diagnostics_iscom2624g_4c_ac(conn, connect_ctx, commands_ctx)
                case "SNR-S2960-24G":
                    body_lines = diagnostics_snr_s2960_24g(conn, connect_ctx, commands_ctx)
                case "SNR-S2985G-24T":
                    body_lines = diagnostics_snr_s2985g_24t(conn, connect_ctx, commands_ctx)
                case "RB941":
                    body_lines = diagnostics_rb941(conn, connect_ctx, commands_ctx)
                case "ZTE C620":
                    body_lines = diagnostics_zte_c620(conn, connect_ctx, commands_ctx)
                case "ZTE C320":
                    # Для C320 используем тот же алгоритм отправки команд, что и для C620.
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
        return body_lines

    # RB941: используем только generic_telnet.
    # Это исключает ложные login-failure, которые давала попытка raisecom_telnet.
    if model_for_filename == "RB941":
        body_lines = _run_with_device_type("generic_telnet")
    else:
        body_lines = _run_with_device_type(device_type)

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
