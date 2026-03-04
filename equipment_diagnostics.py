"""
Модуль диагностики оборудования по SSH.
Читает сценарии из папки equipment_scenario, подставляет параметры, выполняет команды,
возвращает полный вывод в текстовый файл в папку diagnostics_output (рядом с equipment_scenario).
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from typing import Any, Optional

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCENARIO_DIR = os.path.join(_SCRIPT_DIR, "equipment_scenario")
OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "diagnostics_output")


def _parse_scenario(path: str) -> tuple[dict[str, str], list[str]]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    # str.partition("---") ищет в строке первое вхождение "---"
    # и возвращает кортеж из трёх частей: всё до "---" → head,
    head, _, commands_block = content.partition("---")

    # разбиваем содержимое файла на исполняемые команды
    credentials: dict[str, str] = {}
    for line in head.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            credentials[key.strip()] = value.strip()

    # формирование массива команд
    commands = [
        line.strip() for line in commands_block.strip().splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    return credentials, commands

# Функция подставляет в строку команды значения из словаря вместо плейсхолдеров вида {ключ}.
def _substitute_params(command: str, params: dict[str, Any]) -> str:
    for key, value in params.items():
        command = command.replace("{" + key + "}", str(value))
    return command


def _parse_interface_from_cisco_arp(output: str) -> Optional[str]:
    """Из вывода 'sh arp' Cisco берёт интерфейс (последняя колонка первой строки с данными)."""
    for line in output.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("Protocol"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        last = parts[-1]
        if "/" in last or "." in last:
            return last
    return None


def _run_cisco_arp_clear_then_show(
    conn: Any,
    params: dict[str, Any],
    full_output_lines: list[str],
    read_timeout: int = 120,
) -> None:
    """Выполняет sh arp | include {vlan}; при наличии вывода — 8× clear arp cache int <интерфейс>, затем снова sh arp."""
    arp_cmd = _substitute_params("sh arp | include {vlan}", params)
    full_output_lines.append(f"\n--- Команда: {arp_cmd} ---\n")
    out = conn.send_command(arp_cmd, read_timeout=read_timeout)
    full_output_lines.append(out)

    if not out.strip():
        return

    interface = _parse_interface_from_cisco_arp(out)
    if not interface:
        full_output_lines.append("\n(интерфейс из вывода ARP не определён, clear не выполняется)\n")
        return

    clear_cmd = f"clear arp-cache int {interface}"
    full_output_lines.append(f"\n--- Выполняем 8×: {clear_cmd} ---\n")
    for i in range(8):
        full_output_lines.append(f"  [{i + 1}/8] ")
        o = conn.send_command(clear_cmd, read_timeout=read_timeout)
        full_output_lines.append(o.strip() or "(ok)")

    full_output_lines.append(f"\n--- Команда: {arp_cmd} (повторно) ---\n")
    out2 = conn.send_command(arp_cmd, read_timeout=read_timeout)
    full_output_lines.append(out2)


def _run_device_diagnostics(
    model: str,
    host: str,
    params: dict[str, Any],
    read_timeout: int = 120,
) -> list[str]:
    """
    Подключается к одному устройству (host), выполняет сценарий модели, возвращает список строк вывода.
    Не пишет файл. Используется для объединённой диагностики оборудования и маршрутизатора.
    """
    scenario_path = os.path.join(SCENARIO_DIR, f"{model}.txt")
    if not os.path.isfile(scenario_path):
        raise FileNotFoundError(f"Сценарий не найден: {scenario_path}")

    credentials, raw_commands = _parse_scenario(scenario_path)
    device_type = credentials.get("device_type", "linux")
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    secret = credentials.get("secret", "")

    run_params = {**params, "model": model}
    commands = [_substitute_params(cmd, run_params) for cmd in raw_commands]

    device: dict[str, Any] = {
        "device_type": device_type,
        "host": host,
        "username": username,
        "password": password,
        "port": 22,
        "global_delay_factor": 2,
    }
    if secret:
        device["secret"] = secret

    full_output_lines: list[str] = []
    full_output_lines.append(f"=== {model} | {host} | {datetime.now().isoformat()} ===\n")

    # cisco_ios (SNR и др.): не полагаемся на приглашение — читаем по таймеру (send_command_timing)
    # raisecom_roap: гибкий expect_string с привязкой к концу строки ($), чтобы не срабатывать на # в тексте
    use_timing = device_type == "cisco_ios"
    expect_flexible = device_type == "raisecom_roap"
    expect_string = r'\S+[>#]\s*$|\(\w+[^)]*\)#\s*$' if expect_flexible else None

    print(f"  [{host}] Подключение к устройству...")
    with ConnectHandler(**device) as conn:
        print(f"  [{host}] Подключение успешно.")
        if use_timing:
            time.sleep(2)
        for i, cmd in enumerate(commands):
            if cmd.strip() == "@cisco_arp_clear_then_show":
                print(f"  [{host}] Команда: @cisco_arp_clear_then_show")
                _run_cisco_arp_clear_then_show(conn, run_params, full_output_lines, read_timeout=read_timeout)
                print(f"  [{host}] Результат: макрос выполнен.")
                continue
            print(f"  [{host}] Команда: {cmd}")
            full_output_lines.append(f"\n--- Команда: {cmd} ---\n")
            if use_timing:
                out = conn.send_command_timing(
                    cmd,
                    last_read=2.5,
                    read_timeout=read_timeout,
                    strip_prompt=False,
                    strip_command=False,
                )
            else:
                kwargs = {"read_timeout": read_timeout}
                if expect_string:
                    kwargs["expect_string"] = expect_string
                if device_type == "raisecom_roap":
                    kwargs["delay_factor"] = 2
                out = conn.send_command(cmd, **kwargs)
            full_output_lines.append(out)
            print(f"  [{host}] Результат: {len(out)} символов")

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
) -> str:
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
    :return: (полный текст вывода, путь к сохранённому файлу)
    """
    params = {
        "model": model,
        "equipment_ip": equipment_ip,
        "router_ip": router_ip or "",
        "client_ip": client_ip,
        "vlan": client_vlan,
        "port": port,
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
    safe_equipment = equipment_ip.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if router_model and router_ip:
        safe_router = router_ip.replace(".", "_")
        out_path = os.path.join(out_dir, f"diagnostics_{safe_equipment}_{safe_router}_{timestamp}.txt")
    else:
        out_path = os.path.join(out_dir, f"diagnostics_{safe_equipment}_{timestamp}.txt")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(full_output)

    print(f"Вывод сохранён: {out_path}")
    return full_output, out_path

# Функция для ручного ввода данных (временная)
def _read_input(prompt: str, default: str = "") -> str:
    if default:
        value = input(f"{prompt} [{default}]: ").strip()
        return value if value else default
    return input(f"{prompt}: ").strip()


def main() -> None:
    print("Введите параметры диагностики (пустой ввод — пропуск).\n")

    model = _read_input("Модель конечного оборудования (имя сценария без .txt)", "generic")
    equipment_ip = _read_input("IP или хост конечного оборудования")
    router_model = _read_input("Модель маршрутизатора (имя сценария без .txt)")
    router_ip = _read_input("IP или хост маршрутизатора")
    client_ip = _read_input("IP клиента")
    client_vlan = _read_input("VLAN клиента")
    port = _read_input("Порт на оборудовании")

    if not equipment_ip:
        print("IP конечного оборудования обязателен.", file=sys.stderr)
        sys.exit(1)

    try:
        run_diagnostics(
            model=model,
            equipment_ip=equipment_ip,
            client_ip=client_ip or "-",
            client_vlan=client_vlan or "-",
            port=port or "-",
            router_model=router_model or None,
            router_ip=router_ip or None,
        )
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        print(f"Ошибка SSH: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
