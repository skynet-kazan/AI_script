import os
import re
import select
import socket
import sys
import threading
import traceback
from collections import deque
from dataclasses import dataclass
from typing import Deque, FrozenSet, Optional, Set, Tuple

from equipment_diagnostics import reserve_diagnostics_output_file, run_diagnostics
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


HOST = "0.0.0.0"
PORT = 5000

# Версия протокола диагностики по TCP. Смените при изменении формата ответов.
# Проверка с клиента: отправить одну строку «protocol» — в ответ будет diagnostics-tcp-rev-N.
DIAGNOSTICS_TCP_PROTOCOL_REV = 4

# Команда «stop»: выставляется в потоке клиента; главный поток выходит из accept — процесс завершается без os._exit.
_shutdown_requested = threading.Event()

MIKROTIK_WIRELESS_60G_MODEL = "mikrotik wireless 60g"

_OUTER_VLAN_FIELD_RE = re.compile(r"^o(\d+)$", re.IGNORECASE)
_ST_AP_IP_RE = re.compile(r"^(?:ST|AP)\s+(.+)$", re.IGNORECASE)


def _parse_role_prefixed_ip(field: str) -> str:
    """Из поля «ST 10.0.0.1» / «AP 10.0.0.2» извлекает IP."""
    raw = (field or "").strip()
    m = _ST_AP_IP_RE.match(raw)
    return m.group(1).strip() if m else raw


def _parse_diagnostic_request(parts: list[str]) -> dict[str, str]:
    """
    Разбор TCP-запроса диагностики.

    Mikrotik Wireless 60G (7 полей):
      model, ST <ip>, AP <ip>, router_model, router_ip, client_ip, vlan

    Стандарт без OuterVlan (7 полей):
      model, equipment_ip, router_model, router_ip, client_ip, vlan, port

    Стандарт с OuterVlan (8 полей, поле oNNNN перед основным VLAN):
      model, equipment_ip, router_model, router_ip, client_ip, o3001, vlan, port
    """
    while len(parts) < 7:
        parts.append("")

    model = parts[0].strip() or "generic"
    if model.lower() == MIKROTIK_WIRELESS_60G_MODEL:
        st_ip = _parse_role_prefixed_ip(parts[1])
        ap_ip = _parse_role_prefixed_ip(parts[2])
        return {
            "model": model,
            "request_kind": "mikrotik_wireless_60g",
            "st_ip": st_ip,
            "ap_ip": ap_ip,
            "equipment_ip": ap_ip,
            "router_model": parts[3].strip(),
            "router_ip": parts[4].strip(),
            "client_ip": parts[5].strip() or "-",
            "client_vlan": parts[6].strip() or "-",
            "outer_vlan": "",
            "port": "-",
        }

    outer_vlan = ""
    field5 = parts[5].strip()
    if len(parts) >= 8 and (m := _OUTER_VLAN_FIELD_RE.match(field5)):
        outer_vlan = m.group(1)
        client_vlan = parts[6].strip() or "-"
        port = parts[7].strip() or "-"
    else:
        client_vlan = field5 or "-"
        port = parts[6].strip() or "-"

    return {
        "model": model,
        "request_kind": "standard",
        "st_ip": "",
        "ap_ip": "",
        "equipment_ip": parts[1].strip(),
        "router_model": parts[2].strip(),
        "router_ip": parts[3].strip(),
        "client_ip": parts[4].strip() or "-",
        "outer_vlan": outer_vlan,
        "client_vlan": client_vlan,
        "port": port,
    }


# --- Очередь: не запускать параллельно диагностику, если занят equipment_ip или router_ip ---

_diag_queue_lock = threading.Lock()
_running_ips: Set[str] = set()
_wait_queue: Deque["_WaitEntry"] = deque()
_next_queue_ticket = 1


@dataclass
class _WaitEntry:
    event: threading.Event
    ips: FrozenSet[str]
    ticket: int


def _normalize_target_key(host: str) -> str:
    """Единый ключ для сравнения хостов в очереди (в т.ч. регистр имён)."""
    return (host or "").strip().lower()


def _diagnostic_target_ips(
    equipment_ip: str,
    router_ip: Optional[str],
    *,
    ap_ip: Optional[str] = None,
    st_ip: Optional[str] = None,
) -> FrozenSet[str]:
    ips: set[str] = set()
    for host in (equipment_ip, router_ip, ap_ip, st_ip):
        if host and str(host).strip():
            ips.add(_normalize_target_key(str(host)))
    return frozenset(ips)


def _enqueue_or_acquire_ips(ips: FrozenSet[str]) -> Tuple[bool, int, int, Optional[threading.Event]]:
    """
    Если есть пересечение с уже выполняющимися IP — постановка в FIFO-очередь.
    Иначе — сразу резервируем IP под текущий поток.

    Возвращает:
    - immediate: True если слот уже наш (очередь не нужна)
    - ticket: номер заявки в очереди (0 если immediate)
    - position: позиция в момент постановки (0 если immediate)
    - wait_event: событие ожидания, если immediate == False
    """
    global _next_queue_ticket, _running_ips, _wait_queue
    with _diag_queue_lock:
        if _running_ips & ips:
            ticket = _next_queue_ticket
            _next_queue_ticket += 1
            ev = threading.Event()
            _wait_queue.append(_WaitEntry(event=ev, ips=ips, ticket=ticket))
            position = len(_wait_queue)
            print(
                f"[queue] QUEUE ticket={ticket} pos={position} "
                f"targets={sorted(ips)} busy={sorted(_running_ips)} "
                f"({threading.current_thread().name})"
            )
            return False, ticket, position, ev
        _running_ips |= ips
        print(
            f"[queue] RUN  targets={sorted(ips)} busy_after={sorted(_running_ips)} "
            f"({threading.current_thread().name})"
        )
        return True, 0, 0, None


def _release_diagnostic_slot_and_wake_next(ips: FrozenSet[str]) -> None:
    """Снимает резерв IP и будит следующий допустимый запрос из очереди (FIFO)."""
    global _running_ips, _wait_queue
    with _diag_queue_lock:
        _running_ips -= ips
        while _wait_queue:
            head = _wait_queue[0]
            if head.ips & _running_ips:
                break
            _wait_queue.popleft()
            _running_ips |= head.ips
            head.event.set()


def _normalize_router_host(host: str) -> str:
    """
    Нормализует хост маршрутизатора, если он приходит с хвостом интерфейса:
    например: "cher-1002 0/1/0" -> "cher-1002.loc"
    """
    h = (host or "").strip()
    if not h:
        return ""

    # Отбрасываем всё после первого пробела (хвост "0/1/0").
    h = h.split()[0].strip()
    if not h:
        return ""

    # Если домен уже указан (есть '.'), оставляем как есть.
    if "." in h:
        return h

    # Если домена нет — добавляем ".loc" (согласно вашему формату mag-1002.loc).
    return f"{h}.loc"


def _read_line(conn: socket.socket, bufsize: int = 4096) -> str:
    """Читает из сокета одну строку (до \\n)."""
    buf = b""
    while b"\n" not in buf and b"\r\n" not in buf:
        data = conn.recv(bufsize)
        if not data:
            break
        buf += data
    line = buf.decode(errors="replace").splitlines()
    return line[0].strip() if line else ""


def _set_tcp_nodelay(conn: socket.socket) -> None:
    """Отключает алгоритм Нейгла — иначе короткий ранний ACK может склеиться с большим финальным ответом."""
    try:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass


def _send_response(conn: socket.socket, msg: bytes, addr: Tuple[str, int]) -> None:
    try:
        conn.sendall(msg)
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"[{addr}] Не удалось отправить ответ клиенту: {e}", file=sys.stderr)


def _handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    print(f"[{addr}] Подключение.")
    _set_tcp_nodelay(conn)
    reserved_ips: Optional[FrozenSet[str]] = None
    try:
        # Важно: резерв IP в очереди делается только после этой строки. Если клиент
        # открыл сокет, но отправит запрос позже (например после ответа по другому
        # соединению), слот может уже освободиться — пересечения не будет, QUEUED не уйдёт.
        print(f"[{addr}] Ожидание строки запроса...")
        line = _read_line(conn)
        print(f"[{addr}] Строка запроса получена ({len(line)} симв.).")
        if not line:
            print(f"[{addr}] Пустой запрос.")
            _send_response(conn, b"ERROR: No data received\n", addr)
            return

        # Служебная команда для остановки сервера.
        req = line.strip().lower()
        if req == "protocol":
            _send_response(
                conn,
                f"diagnostics-tcp-rev-{DIAGNOSTICS_TCP_PROTOCOL_REV}\n".encode("utf-8"),
                addr,
            )
            return
        if req == "ping":
            # Одна запись: два send подряд + немедленный close на Windows иногда
            # отдают клиенту только первый фрагмент.
            _send_response(conn, b"OK\nPING\n", addr)
            return
        if req == "stop" or req.startswith("stop,"):
            print(f"[{addr}] Получена команда stop. Завершение работы сервера (выход из accept).")
            _send_response(conn, b"OK\n", addr)
            try:
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            _shutdown_requested.set()
            return

        parts = [p.strip() for p in line.split(",")]
        params = _parse_diagnostic_request(parts)
        model = params["model"]
        request_kind = params.get("request_kind", "standard")
        st_ip = params.get("st_ip", "").strip()
        ap_ip = params.get("ap_ip", "").strip()
        equipment_ip = params.get("equipment_ip", "").strip()

        if request_kind == "mikrotik_wireless_60g":
            if not ap_ip or not st_ip:
                _send_response(conn, b"ERROR: AP and ST IP are required for Mikrotik Wireless 60G\n", addr)
                return
        elif not equipment_ip:
            _send_response(conn, b"ERROR: equipment_ip is required\n", addr)
            return

        router_model = params["router_model"].strip() or None
        router_ip_raw = params["router_ip"].strip() or ""
        router_ip = _normalize_router_host(router_ip_raw) or None
        client_ip = params["client_ip"]
        outer_vlan = params["outer_vlan"]
        client_vlan = params["client_vlan"]
        port = params["port"]

        target_ips = _diagnostic_target_ips(
            equipment_ip,
            router_ip,
            ap_ip=ap_ip or None,
            st_ip=st_ip or None,
        )
        immediate, ticket, position, wait_ev = _enqueue_or_acquire_ips(target_ips)

        log_id, out_path = reserve_diagnostics_output_file()
        if not immediate:
            ack = f"{log_id} место в очереди № {position} ожидайте\n"
            _send_response(conn, ack.encode("utf-8"), addr)
            print(
                f"[{addr}] Ожидание очереди: log_id={log_id} ticket={ticket}, position={position}, "
                f"targets={sorted(target_ips)}"
            )
            assert wait_ev is not None
            wait_ev.wait()
            print(f"[{addr}] Очередь: освобождён слот, запуск диагностики.")
        else:
            _send_response(conn, f"{log_id} в обработке\n".encode("utf-8"), addr)

        reserved_ips = target_ips

        if request_kind == "mikrotik_wireless_60g":
            target_info = f"AP={ap_ip}, ST={st_ip}, router={router_ip or '-'}"
        else:
            target_info = f"equipment={equipment_ip}, router={router_ip or '-'}"
        outer_info = f", outer_vlan={outer_vlan}" if outer_vlan else ""
        print(
            f"[{addr}] Подключение успешно. log_id={log_id} Параметры: {target_info}, "
            f"vlan={client_vlan}{outer_info}, port={port}"
        )
        print(f"[{addr}] Запуск диагностики...")

        full_output, out_path = run_diagnostics(
            {
                "model": model,
                "request_kind": request_kind,
                "equipment_ip": equipment_ip,
                "st_ip": st_ip,
                "ap_ip": ap_ip,
                "client_ip": client_ip,
                "outer_vlan": outer_vlan,
                "client_vlan": client_vlan,
                "port": port,
                "router_model": router_model,
                "router_ip": router_ip,
            },
            out_path=out_path,
        )

        print(f"[{addr}] Диагностика завершена. Отправка ответа клиенту ({len(full_output)} символов).")
        # Итог: первая строка — тот же log_id для сопоставления на клиенте, далее тело отчёта (без префикса OK).
        _send_response(conn, f"{log_id}\n".encode("utf-8"), addr)
        _send_response(conn, full_output.encode("utf-8"), addr)
    except FileNotFoundError as e:
        print(f"[{addr}] Ошибка: {e}", file=sys.stderr)
        _send_response(
            conn,
            f"ERROR: {type(e).__name__}: {e!s}\n".encode("utf-8"),
            addr,
        )
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        print(f"[{addr}] Ошибка подключения Netmiko: {e}", file=sys.stderr)
        _send_response(
            conn,
            f"ERROR: NETMIKO_CONNECTION: {e!s}\n".encode("utf-8"),
            addr,
        )
    except Exception as exc:
        print(f"[{addr}] Ошибка: {exc}", file=sys.stderr)
        # Многие исключения имеют пустой .__str__ — покажем repr, чтобы клиент видел причину.
        first_tb_line = traceback.format_exc().splitlines()[-1] if traceback.format_exc() else ""
        _send_response(
            conn,
            f"ERROR: {type(exc).__name__}: {exc!r}\n".encode("utf-8"),
            addr,
        )
    finally:
        if reserved_ips is not None:
            _release_diagnostic_slot_and_wake_next(reserved_ips)
        print(f"[{addr}] Соединение закрыто.")
        try:
            conn.close()
        except OSError:
            pass


def start_server(host: str = HOST, port: int = PORT) -> None:
    _shutdown_requested.clear()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen()
        print(
            f"Server listening on {host}:{port} | diagnostics-tcp rev={DIAGNOSTICS_TCP_PROTOCOL_REV} "
            f"| файл: {__file__}"
        )
        print(
            "Проверка деплоя: отправьте по TCP строку «protocol» — должно вернуться "
            f"diagnostics-tcp-rev-{DIAGNOSTICS_TCP_PROTOCOL_REV}"
        )

        # accept с таймаутом через select: чтобы после «stop» выйти из цикла и закрыть listening socket.
        while True:
            if _shutdown_requested.is_set():
                print("Сервер остановлен по команде stop (процесс завершается штатно).")
                break
            try:
                readable, _, _ = select.select([sock], [], [], 1.0)
            except (ValueError, OSError):
                break
            if not readable:
                continue
            try:
                conn, addr = sock.accept()
            except OSError:
                continue
            thread = threading.Thread(
                target=_handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()
