import os
import select
import socket
import sys
import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, FrozenSet, Optional, Set, Tuple

from equipment_diagnostics import reserve_diagnostics_output_file, run_diagnostics
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


HOST = "0.0.0.0"
PORT = 5000

# Версия протокола диагностики по TCP. Смените при изменении формата ответов.
# Проверка с клиента: отправить одну строку «protocol» — в ответ будет diagnostics-tcp-rev-N.
DIAGNOSTICS_TCP_PROTOCOL_REV = 2

# Команда «stop»: выставляется в потоке клиента; главный поток выходит из accept — процесс завершается без os._exit.
_shutdown_requested = threading.Event()

PARAM_NAMES = (
    "model",
    "equipment_ip",
    "router_model",
    "router_ip",
    "client_ip",
    "client_vlan",
    "port",
)
NUM_PARAMS = len(PARAM_NAMES)


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


def _diagnostic_target_ips(equipment_ip: str, router_ip: Optional[str]) -> FrozenSet[str]:
    ips: set[str] = {_normalize_target_key(equipment_ip)}
    if router_ip and str(router_ip).strip():
        ips.add(_normalize_target_key(str(router_ip)))
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
        while len(parts) < NUM_PARAMS:
            parts.append("")
        lines = parts[:NUM_PARAMS]
        params = dict(zip(PARAM_NAMES, lines))
        model = params["model"] or "generic"
        equipment_ip = params["equipment_ip"]
        if not equipment_ip:
            _send_response(conn, b"ERROR: equipment_ip is required\n", addr)
            return

        router_model = params["router_model"].strip() or None
        router_ip_raw = params["router_ip"].strip() or ""
        router_ip = _normalize_router_host(router_ip_raw) or None
        client_ip = params["client_ip"] or "-"
        client_vlan = params["client_vlan"] or "-"
        port = params["port"] or "-"

        target_ips = _diagnostic_target_ips(equipment_ip, router_ip)
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

        print(
            f"[{addr}] Подключение успешно. log_id={log_id} Параметры: equipment={equipment_ip}, "
            f"router={router_ip or '-'}"
        )
        print(f"[{addr}] Запуск диагностики...")

        full_output, out_path = run_diagnostics(
            {
                "model": model,
                "equipment_ip": equipment_ip,
                "client_ip": client_ip,
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
        _send_response(conn, f"ERROR: {e}\n".encode(), addr)
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        print(f"[{addr}] Ошибка SSH: {e}", file=sys.stderr)
        _send_response(conn, f"ERROR: SSH: {e}\n".encode(), addr)
    except Exception as exc:
        print(f"[{addr}] Ошибка: {exc}", file=sys.stderr)
        _send_response(conn, f"ERROR: {exc}\n".encode(), addr)
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
