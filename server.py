import socket
import sys
import threading
from typing import Tuple

from equipment_diagnostics import run_diagnostics
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException


HOST = "0.0.0.0"
PORT = 5000

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


def _send_response(conn: socket.socket, msg: bytes, addr: Tuple[str, int]) -> None:
    try:
        conn.sendall(msg)
    except (BrokenPipeError, ConnectionResetError, OSError) as e:
        print(f"[{addr}] Не удалось отправить ответ клиенту: {e}", file=sys.stderr)


def _handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    print(f"[{addr}] Подключение.")
    try:
        line = _read_line(conn)
        if not line:
            print(f"[{addr}] Пустой запрос.")
            _send_response(conn, b"ERROR: No data received\n", addr)
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
        router_ip = params["router_ip"].strip() or None
        client_ip = params["client_ip"] or "-"
        client_vlan = params["client_vlan"] or "-"
        port = params["port"] or "-"

        print(f"[{addr}] Подключение успешно. Параметры: equipment={equipment_ip}, router={router_ip or '-'}")
        print(f"[{addr}] Запуск диагностики...")

        full_output, out_path = run_diagnostics(
            model=model,
            equipment_ip=equipment_ip,
            client_ip=client_ip,
            client_vlan=client_vlan,
            port=port,
            router_model=router_model,
            router_ip=router_ip,
        )

        print(f"[{addr}] Диагностика завершена. Отправка ответа клиенту ({len(full_output)} символов).")
        _send_response(conn, b"OK\n", addr)
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
        print(f"[{addr}] Соединение закрыто.")
        try:
            conn.close()
        except OSError:
            pass


def start_server(host: str = HOST, port: int = PORT) -> None:
    """

    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen()
        print(f"Server listening on {host}:{port}")

        while True:

            # ждёт, пока какой‑то клиент попытается подключиться к host:port.
            conn, addr = sock.accept()

            # Создание потока для клиента
            thread = threading.Thread(
                target=_handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()

