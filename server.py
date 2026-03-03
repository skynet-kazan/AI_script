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


def _handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    print(f"Connected by {addr}")
    try:
        line = _read_line(conn)
        if not line:
            conn.sendall(b"ERROR: No data received\n")
            return

        parts = [p.strip() for p in line.split(",")]
        while len(parts) < NUM_PARAMS:
            parts.append("")
        lines = parts[:NUM_PARAMS]

        params = dict(zip(PARAM_NAMES, lines))
        model = params["model"] or "generic"
        equipment_ip = params["equipment_ip"]
        if not equipment_ip:
            conn.sendall(b"ERROR: equipment_ip is required\n")
            return

        router_model = params["router_model"].strip() or None
        router_ip = params["router_ip"].strip() or None
        client_ip = params["client_ip"] or "-"
        client_vlan = params["client_vlan"] or "-"
        port = params["port"] or "-"

        print(f"From {addr}: running diagnostics equipment={equipment_ip} router={router_ip or '-'}")

        _, out_path = run_diagnostics(
            model=model,
            equipment_ip=equipment_ip,
            client_ip=client_ip,
            client_vlan=client_vlan,
            port=port,
            router_model=router_model,
            router_ip=router_ip,
        )
        conn.sendall(f"OK: Diagnostics completed. File on server: {out_path}\n".encode())
    except FileNotFoundError as e:
        conn.sendall(f"ERROR: {e}\n".encode())
        print(f"Error with {addr}: {e}", file=sys.stderr)
    except (NetmikoAuthenticationException, NetmikoTimeoutException) as e:
        conn.sendall(f"ERROR: SSH: {e}\n".encode())
        print(f"Error with {addr}: {e}", file=sys.stderr)
    except Exception as exc:
        conn.sendall(f"ERROR: {exc}\n".encode())
        print(f"Error with {addr}: {exc}", file=sys.stderr)
    finally:
        print(f"Connection closed: {addr}")
        conn.close()


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

