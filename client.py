import socket
import sys


HOST = "10.3.1.147"  # IP Linux-сервера
PORT = 5000          # Порт сервера


def _read_line(sock: socket.socket, bufsize: int = 4096) -> str:
    """Читает из сокета до перевода строки или закрытия."""
    buf = b""
    while b"\n" not in buf and b"\r\n" not in buf:
        data = sock.recv(bufsize)
        if not data:
            break
        buf += data
    line = buf.decode(errors="replace").splitlines()
    return line[0].strip() if line else ""


def _read_rest(sock: socket.socket, bufsize: int = 65536) -> str:
    """Читает из сокета всё до закрытия соединения."""
    chunks = []
    while True:
        data = sock.recv(bufsize)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def main() -> None:
    """
    Клиент диагностики: подключается к серверу, вводит параметры диагностики,
    отправляет их серверу. Сервер выполняет диагностику и сохраняет файл у себя,
    в ответ приходит OK или ERROR.
    """
    host = HOST
    port = PORT

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            print(f"Connecting to {host}:{port}...")
            sock.connect((host, port))
            print("Подключено. Введите параметры диагностики (пустой ввод — пропуск).\n")
        except Exception as exc:
            print(f"Connection error: {exc}", file=sys.stderr)
            sys.exit(1)

        try:
            prompts = [
                ("Модель конечного оборудования (имя сценария без .txt)", "generic"),
                ("IP или хост конечного оборудования", ""),
                ("Модель маршрутизатора (имя сценария без .txt)", ""),
                ("IP или хост маршрутизатора", ""),
                ("IP клиента", ""),
                ("VLAN клиента", ""),
                ("Порт на оборудовании", ""),
            ]
            lines = []
            for prompt, default in prompts:
                if default:
                    value = input(f"{prompt} [{default}]: ").strip() or default
                else:
                    value = input(f"{prompt}: ").strip()
                lines.append(value)

            if not lines[1]:
                print("IP конечного оборудования обязателен.", file=sys.stderr)
                sys.exit(1)

            payload = ",".join(lines) + "\n"
            sock.sendall(payload.encode())

            response = _read_line(sock)
            if not response:
                print("Server closed the connection.")
            elif response == "OK":
                content = _read_rest(sock)
                print(content)
            else:
                print(f"Ошибка: {response}", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nClient interrupted by user.")


if __name__ == "__main__":
    main()
