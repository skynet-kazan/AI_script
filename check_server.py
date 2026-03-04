"""
Модуль проверки работоспособности сервера диагностики.
Отправляет тестовый запрос (строка параметров через запятую), получает ответ,
печатает результат. Удобно для проверки, что сервер живой и отрабатывает сценарии.
"""
import socket
import sys


HOST = "10.3.1.147"
PORT = 5000

# Стандартный тестовый запрос (модель оборудования, IP оборудования, модель роутера, хост роутера, IP клиента, VLAN, порт)
DEFAULT_REQUEST = "SNR-S2960-24G, 10.135.2.137, cisco_asr1002, shv-1002.loc, 172.200.138.251, 1549, 6"


def _read_line(sock: socket.socket, bufsize: int = 4096) -> str:
    buf = b""
    while b"\n" not in buf and b"\r\n" not in buf:
        data = sock.recv(bufsize)
        if not data:
            break
        buf += data
    line = buf.decode(errors="replace").splitlines()
    return line[0].strip() if line else ""


def _read_rest(sock: socket.socket, bufsize: int = 65536) -> str:
    chunks = []
    while True:
        data = sock.recv(bufsize)
        if not data:
            break
        chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def check_server(
    host: str = HOST,
    port: int = PORT,
    request: str | None = None,
    verbose: bool = True,
) -> bool:
    """
    Отправляет на сервер строку request (параметры через запятую), читает ответ.
    Возвращает True при успехе (OK + вывод), False при ошибке или отсутствии ответа.
    """
    request = request or DEFAULT_REQUEST
    if verbose:
        print(f"Подключение к {host}:{port}...")
        print(f"Запрос: {request}\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(300)
            sock.connect((host, port))
            sock.sendall((request.strip() + "\n").encode())

            status = _read_line(sock)
            if not status:
                if verbose:
                    print("Сервер закрыл соединение без ответа.", file=sys.stderr)
                return False
            if status != "OK":
                if verbose:
                    print(f"Ошибка: {status}", file=sys.stderr)
                return False

            content = _read_rest(sock)
            if verbose:
                print("OK\n")
                print(content)
            return True
    except socket.timeout:
        if verbose:
            print("Таймаут ожидания ответа сервера.", file=sys.stderr)
        return False
    except Exception as e:
        if verbose:
            print(f"Ошибка: {e}", file=sys.stderr)
        return False


def main() -> None:
    host = HOST
    port = PORT
    if len(sys.argv) >= 2:
        request = sys.argv[1]
    else:
        request = DEFAULT_REQUEST

    ok = check_server(host=host, port=port, request=request, verbose=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
