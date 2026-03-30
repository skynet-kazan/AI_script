"""
Модуль проверки работоспособности сервера диагностики.
Отправляет тестовый запрос (строка параметров через запятую), получает ответ,
печатает результат. Удобно для проверки, что сервер живой и отрабатывает сценарии.
"""
import socket
import sys


# Для теста на этой же машине укажите 127.0.0.1
HOST = "10.3.1.147"
PORT = 5000

# Стандартный тестовый запрос (модель оборудования, IP оборудования, модель роутера, хост роутера, IP клиента, VLAN, порт)
DEFAULT_REQUEST = "stop"

def _read_status_line(sock: socket.socket, bufsize: int = 4096) -> tuple[str, bytes]:
    """
    Читает одну строку статуса (до \\n / \\r\\n) и возвращает:
    - строку статуса
    - "остаток" байт, которые уже пришли в сокет после конца строки статуса
      (важно, чтобы не потерять начало тела ответа).
    """
    buf = bytearray()
    while True:
        # Поиск разделителя строки в уже накопленном буфере.
        nl = buf.find(b"\n")
        if nl != -1:
            # если было \r\n, то отрезаем \r тоже
            line_end = nl
            if nl > 0 and buf[nl - 1:nl] == b"\r":
                line_end = nl - 1
            status = bytes(buf[:line_end]).decode(errors="replace").strip()
            rest = bytes(buf[nl + 1:])
            return status, rest

        data = sock.recv(bufsize)
        if not data:
            # соединение закрыто, статуса может не быть
            return (
                (bytes(buf).decode(errors="replace").splitlines()[0].strip() if buf else ""),
                b"",
            )
        buf.extend(data)


def _read_rest(sock: socket.socket, initial: bytes = b"", bufsize: int = 65536) -> str:
    chunks: list[bytes] = [initial] if initial else []
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

            status, rest = _read_status_line(sock)
            if not status:
                if verbose:
                    print("Сервер закрыл соединение без ответа.", file=sys.stderr)
                return False
            if status != "OK":
                if verbose:
                    print(f"Ошибка: {status}", file=sys.stderr)
                return False

            content = _read_rest(sock, initial=rest)
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
