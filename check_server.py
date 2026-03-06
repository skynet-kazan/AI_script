"""
Модуль проверки работоспособности сервера диагностики.
Отправляет тестовый запрос (строка параметров через запятую), получает ответ,
печатает результат. Удобно для проверки, что сервер живой и отрабатывает сценарии.
"""
import socket
import sys


# Сервер диагностики на Linux (сюда шлём запрос с этой машины). Можно переопределить: python check_server.py [host] [port] [запрос]
HOST = "10.3.1.147"
PORT = 5000

# Стандартный тестовый запрос (модель оборудования, IP оборудования, модель роутера, хост роутера, IP клиента, VLAN, порт)
DEFAULT_REQUEST = "BDCOM GP3600-04, 10.128.10.122, cisco_asr1002, vst.loc, 10.100.10.5, 1345, 0/1:3"


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
    except ConnectionRefusedError:
        if verbose:
            print(f"Соединение отклонено: {host}:{port}. Запущен ли сервер? (python server.py)", file=sys.stderr)
        return False
    except OSError as e:
        if verbose:
            print(f"Ошибка сети: {e}. Проверьте хост {host} и порт {port}.", file=sys.stderr)
        return False
    except Exception as e:
        if verbose:
            print(f"Ошибка: {e}", file=sys.stderr)
        return False


def main() -> None:
    # Аргументы: [host] [port] [запрос]
    # Варианты: без аргументов; один аргумент = запрос; два = host port; три = host port запрос
    args = sys.argv[1:]
    host, port, request = HOST, PORT, DEFAULT_REQUEST
    if len(args) >= 2 and args[1].isdigit():
        host, port = args[0], int(args[1])
        request = ",".join(args[2:]).strip() or DEFAULT_REQUEST
    elif len(args) == 1:
        request = args[0]
    elif len(args) >= 1:
        request = ",".join(args).strip() or DEFAULT_REQUEST

    ok = check_server(host=host, port=port, request=request, verbose=True)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
