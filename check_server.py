"""
Модуль проверки работоспособности сервера диагностики.
Отправляет тестовый запрос (строка параметров через запятую), получает ответ,
печатает результат. Удобно для проверки, что сервер живой и отрабатывает сценарии.
"""
import argparse
import os
import socket
import sys


# По умолчанию — локально; переопределите через --host или CHECK_SERVER_HOST.
_HOST_ENV = os.environ.get("CHECK_SERVER_HOST", "10.3.1.147")
_PORT_ENV = int(os.environ.get("CHECK_SERVER_PORT", "5000"))

# «Живой» сервер: команда ping в server.py (не используйте stop — она убивает процесс).
_DEFAULT_REQUEST = "ping"


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
    host: str = _HOST_ENV,
    port: int = _PORT_ENV,
    request: str | None = None,
    verbose: bool = True,
    connect_timeout: float = 10.0,
) -> bool:
    """
    Отправляет на сервер строку request (параметры через запятую), читает ответ.
    Возвращает True при успехе (OK + вывод), False при ошибке или отсутствии ответа.
    """
    request = (request or _DEFAULT_REQUEST).strip()
    if verbose:
        print(f"Подключение к {host}:{port} (TCP)...")
        print(f"Запрос: {request!r}\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(connect_timeout)
            try:
                sock.connect((host, port))
            except (ConnectionRefusedError, OSError) as e:
                if verbose:
                    print(
                        f"Не удалось установить TCP-соединение: {e}\n"
                        f"ICMP ping до хоста и доступность TCP-порта {port} — разные вещи: "
                        f"проверьте, что на {host} слушает server.py ({host}:5000 и 0.0.0.0, не только 127.0.0.1), "
                        f"и правила брандмауэра для входящих TCP/{port}.",
                        file=sys.stderr,
                    )
                return False
            sock.settimeout(300)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            payload = (request + "\n").encode("utf-8")
            sock.sendall(payload)

            status, rest = _read_status_line(sock)
            if not status:
                if verbose:
                    print(
                        "Сервер закрыл соединение без ответной строки. "
                        "Если на сервере старая версия без команды «ping», "
                        "обновите server.py или отправьте полную строку параметров диагностики.",
                        file=sys.stderr,
                    )
                return False
            if status != "OK":
                if verbose:
                    print(f"Первая строка ответа (не OK): {status!r}", file=sys.stderr)
                    if request.lower() == "ping" and "equipment_ip" in status:
                        print(
                            "Похоже, на удалённой машине нет обработчика «ping»: "
                            'запрос воспринят как CSV и отклонён. Залейте актуальный server.py.',
                            file=sys.stderr,
                        )
                    if status.startswith("QUEUED"):
                        print(
                            "Сервер вернул очередь; для «проверки живости» используйте ping в простое время "
                            "или дождитесь полного ответа вручную.",
                            file=sys.stderr,
                        )
                return False

            content = _read_rest(sock, initial=rest)
            if verbose:
                print("OK\n")
                print(content)
            return True
    except socket.timeout:
        if verbose:
            print(
                "Таймаут ожидания ответа сервера. "
                "Проверьте сеть и не отправляйте «stop» для проверки — она завершает процесс.",
                file=sys.stderr,
            )
        return False
    except Exception as e:
        if verbose:
            print(f"Ошибка: {e}", file=sys.stderr)
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Проверка TCP-сервера диагностики.")
    parser.add_argument(
        "--host",
        default=_HOST_ENV,
        help=f"Адрес сервера (по умолчанию env CHECK_SERVER_HOST или {_HOST_ENV!r})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=_PORT_ENV,
        help=f"Порт (по умолчанию env CHECK_SERVER_PORT или {_PORT_ENV})",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=10.0,
        help="Таймаут установки TCP-соединения (сек).",
    )
    parser.add_argument(
        "request",
        nargs="?",
        default=_DEFAULT_REQUEST,
        help=f"Строка запроса (по умолчанию {_DEFAULT_REQUEST!r}). Не используйте stop для проверки.",
    )
    args = parser.parse_args()

    ok = check_server(
        host=args.host,
        port=args.port,
        request=args.request,
        verbose=True,
        connect_timeout=args.connect_timeout,
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
