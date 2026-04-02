"""
Модуль проверки работоспособности сервера диагностики.
Отправляет тестовый запрос (строка параметров через запятую), получает ответ,
печатает результат. Удобно для проверки, что сервер живой и отрабатывает сценарии.

Протокол диагностики (актуальный server.py):
1) первая строка: «{log_id} в обработке» или «{log_id} место в очереди № N ожидайте»
2) после завершения: строка «{log_id}», затем тело отчёта.

Устаревший сервер: «OK» → «{log_id}» → тело — поддерживается для чтения, в stderr — предупреждение.

Служебные команды: ping / stop — см. server.py.
"""
import socket
import sys


HOST = "10.3.1.147"
PORT = 5000

DEFAULT_REQUEST = "stop"


def _read_line(sock: socket.socket, initial: bytes = b"", bufsize: int = 4096) -> tuple[str, bytes]:
    buf = bytearray(initial)
    while b"\n" not in buf:
        data = sock.recv(bufsize)
        if not data:
            line0 = bytes(buf).decode(errors="replace").splitlines()
            return (line0[0].strip() if line0 else ""), b""
        buf.extend(data)
    nl = buf.find(b"\n")
    line_end = nl
    if nl > 0 and buf[nl - 1 : nl] == b"\r":
        line_end = nl - 1
    line = bytes(buf[:line_end]).decode(errors="replace").strip()
    return line, bytes(buf[nl + 1 :])


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
    request = request or DEFAULT_REQUEST
    if verbose:
        print(f"Подключение к {host}:{port}...")
        print(f"Запрос: {request}\n")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(600)
            sock.connect((host, port))
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (OSError, AttributeError):
                pass
            sock.sendall((request.strip() + "\n").encode("utf-8"))

            line1, tail = _read_line(sock, b"")
            if not line1:
                if verbose:
                    print("Сервер закрыл соединение без ответа.", file=sys.stderr)
                return False

            # «OK»: либо ping (OK → PING), либо устаревшая диагностика (OK → 10-значный log_id → отчёт).
            if line1 == "OK":
                line2, rest = _read_line(sock, tail)
                if len(line2) == 10 and line2.isdigit():
                    if verbose:
                        print(
                            "Внимание: на сервере старый протокол (сначала OK, без «в обработке» до диагностики). "
                            "Обновите и перезапустите server.py.\n",
                            file=sys.stderr,
                        )
                        print(f"{line2}\n")
                    content = _read_rest(sock, initial=rest)
                    if verbose:
                        print(content)
                    return True
                if line2 == "PING" or line2.startswith("PING"):
                    content = _read_rest(sock, initial=rest)
                    if verbose:
                        print("OK\n")
                        out = line2
                        if content:
                            out = out + "\n" + content
                        print(out)
                    return True
                if verbose:
                    print("OK\n")
                    if line2:
                        print(line2)
                    print(_read_rest(sock, initial=rest))
                return True

            if line1.startswith("ERROR"):
                if verbose:
                    print(f"Ошибка: {line1}", file=sys.stderr)
                return False

            head = line1.split(None, 1)
            if len(head) < 1 or len(head[0]) != 10 or not head[0].isdigit():
                if verbose:
                    print(f"Неожиданная первая строка: {line1!r}", file=sys.stderr)
                return False

            log_id = head[0]
            if verbose:
                print(f"Ранний ответ сервера: {line1}\n")

            line2, rest = _read_line(sock, tail)
            if not line2:
                if verbose:
                    print("Нет итоговой строки от сервера.", file=sys.stderr)
                return False
            if line2.startswith("ERROR"):
                if verbose:
                    print(f"Ошибка: {line2}", file=sys.stderr)
                return False
            if line2 != log_id:
                if verbose:
                    print(
                        f"Ожидался log_id {log_id!r}, получено: {line2!r}",
                        file=sys.stderr,
                    )
                return False

            content = _read_rest(sock, initial=rest)
            if verbose:
                print(f"{log_id}\n")
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
