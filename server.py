import socket
import sys
import threading
from typing import Tuple


HOST = "0.0.0.0"
PORT = 5000


# Функция отправки/получения данных от клиента с которым установлено соединение

# conn – объект сокета, представляющий уже установленное
# соединение с конкретным клиентом.

# addr – кортеж вида (ip_адрес_клиента, порт_клиента),
# например ("192.168.1.10", 54321).

#-> None говорит, что функция ничего не возвращает.
def _handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    print(f"Connected by {addr}")
    try:
        while True:

            # Сервер ждёт, пока клиент пришлёт данные, максимум до 4096 байт за один раз.
            data = conn.recv(4096)

            if not data:
                break

            # Преобразуем полученные байты в строку (по умолчанию с системной кодировкой, обычно UTF‑8).
            # errors="replace" означает: если встречаются некорректные байты, их не выбрасывать как ошибку,
            # а заменить специальным символом (чтобы не упасть с исключением при декодировании).
            text = data.decode(errors="replace")

            # Логируем в консоль, что именно пришло от данного клиента.
            print(f"From {addr}: {text!r}")

            # Отправляем клиенту обратно те же самые байты, которые он прислал.
            # Это делает сервер «эхо‑сервером»: он просто отражает то, что получил.
            # sendall гарантирует, что все данные будут отправлены (или возникнет ошибка).
            conn.sendall(data)
    except Exception as exc:  # noqa: BLE001 - broad for connection errors
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

