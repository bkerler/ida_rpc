# (c) B. Kerler 2026, MIT license
"""Local socket server for ida-rpc.

Accepts newline-delimited JSON requests and dispatches to tool handlers.
"""

from __future__ import annotations

import json
import logging
import queue
import select
import socket
import sys
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from ida_rpc.session import Session, remove as remove_session
from ida_rpc.transport import create_server_socket, remove_endpoint_marker

logger = logging.getLogger("ida-rpc.server")

_HANDLERS: dict[str, Any] = {}
_HANDLER_LOCK = threading.Lock()


@dataclass
class _QueuedRequest:
    cmd: str
    args: dict
    done: threading.Event
    result: Any = None
    error: BaseException | None = None


def register_handler(cmd: str, handler):
    """Register a command handler function."""
    _HANDLERS[cmd] = handler


def _handle_connection(
    conn: socket.socket,
    ctx: Any,
    shutdown_event: threading.Event,
    dispatch: Callable[[str, dict], Any] | None = None,
):
    """Handle a single client connection: read request, dispatch, send response."""
    try:
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk

        line = buf.decode("utf-8").strip()
        if not line:
            return

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            response = {
                "id": None,
                "ok": False,
                "error": "InvalidJSON",
                "message": f"Malformed JSON: {e}",
            }
            conn.sendall((json.dumps(response) + "\n").encode())
            return

        req_id = request.get("id", str(uuid.uuid4()))
        cmd = request.get("cmd", "")
        args = request.get("args", {})

        if cmd == "ping":
            response = {"id": req_id, "ok": True, "result": {"status": "alive"}}
        elif cmd == "stop":
            response = {"id": req_id, "ok": True, "result": {"status": "stopping"}}
            conn.sendall((json.dumps(response) + "\n").encode())
            shutdown_event.set()
            return
        elif cmd in _HANDLERS:
            try:
                if dispatch is not None:
                    result = dispatch(cmd, args)
                else:
                    def _dispatch():
                        with _HANDLER_LOCK:
                            return _HANDLERS[cmd](ctx, args)

                    # If the context can dispatch to IDA's main thread, use it.
                    # This is required because many IDA APIs throw
                    # "Function can be called from the main thread only"
                    # when called from a background thread.
                    if hasattr(ctx, "run_on_main_thread"):
                        result = ctx.run_on_main_thread(_dispatch)
                    else:
                        result = _dispatch()

                response = {"id": req_id, "ok": True, "result": result}
            except Exception as e:
                error_type = type(e).__name__
                response = {
                    "id": req_id,
                    "ok": False,
                    "error": error_type,
                    "message": str(e),
                }
                logger.error(f"Error handling '{cmd}': {e}", exc_info=True)
        else:
            response = {
                "id": req_id,
                "ok": False,
                "error": "UnknownCommand",
                "message": f"Unknown command: {cmd}. Available: {sorted(list(_HANDLERS.keys()) + ['ping', 'stop'])}",
            }

        conn.sendall((json.dumps(response) + "\n").encode())

    except Exception as e:
        logger.error(f"Connection handler error: {e}", exc_info=True)
    finally:
        conn.close()


def run_server(session: Session, ctx: Any, *, synchronous: bool = False) -> None:
    """Run the RPC server on a local Unix or loopback TCP socket.

    Blocks until a 'stop' command is received or the process is interrupted.

    Args:
        synchronous: If True, handle connections on the calling thread
            (use in headless mode so IDA APIs run on the main thread).
            If False, spawn a thread per connection (GUI mode).
    """
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    from ida_rpc.server.tools import register_all_tools
    register_all_tools()

    sock_path = session.socket_path
    server_sock = create_server_socket(sock_path)
    server_sock.setblocking(False)

    shutdown_event = threading.Event()

    logger.info(f"ida-rpc server listening on {sock_path}")
    print(f"ida-rpc server listening on {sock_path}", file=sys.stderr)

    request_queue: queue.Queue[_QueuedRequest] = queue.Queue()

    def _queued_dispatch(cmd: str, args: dict) -> Any:
        request = _QueuedRequest(cmd=cmd, args=args, done=threading.Event())
        request_queue.put(request)
        while not shutdown_event.is_set():
            if request.done.wait(0.1):
                if request.error is not None:
                    raise request.error
                return request.result
        raise RuntimeError("Server is shutting down")

    def _drain_queued_requests() -> None:
        while True:
            try:
                request = request_queue.get_nowait()
            except queue.Empty:
                break
            try:
                with _HANDLER_LOCK:
                    request.result = _HANDLERS[request.cmd](ctx, request.args)
            except BaseException as e:
                request.error = e
            finally:
                request.done.set()

    try:
        while not shutdown_event.is_set():
            if synchronous:
                _drain_queued_requests()

            try:
                readable, _, _ = select.select([server_sock], [], [], 0.05)
            except OSError:
                break
            if not readable:
                continue

            while True:
                try:
                    conn, _ = server_sock.accept()
                except BlockingIOError:
                    break
                except OSError:
                    shutdown_event.set()
                    break

                conn.setblocking(True)
                if synchronous:
                    t = threading.Thread(
                        target=_handle_connection,
                        args=(conn, ctx, shutdown_event, _queued_dispatch),
                        daemon=True,
                    )
                    t.start()
                    _drain_queued_requests()
                else:
                    t = threading.Thread(
                        target=_handle_connection,
                        args=(conn, ctx, shutdown_event),
                        daemon=True,
                    )
                    t.start()

        if synchronous:
            _drain_queued_requests()
    finally:
        server_sock.close()
        remove_endpoint_marker(sock_path)
        # Session state describes a live daemon.  Do not leave a normal stop
        # looking like an active project to status/restart callers.
        remove_session(session.project_idb)
        logger.info("Server shut down.")
        print("Server shut down.", file=sys.stderr)
