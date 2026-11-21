import logging
import threading
import time

from . import api, config
from .engine import Engine
from .store import Store
from .tailer import follow

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("sentinel")


def pump(path, store, handler, stop, name):
    for line in follow(path, store, stop):
        try:
            handler(line)
        except Exception:                         # a malformed line must never kill the pipeline
            log.exception("%s handler failed", name)


def main():
    store = Store(config.DB_PATH)
    engine = Engine(store)
    stop = threading.Event()
    for path, handler, name in ((config.AUDIT_LOG, engine.on_audit, "audit"), (config.ACCESS_LOG, engine.on_access, "access")):
        threading.Thread(target=pump, args=(path, store, handler, stop, name), daemon=True).start()

    def sweeper():
        while not stop.is_set():
            try:
                engine.sweep()
            except Exception:
                log.exception("sweep failed")
            time.sleep(2)
    threading.Thread(target=sweeper, daemon=True).start()

    log.info("Sentinel up: mode=%s strikes=%s window=%ss port=%s", config.MODE, config.BAN_STRIKES, config.STRIKE_WINDOW, config.PORT)
    api.make_server(store, engine).serve_forever()


if __name__ == "__main__":
    main()
