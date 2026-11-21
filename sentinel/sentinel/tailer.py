import os
import time


def follow(path, store, stop):
    """Yield complete lines appended to `path`; survives rotation and restarts (offsets are persisted)."""
    f, inode, buf, last_save = None, None, "", 0.0
    while not stop.is_set():
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(1)
            continue
        if f is None or st.st_ino != inode or st.st_size < f.tell():
            if f:
                f.close()
            f = open(path, "r", encoding="utf-8", errors="replace")
            inode, buf = st.st_ino, ""
            saved = store.get_offset(path)
            if saved and saved[0] == inode and saved[1] <= st.st_size:
                f.seek(saved[1])
        chunk = f.readline()
        if not chunk:
            if time.time() - last_save > 2:
                store.set_offset(path, inode, f.tell())
                last_save = time.time()
            time.sleep(0.25)
            continue
        buf += chunk
        if buf.endswith("\n"):
            line, buf = buf.strip(), ""
            if line:
                yield line
