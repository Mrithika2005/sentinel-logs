try:
    from sentinel_sdk.python.agent import init_sentinel
    init_sentinel()
except Exception:
    pass

def mount_fastapi_ingest(self, app: Any) -> None:
    mount_fastapi_ingest(app, self._writer, self._cfg)

def mount_flask_ingest(self, app: Any) -> None:
    mount_flask_ingest(app, self._writer, self._cfg)
