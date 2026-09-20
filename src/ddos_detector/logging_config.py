import json
import logging


def setup_logging(level: str = "INFO", json_format: bool = False):
    lvl = getattr(logging, level.upper(), logging.INFO)
    if json_format:
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                payload = {"level": record.levelname, "msg": record.getMessage()}
                if record.exc_info:
                    payload["exc"] = self.formatException(record.exc_info)
                return json.dumps(payload)

        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        root = logging.getLogger()
        root.setLevel(lvl)
        root.handlers = [handler]
    else:
        logging.basicConfig(level=lvl, format="%(asctime)s %(levelname)s %(message)s")


def log_window_event(event_name: str, metrics: dict):
    """Emit a single structured traffic-window event without logging every packet."""
    logger = logging.getLogger("ddos_detector")
    payload = {"event": event_name, "metrics": metrics}
    logger.info(json.dumps(payload))
