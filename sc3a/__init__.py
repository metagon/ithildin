import logging

stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s [%(levelname)s\t] %(message)s')
stream_handler.setFormatter(formatter)

log = logging.getLogger(__name__)
log.addHandler(stream_handler)
log.setLevel(logging.INFO)
