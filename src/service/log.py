import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - [%(levelname)s]: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class Log:

    @staticmethod
    def info(message: str):
        logging.info(message)

    @staticmethod
    def error(message: str):
        logging.error(message)
