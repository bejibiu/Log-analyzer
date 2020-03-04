import logging
import os
from configparser import ConfigParser


def setup_config(path):
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    config = ConfigParser()
    config['Main'] = {
        "LOG_DIR": os.path.join(BASE_DIR, 'logs', 'nginx'),
        "REPORT_DIR": os.path.join(BASE_DIR, 'report_dir'),
        "REPORT_SIZE": 1000,
        "TEMPLATE": os.path.join(BASE_DIR, 'template', 'report.html'),
        "FAILURE_PERC": 50
    }
    config.read(path)
    return config


def setup_logger(config):
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s',
                        filename=config['Main'].get('LOG_FILE') if config['Main'].get('LOG_FILE') else None,
                        datefmt='%Y.%m.%d %H:%M:%S')
    return logging.getLogger(__name__)
