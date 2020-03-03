import logging
import os
from configparser import ConfigParser


def setup_config(path):
    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    path_to_log = path if path else os.path.join(BASE_DIR, 'config.ini')
    config = ConfigParser()
    config['Main'] = {
        "LOG_DIR": os.path.join(BASE_DIR, 'logs', 'nginx'),
        "REPORT_DIR": os.path.join(BASE_DIR, 'report_dir'),
        "REPORT_SIZE": 1000,
        "TEMPLATE": os.path.join(BASE_DIR, 'template', 'report.html'),
        "failure_perc": 50
    }
    if not os.path.exists(path_to_log):
        raise OSError('config file not found')
    config.read(path_to_log)
    return config


def setup_logger(config):
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s %(message)s',
                        filename=config['Main'].get('LOG_FILE') if config['Main'].get('LOG_FILE') else None,
                        datefmt='%Y.%m.%d %H:%M:%S')
    return logging.getLogger(__name__)


def calc_med(times):
    n = len(times)
    times.sort()
    if n % 2 == 0:
        med1 = times[n // 2]
        med2 = times[n // 2 - 1]
        return (med1 + med2) / 2
    return times[n // 2]
