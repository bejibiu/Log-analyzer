import datetime
import gzip
import heapq
import logging
import os
import re
from collections import namedtuple, Counter, defaultdict
from configparser import ConfigParser
from itertools import groupby
from operator import itemgetter


def gen_config(path=None):
    BASE_DIR = os.path.dirname(__file__)
    path_to_log = path if path else os.path.join(BASE_DIR, 'config.ini')
    config = ConfigParser()
    config['Main'] = {
        "LOG_DIR": os.path.join(BASE_DIR, 'logs', 'nginx'),
        "REPORT_DIR": os.path.join(BASE_DIR, 'REPORT_DIR'),
        "REPORT_SIZE": 100,
        "time_sum": 10,
    }
    if not os.path.exists(path_to_log):
        raise OSError('config file not found')
    config.read(path_to_log)
    return config


def get_ext(log_file):
    _, extension = os.path.splitext(log_file)
    return extension


def get_last_file(config):
    files_logs = [filelog for filelog in os.listdir(config['Main'].get('LOG_DIR')) if filelog.endswith(('gz', 'log'))]
    FileLog = namedtuple('FileLog', 'path date ext')
    parsed_log = []
    for log_file in files_logs:
        path_to_file = os.path.join(config['Main'].get('LOG_DIR'), log_file)
        date_from_file = get_date_from_file(log_file)
        ext = get_ext(log_file)
        if all((path_to_file, date_from_file, ext)):
            parsed_log.append(FileLog(path_to_file, date_from_file, ext))
    return max(parsed_log, key=lambda x: x.date)


def get_date_from_file(log_file):
    pattern = re.compile(r"(?<=nginx-access-ui.log-)\d{8}")
    match = re.search(pattern, log_file)
    if match:
        return datetime.datetime.strptime(match.group(), "%Y%m%d")
    return False


def gen_open(file_log):
    if file_log.ext == '.gz':
        return gzip.open(file_log.path, 'r')
    if file_log.ext == '.log':
        return open(file_log.path, 'rb')


def process_line(line, line_reg):
    line_parsed = re.search(line_reg, line.decode())
    if not line_parsed:
        print(f'BAD FORMAT - {line}')
        return False
    line_dict = line_parsed.groupdict()
    return {'url': line_dict['url'],
            'time': float(line_dict['request_time'])}


def read_lines_gen(last_file_log):
    log_file = gen_open(last_file_log)
    line_reg = make_reg_exp_for_line()
    for line in log_file:
        parsed_line = process_line(line, line_reg)
        yield parsed_line
    log_file.close()


def make_reg_exp_for_line():
    """Compilation reg expression for nginx log
    log_format ui_short

    $remote_addr $remote_user $http_x_real_ip [$time_local] "$request"'$status $body_bytes_sent "$http_referer"
    "$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER"'$request_time'

    127.0.0.1 - - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n'
    """
    ip_reg = r'(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
    remote_user_reg = '(?P<remote_user>(\-)|(.+))'
    http_x_real_ip_reg = '(?P<http_x_real_ip>(\-)|(.+))'
    date_reg = r'\[(?P<date_time>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\]'
    url_reg = r'(\"(GET|POST|HEAD|PUT|UPDATE|DELETE|OPTIONS)? (?P<url>.+) (http\/1\.(1|0))?")'
    status_code_reg = r'(?P<status_code>\d{3})'
    bytes_send_reg = r'(?P<bytes_send>\d+)'
    referer_reg = r'(["](?P<referer>(\-)|(.+))["])'
    user_agent_reg = r'(["](?P<user_agent>(\-)|(.+))["])'
    http_x_forwarded_for_reg = r'(["](?P<http_x_forwarded_for>(\-)|(.+))["])'
    http_X_REQUEST_ID_reg = r'(["](?P<http_X_REQUEST_ID>(\-)|(.+))["])'
    http_X_RB_USER_reg = r'(["](?P<http_X_RB_USER>(\-)|(.+))["])'
    request_time_reg = r'(?P<request_time>(\d+)(\.\d*)?)'
    return re.compile(
        f'{ip_reg} {remote_user_reg} {http_x_real_ip_reg} {date_reg} {url_reg} {status_code_reg} {bytes_send_reg} '
        f'{referer_reg} {user_agent_reg} {http_x_forwarded_for_reg} {http_X_REQUEST_ID_reg} {http_X_RB_USER_reg} '
        f'{request_time_reg}', re.IGNORECASE)


def calc_med(times):
    n = len(times)
    times.sort()
    if n % 2 == 0:
        med1 = times[n // 2]
        med2 = times[n // 2 - 1]
        return (med1 + med2) / 2
    return times[n // 2]


def analyze(last_file_log, config):
    dict_parsed_lines = defaultdict(list)
    total = total_time = processed = 0

    parsed_lines_gen = read_lines_gen(last_file_log)

    for parsed_line in parsed_lines_gen:
        total += 1
        if parsed_line:
            processed += 1
            dict_parsed_lines[parsed_line['url']].append(parsed_line['time'])
            total_time += parsed_line['time']
    url_time_dict = {}
    for url in dict_parsed_lines:
        url_time_dict[url] = {'time_sum': sum(dict_parsed_lines[url])}
    most_common_url = heapq.nlargest(int(config['Main'].get('REPORT_SIZE')), url_time_dict, key=lambda x: url_time_dict[x]['time_sum'])

    table_list = []
    for url in most_common_url:
        tmp_dict = {'url': url, "count": len(dict_parsed_lines[url]),
                    "count_perc": len(dict_parsed_lines[url]) * 100 / len(dict_parsed_lines),
                    "time_sum": url_time_dict[url]['time_sum'],
                    "time_perc": url_time_dict[url]['time_sum'] * 100 / total_time,
                    "time_avg": url_time_dict[url]['time_sum'] / len(dict_parsed_lines[url]),
                    "time_max": max(dict_parsed_lines[url]), "time_med": calc_med(dict_parsed_lines[url])}
        table_list.append(tmp_dict)
    return table_list


def render_html(tables_for_list, config):
    pass


def run_analyze(config):
    last_file_log = get_last_file(config)
    tables_for_list = analyze(last_file_log, config)
    render_html(tables_for_list, config)


def setup_logger(config):
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s%(message)s',
                        filename=config['Main'].get('LOG_FILE') if config['Main'].get('LOG_FILE') else None,
                        datefmt='%Y.%m.%d %H:%M:%S')
    return logging.getLogger(__name__)


if __name__ == '__main__':
    import time

    start_time = time.time()

    config = gen_config()
    logger = setup_logger(config)
    try:
        run_analyze(config)
    except Exception as e:
        logger.exception(e)
    finally:
        print("--- %s seconds ---" % (time.time() - start_time))
