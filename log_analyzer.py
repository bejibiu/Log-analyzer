import datetime
import gzip
import logging
import os
import re
from collections import namedtuple, Counter
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
        "REPORT_SIZE": 4,
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


def read_lines(last_file_log):
    log_file = gen_open(last_file_log)
    line_reg = make_reg_exp_for_line()
    total = processed = 0
    for line in log_file:
        parsed_line = process_line(line, line_reg)
        total += 1
        if parsed_line:
            processed += 1
            yield parsed_line
    print("%s of %s lines processed" % (processed, total))
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
    url_reg = r'(\"(GET|POST|HEAD|PUT|UPDATE|DELETE)? (?P<url>.+) (http\/1\.(1|0))?")'
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
    parsed_lines_gen = read_lines(last_file_log)

    parsed_lines = list(parsed_lines_gen)
    parsed_lines.sort(key=itemgetter('url'))
    list_url = [log['url'] for log in parsed_lines]
    count_request = len(parsed_lines)
    group_by_url = groupby(parsed_lines, key=itemgetter('url'))
    dict_url_with_times = {url: [time['time'] for time in list(items)] for url, items in group_by_url}
    count_url = Counter(list_url)
    time_sum_by_url = {url: sum(dict_url_with_times[url]) for url in count_url}
    time_sum_counter = Counter(time_sum_by_url)
    most_common_url = time_sum_counter.most_common(int(config['Main'].get('REPORT_SIZE')))

    count_percent = {url[0]: count_url[url[0]] * 100 / count_request for url in most_common_url}
    count_most_common_url = {url: {'count': dict_url_with_times[url]} for url in count_url if url in most_common_url}
    time_sum = sum(time_sum_by_url.values())
    time_percent_by_most_common_url = {url[0]: time_sum_by_url[url[0]] * 100 / time_sum for url in most_common_url}
    time_average_by_most_common_url = {url[0]: sum(dict_url_with_times[url[0]]) / len(dict_url_with_times[url[0]]) for
                                       url in most_common_url}
    time_max_for_most_common_url = {url[0]: max(dict_url_with_times[url[0]]) for url in most_common_url}
    time_med_by_most_common_url = {url[0]: calc_med(dict_url_with_times[url[0]]) for url in most_common_url}

    return parsed_lines


def run_analyze(config):
    last_file_log = get_last_file(config)
    analyze(last_file_log, config)


def setup_logger(config):
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname).1s%(message)s',
                        filename=config['Main'].get('LOG_FILE') if config['Main'].get('LOG_FILE') else None,
                        datefmt='%Y.%m.%d %H:%M:%S')
    return logging.getLogger(__name__)


if __name__ == '__main__':
    config = gen_config()
    logger = setup_logger(config)
    try:
        run_analyze(config)
    except Exception as e:
        logger.exception(e)
