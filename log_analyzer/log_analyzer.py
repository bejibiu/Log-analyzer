import datetime
import gzip
import heapq
import os
import re
import statistics
from collections import defaultdict, namedtuple
from parser import ParserError
from string import Template

LOG_FORMAT_REG = re.compile(r'nginx-access-ui.log-(\d){8}(.gz)?$')
FileLog = namedtuple('FileLog', 'path date ext')


def get_ext(log_file):
    _, extension = os.path.splitext(log_file)
    return extension


def get_last_file(config, logger):
    path_to_log = config.get('LOG_DIR')
    if not os.path.exists(path_to_log):
        logger.error('Log dir is not exist')
        raise FileNotFoundError
    log_files = [log_file for log_file in os.listdir(path_to_log) if re.search(LOG_FORMAT_REG, log_file)]
    if not log_files:
        logger.info('Log files not found')
        return False
    logger.info(f"found {len(log_files)} files :{log_files}")
    parsed_log = [get_arg_for_file_log(config, log_file) for log_file in log_files]
    return max(parsed_log, key=lambda x: x.date)


def get_arg_for_file_log(config, log_file):
    path_to_file = os.path.join(config.get('LOG_DIR'), log_file)
    date_from_file = get_date_from_file(log_file)
    ext = get_ext(log_file)
    return FileLog(path_to_file, date_from_file, ext)


def get_date_from_file(log_file):
    pattern = re.compile(r"\d{8}")
    match = re.search(pattern, log_file)
    try:
        return datetime.datetime.strptime(match.group(), "%Y%m%d")
    except ValueError:
        # logger.
        return datetime.datetime.min()


def open_file_log(file_log):
    if file_log.ext == '.gz':
        return gzip.open(file_log.path)
    return open(file_log.path, 'rb')


def process_line(line, line_reg, logger):
    line_parsed = re.search(line_reg, line.decode())
    if not line_parsed:
        logger.info(f'could not parse the string - {line}')
        return False
    line_dict = line_parsed.groupdict()
    url = get_url_from_request(line_dict['url'])
    return {'url': url,
            'time': float(line_dict['request_time'])}


def get_url_from_request(url):
    url_from_request = 1
    request = url.split(' ')
    if len(request) == 3:
        return request[url_from_request]
    return url


def read_lines_gen(last_file_log, logger):
    log_file = open_file_log(last_file_log)
    line_reg = make_reg_exp_for_line()
    for line in log_file:
        parsed_line = process_line(line, line_reg, logger)
        yield parsed_line
    log_file.close()


def make_reg_exp_for_line():
    """
        Compilation reg expression for nginx log
            log_format ui_short

            $remote_addr $remote_user $http_x_real_ip [$time_local] "$request"'$status $body_bytes_sent "$http_referer"
            "$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER"'$request_time'

            127.0.0.1 - - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-"
            "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390\n'
    """
    ip_reg = r'(?P<ip>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})'
    remote_user_reg = '(?P<remote_user>(-)|(.+))'
    http_x_real_ip_reg = '(?P<http_x_real_ip>(-)|(.+))'
    date_reg = r'\[(?P<date_time>\d{2}\/[a-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\]'
    url_reg = r'(["](?P<url>(.+))["])'
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


def run_processed(last_file_log, config, logger):
    parsed_lines_gen = read_lines_gen(last_file_log, logger)

    processed, total, total_time, dict_parsed_lines = get_common_params(logger, parsed_lines_gen)

    checked_for_numbers_parsed_line(config, logger, processed, total)
    url_time_dict = {url: {'time_sum': sum(dict_parsed_lines[url])} for url in dict_parsed_lines}
    most_common_url = heapq.nlargest(int(config.get('REPORT_SIZE')), url_time_dict,
                                     key=lambda x: url_time_dict[x]['time_sum'])

    table_list = []
    for url in most_common_url:
        tmp_dict = {'url': url,
                    "count": len(dict_parsed_lines[url]),
                    "count_perc": len(dict_parsed_lines[url]) * 100 / processed,
                    "time_sum": url_time_dict[url]['time_sum'],
                    "time_perc": url_time_dict[url]['time_sum'] * 100 / total_time,
                    "time_avg": statistics.mean(dict_parsed_lines[url]),
                    "time_max": max(dict_parsed_lines[url]),
                    "time_med": statistics.median(dict_parsed_lines[url])}
        table_list.append(tmp_dict)
    return table_list


def get_common_params(logger, parsed_lines_gen):
    dict_parsed_lines = defaultdict(list)
    processed = total = total_time = 0
    for parse_line in parsed_lines_gen:
        total += 1
        if parse_line:
            processed += 1
            dict_parsed_lines[parse_line['url']].append(parse_line['time'])
            total_time += parse_line['time']
        if total % 100000 == 0:
            logger.info(f"read {total} line. Parsed {processed} line ")
    return processed, total, total_time, dict_parsed_lines


def checked_for_numbers_parsed_line(config, logger, processed, total):
    if float(config.get('FAILURE_PERC')) > processed * 100 / total:
        logger.error(f"Parsed only {processed} of {total} line")
        raise ParserError(f"More than half of the file could not be parsed.")
    logger.info(f"Parsed {processed} of {total} line")
    return True


def render_html(tables_for_list, config, logger, date_report):
    template = load_template(config)
    if not os.path.exists(os.path.join(config.get('REPORT_DIR'))):
        os.mkdir(os.path.join(config.get('REPORT_DIR')))
        logger.info("report dir is created")
    name_report = get_report_name(date_report)
    report_path = os.path.join(config.get('REPORT_DIR'), name_report)
    with open(report_path, 'w') as report:
        report.write(template.safe_substitute(table_json=tables_for_list))
    logger.info('report is create')


def load_template(config):
    with open(config.get('TEMPLATE'), 'r') as f:
        template_str = f.read()
    template = Template(template_str)
    return template


def get_report_name(date_report):
    name_report = f'report-{date_report.strftime("%Y.%m.%d")}.html'
    return name_report


def check_by_report_already_exist(path_to_report_dir, date, logger):
    report_name = get_report_name(date)
    if os.path.exists(os.path.join(path_to_report_dir, report_name)):
        logger.info('Report already exist')


def run_analyze(config, logger):
    last_file_log = get_last_file(config, logger)
    if not last_file_log:
        return True
    logger.info(f"last file is {last_file_log.path}")
    if check_by_report_already_exist(config.get('REPORT_DIR'), last_file_log.date, logger):
        return True
    tables_for_list = run_processed(last_file_log, config, logger)
    render_html(tables_for_list, config, logger, date_report=last_file_log.date)
    return True
