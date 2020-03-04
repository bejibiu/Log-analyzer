import datetime
import logging
import os
import re

import pytest

from log_analyzer.helper import setup_config
from log_analyzer.log_analyzer import run_analyze, get_last_file, get_date_from_file, make_reg_exp_for_line, \
    checked_for_numbers_parsed_line, check_by_report_already_exist


def test_report(default_config, create_last_file_log_20200212):
    run_analyze(default_config, logging.getLogger())
    name_report = "report-2020.02.12.html"
    files = os.listdir(default_config['Main'].get('REPORT_DIR'))
    assert any(name_report in file for file in files)


def render_file(path_to_report):
    with open(path_to_report) as f:
        data = f.read()
    return data.splitlines()


def test_create_log_with_custom_config(tmpdir):
    p = tmpdir.mkdir('sub').join('config.ini')
    new_report_size = "7"
    p.write(f'[Main]\nREPORT_SIZE = {new_report_size}\n')
    config = setup_config(p.strpath)
    assert config['Main']['REPORT_DIR']
    assert config['Main']['REPORT_SIZE'] == new_report_size
    assert config['Main']['LOG_DIR']


def test_create_log_with_fail_custom_config(tmpdir):
    p = tmpdir.mkdir('sub').join('config.ini')
    new_report_size = "7"
    p.write(f'[MainREPORT_SIZE = {new_report_size}\n')
    with pytest.raises(Exception):
        setup_config(p.strpath)


def test_get_last_file_log(create_last_file_log_20200212, default_config):
    last_file_path = get_last_file(default_config, logging.getLogger())
    assert last_file_path.path == create_last_file_log_20200212


def test_get_date_from_file():
    date = get_date_from_file('access.log-20200212.gz')
    assert date == datetime.datetime(2020, 2, 12)


def test_get_invalid_date_from_file():
    date = get_date_from_file('access.lg-20200212.gz')
    assert date == datetime.datetime(2020, 2, 12)


@pytest.mark.parametrize("line, url, request_time", [
    ('127.0.0.1 - - [29/Jun/2017:03:50:22 +0300] "GET /index.html HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 '
     'libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.34\n',
     '/index.html', '0.34'),
    ('127.0.0.1 - - [29/Jun/2017:03:50:22 +0300] "GET /index.html HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 '
     'libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 34.0\n',
     '/index.html', '34.0'),
    ('127.0.0.1 - - [29/Jun/2017:03:50:22 +0300] "GET /index.html HTTP/1.0" 200 927 "-" "Lynx/2.8.8dev.9 '
     'libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.00\n',
     '/index.html', '0.00'),
    ('127.0.0.1 -  - [29/Jun/2017:03:50:22 +0300] "GET /export/appinstall_raw/2017-06-29/ HTTP/1.0" 200 28358 "-" '
     '"Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR '
     '3.5.30729)" "-" "-" "-" 0.003\n', "/export/appinstall_raw/2017-06-29/", '0.003'),
    # ('127.0.0.1 -  - [29/Jun/2017:05:07:25 +0300] "0" 400 166 "-" "-" "-" "-" "-" 0.001\n', "0", "0.001"), #This false test =(
])
def test_right_reg_exp(line, url, request_time):
    reg = make_reg_exp_for_line()
    data = re.search(reg, line)
    assert data
    datadict = data.groupdict()
    assert datadict['ip'] == '127.0.0.1'
    assert datadict['remote_user']
    assert datadict['http_x_real_ip']
    assert datadict['date_time']
    assert url in datadict['url']
    assert datadict['status_code']
    assert datadict['bytes_send']
    assert datadict['referer']
    assert datadict['user_agent']
    assert datadict['http_x_forwarded_for']
    assert datadict['http_X_REQUEST_ID']
    assert datadict['http_X_RB_USER']
    assert datadict['request_time'] == request_time


def test_checked_for_numbers_parsed_line(default_config):
    with pytest.raises(TypeError):
        checked_for_numbers_parsed_line(default_config, logging.getLogger(), 1000, 2001)
    assert checked_for_numbers_parsed_line(default_config, logging.getLogger(), 1002, 2001)
    assert checked_for_numbers_parsed_line(default_config, logging.getLogger(), 1000, 2000)


def test_if_file_report_already_exist(create_last_file_log_20200212, default_config, create_report_20200212):
    date = datetime.datetime.strptime("20200212", "%Y%m%d")
    assert check_by_report_already_exist(create_report_20200212.dirname, date=date)


def test_run_analyze_without_logs_file(default_config, create_log_dir, caplog):
    run_analyze(default_config, logging.getLogger())
