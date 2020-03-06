import os

import pytest

from log_analyzer.helper import setup_config


@pytest.fixture
def default_config(tmpdir):
    p = tmpdir.mkdir('config').join('config.ini')
    log_path = os.path.join(tmpdir.strpath, "logs")
    report_dir = os.path.join(tmpdir.strpath, "report")
    p.write(f'[Main]\nLOG_DIR = {log_path}\nREPORT_DIR = {report_dir}')
    return setup_config(p.strpath)['Main']


@pytest.fixture
def create_log_dir(tmpdir):
    d = tmpdir.mkdir('logs')
    return d


@pytest.fixture
def create_last_file_log_20200212(tmpdir):
    d = tmpdir.mkdir('logs')
    d.join('nginx-access-ui.log-20170628.gz').write(b' ')
    d.join('nginx-access-ui.log-20170629.gz').write(b' ')
    last_file = d.join('nginx-access-ui.log-20200212.log')
    last_file.write(b'1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 '
                    b'"-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" '
                    b'"1498697422-2190034393-4708-9752759" "dc7161be3" 0.390')
    return last_file.strpath


@pytest.fixture
def create_report_20200212(tmpdir):
    d = tmpdir.mkdir('report')
    report = d.join('report-2020.02.12.html')
    report.write(' ')
    return report


@pytest.fixture
def opened_last_file(tmpdir):
    d = tmpdir.mkdir('logs')
    last_file = d.join('access.log-20200212.gz')
    last_file.write(
        b'172.30.16.199 - - [11/Feb/2020:09:09:10 -0500] "GET /static/css/font-awesome.min.css HTTP/1.1" 304 31 '
        b'"http://testinstaller/static/css/style.css" "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:70.0) '
        b'Gecko/20100101 Firefox/70.0" "-"')
    with open(last_file.strpath, 'rb') as f:
        yield f


@pytest.fixture
def parsed_last_file():
    return [{'url': '/static/css/font-awesome.min.css', 'time': 31}]
