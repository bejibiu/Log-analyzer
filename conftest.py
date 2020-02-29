import pytest

from log_analyzer import gen_config


@pytest.fixture
def default_config(tmpdir):
    p = tmpdir.mkdir('config').join('config.ini')
    p.write(f'[Main]\nLOG_DIR = {tmpdir.strpath + "/logs"}\n')
    return gen_config(p.strpath)


@pytest.fixture
def create_last_file_log(tmpdir):
    d = tmpdir.mkdir('logs')
    d.join('access.log-20200130.gz').write(b' ')
    d.join('access.log-20200131.gz').write(b' ')
    last_file = d.join('access.log-20200212.gz')
    last_file.write(b' ')
    return last_file.strpath


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
