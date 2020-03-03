import argparse

from log_analyzer.helper import setup_logger, setup_config
from log_analyzer.log_analyzer import run_analyze


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', dest='path_to_config', default=None,
                        help="path to config file. By default it's config.ini in root dir")
    return parser.parse_args()


def main():
    import time

    start_time = time.time()

    args = parse_args()
    config = setup_config(path=args.path_to_config)
    logger = setup_logger(config)
    try:
        logger.info('run analyze')
        run_analyze(config, logger)
    except Exception as e:
        logger.exception(e)
    finally:
        print("--- %s seconds ---" % (time.time() - start_time))


if __name__ == '__main__':
    main()
