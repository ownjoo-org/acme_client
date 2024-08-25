import argparse
import logging

from json import loads, dumps
from typing import Optional


import http.client

from requests import Session, Response

http.client.HTTPConnection.debuglevel = 0  # 0 for off, > 0 for on

log_level: int = logging.ERROR
logging.basicConfig()
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(log_level)
requests_log.propagate = True


def main(
        client_id: str,
        client_secret: str,
        proxies: Optional[dict] = None,
) -> dict | str:
    session = Session()
    session.proxies = proxies
    session.headers = {'Accept': 'application/json'}

    token_resp: Response = session.post(
        url=f'https://login.intigriti.com/connect/token',
    )

    return token_resp


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--client_id',
        type=str,
        required=True,
        help="The client_id for your Let's Encrypt account",
    )
    parser.add_argument(
        '--client_secret',
        type=str,
        required=True,
        help="The client_secret for your Let's Encrypt account",
    )
    parser.add_argument(
        '--proxies',
        type=str,
        required=False,
        help="JSON structure specifying 'http' and 'https' proxy URLs",
    )
    parser.add_argument(
        '--debug',
        type=int,
        help="enable debug logging",
    )

    args = parser.parse_args()

    proxies: Optional[dict] = None
    if args.proxies:
        proxies: dict = loads(args.proxies)

    if args.debug:
        http.client.HTTPConnection.debuglevel = args.debug
        requests_log.setLevel(args.debug)

    if data := main(
        client_id=args.client_id,
        client_secret=args.client_secret,
        proxies=proxies,
    ):
        print(f'\n\n{data}\n\n')
    else:
        print('whoops...')
