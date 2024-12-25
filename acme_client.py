import argparse
import http.client
import logging
from json import dumps, loads
from sys import stderr
from typing import Optional

from jose.jws import sign
from josepy import b64encode

from requests import Response, Session

http.client.HTTPConnection.debuglevel = 0  # 0 for off, > 0 for on

log_level: int = logging.ERROR
logging.basicConfig()
logger = logging.getLogger("requests.packages.urllib3")
logger.setLevel(log_level)
logger.propagate = True


def get_directory(session: Session, url: str) -> dict:
    resp_dir: Response = session.get(
        url=f'{url}/directory',
    )
    return resp_dir.json()


def get_nonce(session: Session, url: str) -> str:
    resp_nonce: Response = session.get(url=url)
    nonce: str = resp_nonce.headers.get('Replay-Nonce')
    return nonce


def do_signed_request(
        session: Session,
        key: str,
        protected: dict,
        payload: dict,
        **kwargs,
) -> dict:
    try:
        json: Optional[dict] = {
            'protected': b64encode(str(protected).encode(encoding='utf-8')).decode(encoding='utf-8'),
            'payload': b64encode(str(payload).encode(encoding='utf-8')).decode(encoding='utf-8'),
            'signature': b64encode(sign(payload=payload, key=key).encode(encoding='utf-8')).decode(encoding='utf-8'),
        }
        resp_acct: Response = session.request(**kwargs, json=json)
    except Exception as e:
        print(f'ERROR GETTING RESPONSE: {e}', file=stderr)
        raise
    try:
        acct: dict = resp_acct.json()
        return acct
    except Exception as e:
        print(f'ERROR PARSING RESPONSE: {e}', file=stderr)
        raise


def main(
        url: str,
        key_file: str,
        proxies: Optional[dict] = None,
) -> dict | str:
    session = Session()
    session.proxies = proxies
    session.headers = {'Accept': 'application/json'}

    directory: dict = get_directory(session=session, url=url)

    protected: dict = {
        'alg': 'HS256',
        'kid': '0391180c5936fdcfa3a59923a6982d75a321',
        'nonce': get_nonce(session, directory.get('newNonce')),
        'url': 'https://mywebserver.ownjoo.org/',
    }
    payload: dict = {'onlyReturnExisting': True}
    with open(key_file, 'r') as file:
        key = file.read()
        return do_signed_request(
            session=session,
            key=key,
            protected=protected,
            payload=payload,
            method='post',
            headers={'Content-Type': 'application/jose+json'},
            url=directory.get('newAccount'),
        )


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--url',
        type=str,
        required=True,
        help="The URL for your ACME server",
    )
    parser.add_argument(
        '--key_file',
        type=str,
        required=True,
        help="Path to private key file",
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
        logger.setLevel(args.debug)

    if data := main(
        url=args.url,
        key_file=args.key_file,
        proxies=proxies,
    ):
        print(data)
    else:
        print('whoops...')
