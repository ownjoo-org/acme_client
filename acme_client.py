import argparse
import http.client
import logging
from base64 import b64encode
from json import dumps, loads
from typing import Optional

from key_utils import create_key
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


def create_account(
        session: Session,
        url: str,
        nonce: str,
) -> dict:
    priv, pub = create_key()

    protected: dict = {
        "alg": priv.to_dict().get('alg'),
        "jwk": priv.to_dict(),
        "nonce": nonce,
        "url": url,
    }

    payload: dict = {
        "termsOfServiceAgreed": True,
        "contact": [
            "mailto:cert-admin@ownjoo.org",
            "mailto:admin@ownjoo.org"
        ]
    }

    signed_protected = priv.sign(dumps(protected).encode('utf-8'))

    headers: dict = {
        'Accept': 'application/json',
        'Content-Type': 'application/jose+json',
        'url': url,
    }

    data: dict = {
        'protected': b64encode(dumps(protected).encode('utf-8')).decode('utf-8'),
        'payload': b64encode(dumps(payload).encode('utf-8')).decode('utf-8'),
        'signature': b64encode(signed_protected).decode('utf-8'),
    }

    resp_acct: Response = session.post(url=url, headers=headers, json=data)
    acct: dict = resp_acct.json()

    return acct


def main(
        url: str,
        # key: str,
        # key_id: str,
        proxies: Optional[dict] = None,
) -> dict | str:
    session = Session()
    session.proxies = proxies
    session.headers = {'Accept': 'application/json'}

    directory: dict = get_directory(session=session, url=url)
    nonce: str = get_nonce(session=session, url=directory.get('newNonce'))
    acct: dict = create_account(
        session=session,
        url=directory.get('newAccount'),
        nonce=nonce,
    )

    return acct


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--url',
        type=str,
        required=True,
        help="The URL for your ACME server",
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
        proxies=proxies,
    ):
        print(data)
    else:
        print('whoops...')
