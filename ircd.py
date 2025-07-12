#!/usr/bin python3

import argparse
import sys
import os
from socket import socket

from OpenSSL.crypto import load_certificate, FILETYPE_PEM, Error
from handle.logger import logging
from classes.configuration import ConfigBuild
from handle.core import IRCD

if __name__ == "__main__":
    if sys.version_info < (3, 10, 0):
        logging.error("Python version 3.10 or higher is required.")
        sys.exit()

    parser = argparse.ArgumentParser(description="ProvisionIRCd")
    parser.add_argument("-c", "--conf", help="Relative path to main configuration file", default="ircd.conf")
    parser.add_argument("--debug", help="Show debug output in console", action="store_true")
    parser.add_argument("--fork", help="Fork to the background", action="store_true")
    parser.add_argument("--certfp", help="Prints the server certificate fingerprint", action="store_true")
    parser.add_argument("--certcn", help="Prints the server certificate CN", action="store_true")
    parser.add_argument("--rehash", help="Rehashes the server configuration file", action="store_true")
    parser.add_argument("--restart", help="Restarts the IRCd", action="store_true")

    try:
        import bcrypt

        parser.add_argument("--mkpasswd", help="Generate bcrypt password to use in opers.conf")
    except ImportError:
        bcrypt = None

    args = parser.parse_args()

    if bcrypt and args.mkpasswd:
        hashed = bcrypt.hashpw(args.mkpasswd.encode(), bcrypt.gensalt()).decode()
        logging.info(f"Your salted password: {hashed}")
        sys.exit()

    if args.certfp or args.certcn:
        for file in filter(lambda f: f.endswith(".pem"), os.listdir("tls")):
            with open(os.path.join("tls", file), "rb") as cert_file:
                try:
                    cert = load_certificate(FILETYPE_PEM, cert_file.read())
                    if args.certfp:
                        fingerprint = cert.digest("sha256").decode().replace(':', '').lower()
                        logging.info(f"[{file}] Fingerprint: {fingerprint}")
                    if args.certcn:
                        if cn := cert.get_subject().commonName:
                            cn = cn.replace(' ', '_')
                            logging.info(f"[{file}] CN: {cn}")
                except Error:
                    pass
                except Exception as ex:
                    logging.error(f"Unable to read certificate file {file}: {ex}")
        sys.exit()

    if args.rehash:
        try:
            with socket() as sock:
                # sock.settimeout(1)
                sock.connect(("127.0.0.1", 65432))
                sock.sendall(b"REHASH")
                resp = b''.join(iter(lambda: sock.recv(1024), b'')).decode()

            if resp == '1':
                logging.info("Configuration file rehashed successfully.")
            else:
                IRCD.cli_resp(resp)
                logging.error("Configuration file failed to reload.")

        except (ConnectionRefusedError, TimeoutError):
            logging.error("Rehashing failed. Is the server running?")

        sys.exit()

    if args.restart:
        try:
            with socket() as sock:
                sock.settimeout(0.1)
                sock.connect(("127.0.0.1", 65432))
                sock.sendall(b"RESTART")
                resp = b''.join(iter(lambda: sock.recv(1024), b'')).decode()

        except (ConnectionRefusedError, TimeoutError):
            logging.error("Rehashing failed. Is the server running?")

        sys.exit()
    try:
        if ConfigBuild(conffile=args.conf, debug=args.debug).is_ok():
            IRCD.boot(fork=args.fork)
    except Exception as ex:
        logging.exception(ex)
