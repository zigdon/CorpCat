#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:

import argparse
import logging

import kitnirc.client
import kitnirc.modular

def main():
    parser = argparse.ArgumentParser(description="CorpCat")
    parser.add_argument("config", help="Path to config file")
    args = parser.parse_args()

    log_handler = logging.StreamHandler()
    log_formatter = logging.Formatter(
        "%(levelname)s %(asctime)s %(name)s:%(lineno)04d - %(message)s")
    log_handler.setFormatter(log_formatter)

    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)
    root_logger.setLevel(logging.DEBUG)

    client = kitnirc.client.Client()
    c = kitnirc.modular.Controller(client, args.config)
    c.start()

    nick = c.config.get('server', 'nick')
    username = c.config.get('server', 'username')
    realname = c.config.get('server', 'realname')
    password = c.config.get('nickserv', 'password')
    host = c.config.get('server', 'host')
    port = c.config.getint('server', 'port')
    client.connect(nick, username, realname, password, host, port)

    client.run()

if __name__ == '__main__':
    main()
