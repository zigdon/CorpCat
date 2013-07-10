#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging

import kitnirc.client
import kitnirc.modular
import kitnirc.contrib.admintools

def main():
    parser = argparse.ArgumentParser(description="CorpCat")
    parser.add_argument("config", help="Path to config file")
    args = parser.parse_args()

    log_handler = logging.StreamHandler()
    log_formatter = logging.Formatter(
        "%(levelname)s %(asctime)s %(name)s:%(lineno)04d - %(message)s")
    log_handler.setFormatter(log_formatter)

    _log = logging.getLogger()
    _log.addHandler(log_handler)
    _log.setLevel(logging.DEBUG)

    client = kitnirc.client.Client()
    c = kitnirc.modular.Controller(client, args.config)

    def is_admin(controller, client, user):
        _log.info('checking if %s is admin' % user)
        return any(user == admin for admin, level in controller.config.items('admin'))
    kitnirc.contrib.admintools.is_admin = is_admin

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

# vim: set ts=4 sw=4:
