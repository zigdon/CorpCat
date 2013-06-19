#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:

import datetime
import logging

import evelink
import evelink.cache.shelf

cache=evelink.cache.shelf.ShelveCache("/tmp/evecache")

class CorpAccess(object):
    def __init__(self, config, schema):
        self.schema = schema
        self.session = schema.session
        self.config = config

    def _ts(self, timestamp):
        date = datetime.date.fromtimestamp(int(timestamp))
        return "%04d-%02d-%02d" % (date.year, date.month, date.day)

    def is_allowed(self, tag, nick):
        person = self.session.query(self.schema.Person).filter(self.schema.Person.nick==nick).first()
        if person is None:
            return

        corps = set(c.corpname for key in person.keys for c in key.characters)
        return corps.intersection(self.config['corps'][tag]['allowed'])

    def get_person(self, nick, mask):
        person = self.session.query(self.schema.Person).filter(self.schema.Person.nick==nick).first()
        if person is None:
            person = self.schema.Person(nick, mask)

        self.session.add(person)
        self.session.commit()

        return person

    def search(self, args):
        person = self.session.query(self.schema.Person).filter(self.schema.Person.nick==args).first()
        if person is None:
            chars = self.session.query(self.schema.Character).filter(self.schema.Character.name.like("%%%s%%" % args)).all()
        else:
            chars = set(c for key in person.keys for c in key.characters)

        return person, chars;

    def add_key(self, person, key_id, vcode):
        try:
            api = evelink.api.API(api_key=(key_id, vcode), cache=cache)
            account = evelink.account.Account(api=api)
            result = account.key_info()
        except evelink.api.APIError as e:
            logging.warn("Error loading api key(%d, %s): %s" % (key_id, vcode, e))
            return None

        if result:
            if result['expire_ts']:
                expire = self._ts(result['expire_ts'])
            else:
                expire = 'Never'

            logging.info("expires: %s, type: %s, charscters: %s" % (
                         expire, result['type'],
                         ", ".join(char['name'] for char in result['characters'].itervalues())))
        else:
            logging.warn("Invalid key")
            return None

        try:
            key = self.schema.ApiKey(key_id, vcode, result['access_mask'], result['type'], expire)
            person.keys += [key]
            self.session.add(key)
            self.session.commit()

            for char in result['characters'].itervalues():
                if not self.session.query(self.schema.Character).filter(self.schema.Character.charid==char['id']).first():
                    key.characters += [
                      self.schema.Character(char['id'], char['name'], char['corp']['id'], char['corp']['name'])
                    ]

            self.session.add(key)
            self.session.commit()
        except Exception:
            self.session.rollback()

        return key



