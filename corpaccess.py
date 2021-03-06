#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:

import datetime
import logging

import evelink
import evelink.cache.shelf

from sqlalchemy import func

cache=evelink.cache.shelf.ShelveCache(".evecache")

class EveKeyError(Exception):
    pass

class CorpAccess(object):
    def __init__(self, config, schema):
        self.schema = schema
        self.session = schema.session
        self.config = config

    def _ts(self, timestamp):
        date = datetime.date.fromtimestamp(int(timestamp))
        return "%04d-%02d-%02d" % (date.year, date.month, date.day)

    def is_allowed(self, tag, nick):
        person = self.session.query(self.schema.Person).\
                 filter(func.lower(self.schema.Person.nick)==nick.lower()).first()
        if person is None:
            logging.info('no person object found for "%s".' % nick)
            return

        corps = set(c.corpname for key in person.keys for c in key.characters)
        logging.info('corps[%s] = %s' % (nick, ", ".join(corps)))
        logging.info('allowed[%s] = %s' % (tag, ", ".join(self.config['corps'][tag]['allowed'])))
        return corps.intersection(self.config['corps'][tag]['allowed'])

    def get_person(self, nick, mask):
        person = self.session.query(self.schema.Person).\
                 filter(func.lower(self.schema.Person.nick)==nick.lower()).first()
        if person is None:
            person = self.schema.Person(nick.lower(), mask)

        self.session.add(person)
        self.session.commit()

        return person

    def search(self, args):
        person = self.session.query(self.schema.Person).filter(self.schema.Person.nick==args.lower()).first()
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
        except Exception as e:
            logging.warn("Error loading api key(%s, %s): %s" % (key_id, vcode, e))
            raise EveKeyError("Error loading key: %s" % e)

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
            raise EveKeyError("Invalid key.")

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
        except Exception as e:
            self.session.rollback()
            raise EveKeyError("Database error: %s" % e)

        return key

    def del_key(self, person, key_id):
        key = self.session.query(self.schema.ApiKey).get(key_id)
        if key and key.personid == person.id:
            self.session.delete(key)
            self.session.commit()
            return True
        else:
            self.session.rollback()
            return False


