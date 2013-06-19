#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:

import datetime
import logging

import evelink
import evelink.cache.shelf

from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
cache=evelink.cache.shelf.ShelveCache("/tmp/evecache")

class CorpAccess(object):
    def __init__(self, config, corp):

        engine = create_engine('sqlite:///%s' % config['database']['path'])
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()

        self.config = config
        self.corp = corp
        self.action = self.corp.get('action', 'voice')
        self.channel = self.corp.get('channel', None)

    def _ts(self, timestamp):
        date = datetime.date.fromtimestamp(int(timestamp))
        return "%04d-%02d-%02d" % (date.year, date.month, date.day)

    def is_allowed(self, nick):
        person = self.session.query(Person).filter(Person.nick==nick).first()
        if person is None:
            return

        corps = set(c.corpname for key in person.keys for c in key.characters)
        return corps.intersection(self.corp['allowed'])

    def get_person(self, nick, mask):
        person = self.session.query(Person).filter(Person.nick==nick).first()
        if person is None:
            person = Person(nick, mask)

        self.session.add(person)
        self.session.commit()

        return person

    def search(self, args):
        person = self.session.query(Person).filter(Person.nick==args).first()
        if person is None:
            chars = self.session.query(Character).filter(Character.name.like("%%%s%%" % args)).all()
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
            key = ApiKey(key_id, vcode, result['access_mask'], result['type'], expire)
            person.keys += [key]
            self.session.add(key)
            self.session.commit()

            for char in result['characters'].itervalues():
                if not self.session.query(Character).filter(Character.charid==char['id']).first():
                    key.characters += [
                      Character(char['id'], char['name'], char['corp']['id'], char['corp']['name'])
                    ]

            self.session.add(key)
            self.session.commit()
        except Exception:
            self.session.rollback()

        return key



class Person(Base):
    __tablename__ = 'people'

    id = Column(Integer, primary_key=True)
    nick = Column(String, nullable=False)
    hostmask = Column(String, nullable=False)

    keys = relationship("ApiKey", backref="person")

    def __init__(self, nick, hostmask):
        self.nick = nick
        self.hostmask = hostmask

    def __repr__(self):
        return "<Person('%s')>" % self.nick

class ApiKey(Base):
    __tablename__ = 'apikeys'

    keyid = Column(Integer, primary_key=True)
    vcode = Column(String, nullable=False)
    accessmask = Column(Integer, nullable=False)
    type = Column(String, nullable=False)
    expires = Column(Integer, nullable=False)
    personid = Column(Integer, ForeignKey('people.id'))

    characters = relationship("Character", backref="api")

    def __init__(self, key_id, vcode, access_mask, type, expires):
        self.keyid = key_id
        self.vcode = vcode
        self.accessmask = access_mask
        self.type = type
        self.expires = expires

    def __repr__(self):
        return "<Api('%s')>" % self.keyid

class Character(Base):
    __tablename__ = 'characters'

    charid = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    corpid = Column(Integer, nullable=False)
    corpname = Column(String, nullable=False)
    apiid = Column(Integer, ForeignKey('apikeys.keyid'), nullable=False)

    def __init__(self, char_id, name, corp_id, corp_name):
        self.charid = char_id
        self.name = name
        self.corpid = corp_id
        self.corpname = corp_name

    def __repr__(self):
        return "<Char('%s')>" % self.name

