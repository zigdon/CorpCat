#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:
from collections import defaultdict
import datetime
import functools
import logging
import re
from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import sys
from inspect import getmembers, getdoc, ismethod

import evelink
import evelink.cache.shelf

from oyoyo.client import IRCApp, IRCClient
from oyoyo.cmdhandler import DefaultCommandHandler
from oyoyo import helpers, ircevents
import yaml

import time
import threading

ircevents.numeric_events["335"] = 'whoisbot'
ircevents.all_events.append('whoisbot')
ircevents.numeric_events["307"] = 'whoisregistered'
ircevents.all_events.append('whoisregistered')

logging.basicConfig(level=logging.INFO)
app = None
config = None
db = None
Base = declarative_base()

def admin_only(f):
    @functools.wraps(f)
    def wrapper(self, nick, mask, chan, arg):
        if '%s!%s' % (nick, mask) in config['admin']:
            return f(self, nick, mask, chan, arg)
        else:
            return self._msg(chan, "%s: You are not allowed to run that command." % nick)
    return wrapper

def pm_only(f):
    @functools.wraps(f)
    def wrapper(self, nick, mask, chan, arg):
        if chan.startswith("#"):
            return self._msg(chan, "%s: This command is accepted only in PM." % nick)
        else:
            return f(self, nick, mask, chan, arg)
    return wrapper

def is_action(f):
    f.is_action = True
    return f

def timeago(secs):
    """Returns a 'nice' representation of a time interval."""
    if secs < 60:
        return "%ds" % secs
    elif secs < 3600:
        return "%dm" % (secs // 60)
    elif secs < 86400:
        return "%dh" % (secs // 3600)
    else:
        return "%dd" % (secs // 86400)

class CorpHandler(DefaultCommandHandler):

    def __init__(self, *args, **kwargs):
        super(CorpHandler, self).__init__(*args, **kwargs)

        engine = create_engine('sqlite:///%s' % config['database']['path'])
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()

        # To allow certain handlers to wait until after the handshake
        self.WELCOMED = False

        # Users present in channels
        self.channel_userlists = defaultdict(set)

        # Commands - match either "<nick>: " or the sigil character as a prefix
        self.COMMAND_RE = re.compile(r"^(?:%s[:,]\s+|%s)(\w+)(?:\s+(.*))?[?!.]?$" % (
            self.client.nick,
            re.escape(config['sigil']),
        ), re.IGNORECASE)

        # Highlight - match "<nick>: <msg>" or "<nick>, <msg>"
        self.HIGHLIGHT_RE = re.compile(r"^([\w^`[\]|-]+)[:,]\s*(.+)$")

        self.callbacks = defaultdict(None)
        self.identified = defaultdict(None)
        self.to_identify = set()

        self.periodic_callbacks = {
            'identifier': self._process_identify_queue,
        }

        self.periodic_thread = threading.Thread(target=self._periodic_callback, name='periodic')
        self.periodic_thread.daemon = True
        self.periodic_thread.start()

    def _periodic_callback(self):
        """Run registered callbacks every so often (~1 Hz)"""

        while True:
            start = time.time()
            for cb in self.periodic_callbacks.keys():
                try:
                    self.periodic_callbacks[cb]()
                except:
                    logging.error("Error while processing periodic callback '%s'." % cb, exc_info=True)
                duration = time.time() - start

                # Run no more often than once a second
                if duration < 1.0:
                    time.sleep(1.0 - duration)

    def _process_identify_queue(self):
        if len(self.to_identify) > 0:
            nick = self.to_identify.pop()
            self._identify(nick, lambda: self.corpvoice(config['corp']['channel'], nick))

    def nick(self, nick, newnick):
        """Process server's notification of a nick change."""
        nick = nick.split('!')[0].lower()
        newnick = newnick.lower()
        logging.info("[renick] %s -> %s" % (nick, newnick))
        for userlist in self.channel_userlists.itervalues():
            if nick in userlist:
                userlist.discard(nick)
                userlist.add(newnick)

    def join(self, nick, chan):
        """When a user joins a channel..."""
        nick = nick.split('!')[0]
        if nick == self.client.nick:
            logging.info("[joined] %s" % chan)
        else:
            logging.info("[join] %s -> %s" % (nick, chan))
            self._identify(nick, lambda: self.corpvoice(config['corp']['channel'], nick))

    def namreply(self, nick, chan, equals, channel, nicklist):
        nicks = set(x.lstrip('+@%~&').lower() for x in nicklist.split() if x[0] not in '+@%~&')
        logging.info("[namreply] %s -> %r" % (channel, nicks))
        self.to_identify = nicks | self.to_identify


    def part(self, nick, chan):
        logging.info("[part] %s -> %s" % (nick, chan))
        del(self.identified[nick.lower()])

    def corpvoice(self, chan, nick):
        person = self.session.query(Person).filter(Person.nick==nick).first()
        if person is None:
            return

        corps = set(c.corpname for key in person.keys for c in key.characters)
        if config['corp']['name'] in corps:
            self._voice(chan, nick)

    def welcome(self, nick, chan, msg):
        """Trigger on-login actions via the WELCOME event."""
        s = config['servers'][self.client.host]

        # If an auth is specified, use it.
        auth = s.get('auth')
        if auth:
            try:
                self._msg(auth['to'], auth['msg'])
            except KeyError:
                logging.error('Authentication info for %s missing "to" or "msg", skipping.' %
                    self.client.host)

        # If default channels to join are specified, join them.
        channels = s.get('channels', ())
        for channel in channels:
            helpers.join(self.client, channel)

        # If server-specific user modes are specified, set them.
        modes = s.get('modes')
        if modes:
            self.client.send('MODE', s['nick'], modes)

        logging.info("Completed initial connection actions for %s." % self.client.host)
        self.WELCOMED = True

    def privmsg(self, nick, chan, msg):
        logging.debug("[message] %s -> %s: %s" % (nick, chan, msg))
        msg = msg.lstrip("!")
        self._parse_line(nick, chan, msg)

    def notice(self, nick, chan, msg):
        logging.debug("[notice] %s -> %s: %s" % (nick, chan, msg))
        self._parse_line(nick, chan, msg)

    def _msg(self, chan, msg):
        helpers.msg(self.client, chan, msg)

    def _ctcp(self, chan, msg):
        self._msg(chan, "\x01%s\x01" % msg)

    def _emote(self, chan, msg):
        self._ctcp(chan, "ACTION %s" % msg)

    def _kick(self, chan, nick, msg):
        self.client.send("KICK", chan, nick, ":%s" % msg)

    def _voice(self, chan, nick):
        self.client.send("MODE", chan, '+v', nick)

    def _ts(self, timestamp):
        date = datetime.date.fromtimestamp(int(timestamp))
        return "%04d-%02d-%02d" % (date.year, date.month, date.day)

    def _identify(self, nick, callback=None):
        if nick in self.identified:
            if callback is not None:
                callback()
            return True

        self._msg(config['servers'][self.client.host]['auth']['to'],
                  'acc %s *' % nick)
        if callback is not None:
            self.callbacks[nick.lower()] = callback

        return False

    def _parse_line(self, nick, chan, msg):
        """Parse an incoming line of chat for commands and URLs."""
        pm = False

        # PMs to us should generally be replied to the other party, not ourself
        if chan.lower() == self.client.nick.lower():
            chan = nick.split('!')[0]
            pm = True

        # Ignore services
        if chan in ('ChanServ', 'BotServ'):
            return

        if chan.lower() == config['servers'][self.client.host]['auth']['to'].lower():
            logging.info("[nickserv] %s" % msg)
            m = re.search(r'(\w+) -> .* ACC (\d)', msg)
            if m is not None:
                user = m.group(1).lower()
                if m.group(2) == "3":
                    self.identified[user] = 1
                    if user in self.callbacks:
                        self.callbacks[user]()
                        del(self.callbacks[user])
                else:
                    del(self.identified[user])

            return

        # See if this is a command we recognize
        m = self.COMMAND_RE.match(msg)
        if m or pm:
            logging.info("[cmd] %s -> %s: %s" % (nick, chan, msg))
            if pm:
                try:
                    cmd, arg = msg.split(None, 1)
                except:
                    cmd = msg
                    arg = None
            else:
                cmd = m.group(1)
                arg = m.group(2)
            cmd_func = '_cmd_%s' % cmd.upper()
            nick, mask = nick.split('!', 1)
            if hasattr(self, cmd_func):
                try:
                    getattr(self, cmd_func)(nick, mask, chan, arg)
                except:
                    logging.error("Exception while attempting to process command '%s'" % cmd, exc_info=True)
                # Don't try to parse a URL in a recognized command
                return
            else:
                logging.warning('Unknown command "%s".' % cmd)

        # If we've gotten here and we're in a PM, we should say something
        if pm:
            logging.info("[unknown] %s -> %s" % (nick, msg))
            self._msg(chan, "Sorry, I don't understand that")

    def _add_key(self, person, key_id, vcode):
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


    # COMMANDS
    @admin_only
    def _cmd_JOIN(self, nick, mask, chan, arg):
        """ADMIN: join <channel> - Make the bot join the specified channel."""
        usage = lambda: self._msg(chan, "Usage: join <channel>")

        if not arg:
            return usage()

        self._msg(chan, "Joining channel %s." % arg)
        helpers.join(self.client, arg)

    @pm_only
    def _cmd_ADDKEY(self, nick, mask, chan, args):
        """addkey <keyid> <vcode> - add an api key for a person (PM only)."""
        usage = lambda: self._msg(chan, "Usage: add key <keyid> <vcode>.")

        if not args:
            return usage()

        key_id, vcode = args.split()

        if not vcode:
            return usage()

        (nick, mask) = nick.split("!", 1)

        person = self.session.query(Person).filter(Person.nick==nick).first()
        if person is None:
            person = Person(nick, mask)

        self.session.add(person)
        self.session.commit()

        self._msg(chan, "Loading key...")
        self._add_key(person, key_id, vcode)
        self._identify(nick, lambda: self.corpvoice(config['corp']['channel'], nick))


    def _cmd_HELP(self, nick, mask, chan, args):
        """Show all known commands. help <cmd> for more details."""
        cmds = set(x[0][5:].lower() for x in getmembers(self, ismethod) if x[0][0:5] == '_cmd_')
        if not args:
            self._msg(chan, '%s: known commands: %s' % (nick, ", ".join(sorted(cmds))))
            return

        if args.lower() in cmds:
            self._msg(chan, '%s: %s - %s' % (nick, args, getdoc(getattr(self, '_cmd_%s' % args.upper()))))
            return

    def _cmd_WHOIS(self, nick, mask, chan, args):
        """whois <nick|character> - Look up details of a person or character."""

        person = self.session.query(Person).filter(Person.nick==args).first()
        if person is not None:
            chars = set(c for key in person.keys for c in key.characters)
            self._msg(chan, "%s: %s has %d api key(s) and %d character(s): %s"
                      % (nick, person.nick, len(person.keys), len(chars),
                         ", ".join("%s (%s)" % (c.name, c.corpname) for c in chars)))

            return

        chars = self.session.query(Character).filter(Character.name.like("%%%s%%" % args)).all()
        if chars is not None:
            if len(chars) == 1:
                char = chars[0]
                self._msg(chan, "%s: %s (%s) is owned by %s." %
                  (nick, char.name, char.corpname, char.api.person.nick))
            else:
                self._msg(chan, "%s: %d matches: %s" % (nick, len(chars), ", ".join(c.name for c in chars)))

            return;

        self._msg(chan, "%s: Couldn't find %s." % (nick, args))


    @admin_only
    def _cmd_PART(self, nick, mask, chan, arg):
        """ADMIN: part [<channel>] - Make the bot leave the specified channel, or if not specified, the channel the message was in."""
        usage = lambda: self._msg(chan, "%s: Usage: part [<channel>]" % nick)

        if not arg:
            if chan.startswith('#'):
                arg = chan
            else:
                return usage()

        self._msg(chan, "%s: Leaving channel %s." % (nick, arg))
        helpers.part(self.client, arg)

    @admin_only
    def _cmd_QUIT(self, nick, mask, chan, arg):
        """ADMIN: shut down."""
        helpers.quit(self.client, 'Shutting down...')

    @admin_only
    def _cmd_SRV(self, nick, mask, chan, arg):
        """ADMIN: srv <args>: send the server arbitrary commands."""
        if arg:
            self.client.send(arg)

    def _cmd_UTC(self, nick, mask, chan, arg):
        """utc - Responds with the current time, UTC."""
        self._msg(chan, "%s: %s" % (nick, datetime.datetime.utcnow().replace(microsecond=0).isoformat(' ')))

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

if __name__ == '__main__':

    if len(sys.argv) > 1:
        conf = sys.argv[1]
    else:
        conf = 'config.yaml'

    with open(conf) as f:
        config = yaml.safe_load(f)

    app = IRCApp()
    clients = {}
    cache=evelink.cache.shelf.ShelveCache("/tmp/evecache")

    for server, conf in config['servers'].iteritems():
        client = IRCClient(
            CorpHandler,
            host=server,
            port=conf['port'],
            nick=conf['nick'],
            real_name=conf['name'],
        )
        clients[server] = client
        app.addClient(client, autoreconnect=True)

    app.run()
