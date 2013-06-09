#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:
# import base64
from collections import defaultdict
import datetime
import functools
# import json
import logging
# import random
import re
import sqlite3
# import threading
import time
# from urllib import urlencode, quote_plus
# import urllib2
# from urlparse import urlparse

# from BeautifulSoup import BeautifulSoup as soup
from oyoyo.client import IRCApp, IRCClient
from oyoyo.cmdhandler import DefaultCommandHandler
from oyoyo import helpers, ircevents
# import pytz
import yaml

ircevents.numeric_events["335"] = 'whoisbot'
ircevents.all_events.append('whoisbot')
ircevents.numeric_events["307"] = 'whoisregistered'
ircevents.all_events.append('whoisregistered')

logging.basicConfig(level=logging.INFO)
app = None
config = None
db = None

def admin_only(f):
    @functools.wraps(f)
    def wrapper(self, nick, chan, arg):
        if nick in config['admin']:
            return f(self, nick, chan, arg)
        else:
            return self._msg(chan, "You are not allowed to run that command.")
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

        # Periodic tasks
        # self.periodic_callbacks = {
        # }
        # self.periodic_thread = threading.Thread(target=self._periodic_callback, name='periodic')
        # self.periodic_thread.daemon = True
        # self.periodic_thread.start()

    def _periodic_callback(self):
        """Run registered callbacks every so often (~1 Hz)"""

        db = sqlite3.connect(config['database']['path'])
        while True:
            start = time.time()
            for cb in self.periodic_callbacks.keys():
                try:
                    self.periodic_callbacks[cb](db)
                except:
                    logging.error("Error while processing periodic callback '%s'." % cb, exc_info=True)
            duration = time.time() - start

            # Run no more often than once a second
            if duration < 1.0:
                time.sleep(1.0 - duration)

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
        logging.info("[join] %s -> %s" % (nick, chan))
        self.channel_userlists[chan].add(nick.lower())

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

    def _parse_line(self, nick, chan, msg):
        """Parse an incoming line of chat for commands and URLs."""
        pm = False

        # PMs to us should generally be replied to the other party, not ourself
        if chan.lower() == self.client.nick.lower():
            chan = nick.split('!')[0]
            pm = True

        if chan.startswith('#'):
            # If we're in a public channel and this is the fourth looks-like-spam line
            if len(msg) > 100 and all(re.match(r"\S{100,}", x[2]) for x in list(self.replay_buffers[chan])[-3:]):
                self.client.send('MODE', chan, '+M')

        # See if this is a command we recognize
        m = self.COMMAND_RE.match(msg)
        if m:
            logging.info("[cmd] %s -> %s: %s" % (nick, chan, msg))
            cmd = m.group(1)
            arg = m.group(2)
            cmd_func = '_cmd_%s' % cmd.upper()
            if hasattr(self, cmd_func):
                try:
                    getattr(self, cmd_func)(nick, chan, arg)
                except:
                    logging.error("Exception while attempting to process command '%s'" % cmd, exc_info=True)
                # Don't try to parse a URL in a recognized command
                return
            else:
                logging.warning('Unknown command "%s".' % cmd)

        # If we've gotten here and we're in a PM, we should say something
        if pm and not nick.startswith("NickServ"):
            logging.info("[unknown] %s -> %s" % (nick, msg))
            self._msg(chan, "Sorry, I don't understand that")


    # COMMANDS
    @admin_only
    def _cmd_JOIN(self, nick, chan, arg):
        """part - Make the bot join the specified channel."""
        usage = lambda: self._msg(chan, "Usage: join <channel>")

        if not arg:
            return usage()

        self._msg(chan, "Joining channel %s." % arg)
        helpers.join(self.client, arg)

    @admin_only
    def _cmd_PART(self, nick, chan, arg):
        """part - Make the bot leave the specified channel, or if not specified, the channel the message was in."""
        usage = lambda: self._msg(chan, "Usage: part [<channel>]")

        if not arg:
            if chan.startswith('#'):
                arg = chan
            else:
                return usage()

        self._msg(chan, "Leaving channel %s." % arg)
        helpers.part(self.client, arg)

    @admin_only
    def _cmd_QUIT(self, nick, chan, arg):
        helpers.quit(self.client, 'Shutting down...')

    @admin_only
    def _cmd_SRV(self, nick, chan, arg):
        if arg:
            self.client.send(arg)

    def _cmd_UTC(self, nick, chan, arg):
        """utc - Responds with the current time, UTC."""
        self._msg(chan, datetime.datetime.utcnow().replace(microsecond=0).isoformat(' '))

def db_keyval(key, val=None, default=None, conn=None):
    """Fetch a value from our 'misc' table key-val store."""
    if conn is None:
        conn = db
    if val is not None:
        conn.execute("INSERT OR REPLACE INTO misc (keyword, content) VALUES (?,?)", (key, val))
        conn.commit()
    else:
        result = conn.execute("SELECT content FROM misc WHERE keyword = ?", (key,)).fetchone()
        conn.rollback()
        if result is None:
            return default
        else:
            return result[0]

if __name__ == '__main__':

    with open('config.yaml') as f:
        config = yaml.safe_load(f)

    db = sqlite3.connect(config['database']['path'])
    db.execute("""
        CREATE TABLE IF NOT EXISTS apikeys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyid INTEGER,
            vcode TEXT,
            person INTEGER,
            accessMask INTEGER,
            type TEXT,
            expires INTEGER
        )""")
    db.execute("""
        CREATE TABLE IF NOT EXISTS people (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nick TEXT,
            hostmask TEXT
        )""")
    db.execute("""
        CREATE TABLE IF NOT EXISTS characters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            apiKey INTEGER
        )""")
    db.commit()

    app = IRCApp()
    clients = {}

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
