#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: set ts=4 sw=4:
from collections import defaultdict
import datetime
import functools
import logging
import re
import sys
from inspect import getmembers, getdoc, ismethod

from oyoyo.client import IRCApp, IRCClient
from oyoyo.cmdhandler import DefaultCommandHandler
from oyoyo import helpers, ircevents
import yaml

import time
import threading

from corpaccess import CorpAccess, EveKeyError
from corpschema import CorpSchema

ircevents.numeric_events["335"] = 'whoisbot'
ircevents.all_events.append('whoisbot')
ircevents.numeric_events["307"] = 'whoisregistered'
ircevents.all_events.append('whoisregistered')

logging.basicConfig(level=logging.INFO)
app = None
config = None
schema = None
access = None

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
        self.corps = config['corps']

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

        self.to_identify = defaultdict(set)
        self.identify_sent = set()
        self.to_invite = defaultdict(set)
        self.to_voice = defaultdict(set)
        self.perms = defaultdict(lambda: defaultdict(str))

        self.periodic_callbacks = {
            'identifier': (1, self._process_identify_queue),
            'voicer': (15, self._process_voice_queue),
            'inviter': (15, self._process_invite_queue),
        }

        self.periodic_thread = threading.Thread(target=self._periodic_callback, name='periodic')
        self.periodic_thread.daemon = True
        self.periodic_thread.start()

    def _periodic_callback(self):
        """Run registered callbacks every so often (~1 Hz)"""

        iteration = 0
        while True:
            start = time.time()
            iteration += 1
            for cb in self.periodic_callbacks.keys():
                try:
                    freq, callback = self.periodic_callbacks[cb]
                    if iteration % freq == 0:
                        callback()
                except:
                    logging.error("Error while processing periodic callback '%s'." % cb, exc_info=True)
                duration = time.time() - start

                # Run no more often than once a second
                if duration < 2.0:
                    time.sleep(2.0 - duration)

    def _process_identify_queue(self):
        if len(self.to_identify) > 0:
            for chan, nicks in self.to_identify.items():
                if len(nicks) == 0:
                    del(self.to_identify[chan])
                    break
                nick = nicks.pop()
                self._identify(nick)
                self.identify_sent.update([nick.lower()])
                break

    def _process_mode_queue(self, queue, sigil, callback):
        if len(queue) > 0:
            logging.info('[moder +%s] %r' % (sigil, queue))
            for chan, nicks in queue.items():
                authed = set([n.lower() for n in nicks if self.perms[chan][n]])
                pending = list(nicks - authed)[:8]
                logging.info('[set math] nicks: %r' % nicks)
                logging.info('[set math] authed: %r' % authed)
                logging.info('[set math] pending: %r' % pending)
                if pending:
                    callback(chan, pending)
                queue[chan] -= set(pending)
                queue[chan] -= authed
                self.perms[chan].update((n.lower(), sigil) for n in pending)
                if len(queue[chan]) == 0:
                    del(queue[chan])

    def _process_voice_queue(self):
        self._process_mode_queue(self.to_voice, "v", self._voice)

    def _process_invite_queue(self):
        self._process_mode_queue(self.to_invite, "I", self._auto_invite)

    def nick(self, nick, newnick):
        """Process server's notification of a nick change."""
        nick = nick.split('!')[0].lower()
        newnick = newnick.lower()
        logging.info("[renick] %s -> %s" % (nick, newnick))
        for userlist in self.channel_userlists.itervalues():
            if nick in userlist:
                userlist.discard(nick)
                userlist.add(newnick)

        for chan in self.perms:
            if nick in self.perms[chan]:
                self.perms[chan][newnick] = self.perms[chan][nick]
                del(self.perms[chan][nick])

    def join(self, nick, chan):
        """When a user joins a channel..."""
        nick = nick.split('!')[0]
        if nick == self.client.nick:
            logging.info("[joined] %s" % chan)
        else:
            logging.info("[join] %s -> %s" % (nick, chan))
            self._identify(nick)

    def namreply(self, nick, chan, equals, channel, nicklist):
        for n in nicklist.lower().split():
            if n[0] in '+@%~&':
                self.perms[channel][n[1:]] = n[0]
            else:
                self.perms[channel][n] = ''

        nicks = set(x.lstrip('+@%~&').lower() for x in nicklist.split())
        logging.info("[namreply] %s -> %r" % (channel, nicks))
        self.to_identify[channel].update(nicks)


    def part(self, nick, chan):
        nick = nick.split('!')[0]
        logging.info("[part] %s -> %s" % (nick, chan))
        try:
            del(self.perms[chan][nick.lower()])
        except KeyError:
            logging.info("Couldn't clear %s's perms in %s: %r" % (nick, chan, self.perms))

    def quit(self, nick, message=None):
        nick = nick.split('!')[0]
        logging.info("[quit] %s" % nick)
        for chan in self.perms:
            try:
                del(self.perms[chan][nick.lower()])
            except KeyError:
                pass

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

        # If server-specific user modes are specified, set them.
        modes = s.get('modes')
        if modes:
            self.client.send('MODE', s['nick'], modes)

        time.sleep(10)
        for corp in self.corps.itervalues():
            if corp['server'] == self.client.host:
                helpers.join(self.client, corp['channel'])

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

    def _voice(self, chan, nicks):
        logging.info('[voice] %r: %r' % (chan, nicks))
        self._mode(chan, 'v', nicks)

    def _auto_invite(self, chan, nicks):
        self._mode(chan, 'I', nicks)

    def _mode(self, chan, mode, nicks):
        if len(nicks) == 0:
            return

        modes = '+%s' % (mode*len(nicks))
        self.client.send("MODE", chan, modes, " ".join(nicks))

    def _identify(self, nick):
        if nick in self.identify_sent:
            logging.info("Not reidentifying %s" % nick)
            return

        self._msg(config['servers'][self.client.host]['auth']['to'],
                  'acc %s *' % nick)

    def _enforce(self, user, nick, identified):
        logging.info('Enforcing %s (%s) (identify=%d)' % (user, nick, identified))
        for tag, corp in self.corps.iteritems():
            logging.info('corp=%s, action=%s, channel=%s' % (tag, corp['action'], corp['channel']))
            if corp['action'] == 'voice' and identified and access.is_allowed(tag, user):
                    self.to_voice[corp['channel']].update([nick])
            elif corp['action'] == 'kick' and not (identified and access.is_allowed(tag, user)):
                self._kick(corp['channel'], nick, 'This channel is restricted. /msg me "help id" for details.')
            elif corp['action'] == 'invite' and identified and access.is_allowed(tag, user):
                self.to_invite[corp['channel']].update([nick])

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
            m = re.search(r'(.*) -> (\S+) ACC (\d)', msg)
            if m is not None:
                nick = m.group(1).lower()
                user = m.group(2).lower()
                self.identify_sent.discard(nick)
                if m.group(3) == "3":
                    self._enforce(user, nick, True)
                else:
                    self._enforce(user, nick, False)

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
        """addkey <keyid> <vcode> - add an api key for a person (PM only). Create a key at http://api.eveonline.com"""
        usage = lambda: self._msg(chan, "Usage: addkey <keyid> <vcode>.")

        if not args:
            return usage()

        key_id, vcode = args.split()

        if not vcode:
            return usage()

        person = access.get_person(nick, mask)
        self._msg(chan, "Loading key...")
        try:
            access.add_key(person, key_id, vcode)
            self._identify(nick)
            self._msg(chan, "Key loaded.")
        except EveKeyError as e:
            self._msg(chan, e.message)

    @pm_only
    def _cmd_DELKEY(self, nick, mask, chan, args):
        """delkey <keyid> - delete an api key (PM only). Will delete associated characters too."""
        usage = lambda: self._msg(chan, "Usage: delkey <keyid>.")

        if not args:
            return usage()

        person = access.get_person(nick, mask)
        if access.del_key(person, args):
            self._msg(chan, "Key removed.")
        else:
            self._msg(chan, "Key not found.")

    def _cmd_ID(self, nick, mask, chan, args):
        """identify [<nick>] - check again if nick is known. A nick is considered known if it has an an api key added (help addkey) and is identified with NickServ."""

        target = args if args else nick
        self._identify(target)

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

        for corp in self.corps.itervalues():
            person, chars = access.search(args)
            if person is not None:
                self._msg(chan, "%s: %s has %d api key(s) and %d character(s): %s"
                          % (nick, person.nick, len(person.keys), len(chars),
                             ", ".join("%s (%s)" % (c.name, c.corpname) for c in chars)))
                return

            if chars is not None:
                if len(chars) == 1:
                    char = chars[0]
                    self._msg(chan, "%s: %s (%s) is owned by %s." %
                      (nick, char.name, char.corpname, char.api.person.nick))
                else:
                    self._msg(chan, "%s: %d matches: %s" % (nick, len(chars), ", ".join(c.name for c in chars)))

                return

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

if __name__ == '__main__':

    if len(sys.argv) > 1:
        conf = sys.argv[1]
    else:
        conf = 'config.yaml'

    with open(conf) as f:
        config = yaml.safe_load(f)

    app = IRCApp()
    schema = CorpSchema(config['database']['path'])
    access = CorpAccess(config, schema)
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
