#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
from collections import defaultdict, deque
import datetime
import functools
import json
import logging
import random
import re
import sqlite3
import threading
import time
from urllib import urlencode, quote_plus
import urllib2
from urlparse import urlparse

from BeautifulSoup import BeautifulSoup as soup
from oyoyo.client import IRCApp, IRCClient
from oyoyo.cmdhandler import DefaultCommandHandler
from oyoyo import helpers, ircevents
import pytz
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
		if nick in ('Aaeriele!aiiane@hide-F3E0B19.aiiane.com', 'Aaeriele!~aiiane@hide-F3E0B19.aiiane.com'):
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

class KitnHandler(DefaultCommandHandler):

	def __init__(self, *args, **kwargs):
		super(KitnHandler, self).__init__(*args, **kwargs)

		# To allow certain handlers to wait until after the handshake
		self.WELCOMED = False

		# Keep track of known bots
		self.KNOWN_NICKS = set([self.client.nick])
		self.KNOWN_BOTS = set([self.client.nick])

		# Common timezones
		self.TIMEZONES = {
			'UTC': pytz.timezone('UTC'),
			'UCT': pytz.timezone('UCT'),
			'GMT': pytz.timezone('GMT'),
			'EST': pytz.timezone('America/New_York'),
			'EDT': pytz.timezone('America/New_York'),
			'CST': pytz.timezone('America/Chicago'),
			'CDT': pytz.timezone('America/Chicago'),
			'MST': pytz.timezone('America/Boise'),
			'MDT': pytz.timezone('America/Boise'),
			'PST': pytz.timezone('America/Los_Angeles'),
			'PDT': pytz.timezone('America/Los_Angeles'),
		}
		for offset in range(13):
			self.TIMEZONES['GMT+%d' % offset] = pytz.timezone('Etc/GMT+%d' % offset)
			self.TIMEZONES['GMT-%d' % offset] = pytz.timezone('Etc/GMT-%d' % offset)

		# Replay buffers
		self.replay_buffers = defaultdict(lambda: deque(maxlen=config['limits']['replay']))
		self.last_join = defaultdict(dict)

		# Last karma spam checks
		self.last_karma = defaultdict(dict)

		# Users present in channels
		self.channel_userlists = defaultdict(set)
		self.channel_usercounts = {}

		# Commands - match either "<nick>: " or the sigil character as a prefix
		self.COMMAND_RE = re.compile(r"^(?:%s[:,]\s+|%s)(\w+)(?:\s+(.*))?[?!.]?$" % (
			self.client.nick,
			re.escape(config['sigil']),
		), re.IGNORECASE)

		# Actions - match "\x01ACTION <something>s <nick>\x01"
		self.ACTION_RE = re.compile("\x01ACTION (\\w+)s %s\x01" % self.client.nick)

		# Highlight - match "<nick>: <msg>" or "<nick>, <msg>"
		self.HIGHLIGHT_RE = re.compile(r"^([\w^`[\]|-]+)[:,]\s*(.+)$")

		# Karma - match "<nick>++"
		self.KARMA_RE = re.compile(r"^([\w^`[\]|-]+)\+\+$")

		# URLs
		self.URL_RE = re.compile(r"""
				\b
				(
					# URLs that start with http://, https://, or www.

					(https?://|www\.)
					([a-zA-Z0-9-]+\.)+   # domain segments
					[a-zA-Z]{2,4}        # TLD
					                     # We don't require 'nice' URLs to have a path (/ can be implied)
				|
					# URLs that don't start with a 'nice' prefix

					([a-zA-Z0-9-]+\.)+   # domain segments
					[a-zA-Z]{2,4}        # TLD
					(?=/)                # These URLs are required to at least have a /
				|
					# IPs
					https?://                   # protocol
					([0-9]{1,3}\.){3}[0-9]{1,3} # IP octets
					(?=/)                       # IPs must be followed by a /
				)

				# And then allow any kind of URL path, except for unpaired parens
				# (we do this to make it easier to properly detect URLs that are
				# inside parens, e.g. "Example site (www.foo.com/bar)"
				(
					/
					(
						\([^\s()]+\)     # Allow paired parens
					|
						[^\s()]+         # Normal URL content (no parens)
					)*
				)?
			""", re.X)

		# Periodic tasks
		self.periodic_callbacks = {
			'reminders': self._process_reminders,
			'new_xkcd': self._check_for_new_xkcd,
			'userlimit': self._adjust_channel_limits,
		}
		self.periodic_thread = threading.Thread(target=self._periodic_callback, name='periodic')
		self.periodic_thread.daemon = True
		self.periodic_thread.start()

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

	def _process_reminders(self, db):
		"""Check to see if any reminders need to be triggered."""
		# Wait until after handshakes
		if not self.WELCOMED:
			return

		reminders = db.execute("SELECT id, nick, chan, content FROM reminders WHERE timestamp < ?", (time.time(),)).fetchall()
		for r_id, nick, chan, content in reminders:
			logging.info("Resolving reminder #%s" % r_id)
			msg = "%s: %s" % (nick, content)
			self._msg(chan, msg)
			self._highlight(self.client.nick, chan, msg, nick, db_conn=db)
			db.execute("DELETE FROM reminders WHERE id = ?", (r_id,))
			db.commit()

		daily_reminders = db.execute("SELECT id, nick, chan, content, timestamp FROM daily WHERE timestamp < ?", (time.time(),)).fetchall()
		for r_id, nick, chan, content, timestamp in daily_reminders:
			logging.info("Resolving daily reminder #%s" % r_id)
			msg = "%s: %s (#%s)" % (nick, content, r_id)
			self._msg(chan, msg)
			self._highlight(self.client.nick, chan, msg, nick, db_conn=db)
			db.execute("UPDATE daily SET timestamp = ? WHERE id = ?", (timestamp+86400, r_id))
			db.commit()

	def _check_for_new_xkcd(self, db):
		# Wait until after handshakes
		if not self.WELCOMED:
			return

		if int(db_keyval('last_comic_check', default=0, conn=db)) + 60 < time.time():
			db_keyval('last_comic_check', int(time.time()), conn=db)
			comic_json_uri = "http://xkcd.com/info.0.json"
			try:
				data = urllib2.urlopen(comic_json_uri, timeout=3)
				xkcd_json = json.load(data)
				if int(db_keyval('last_comic_num', default=0, conn=db)) < xkcd_json['num']:
					db_keyval('last_comic_num', xkcd_json['num'], conn=db)
					s = config['servers'][self.client.host]
					for chan in s.get('channels', ()):
						self._msg(chan, "New xkcd #%d: %s <http://xkcd.com/%d/>" % (
							xkcd_json['num'], xkcd_json['title'], xkcd_json['num'],
						))
			except urllib2.URLError:
				logging.warning("Unable to load info for latest xkcd comic while checking for new.")

	def _adjust_channel_limits(self, db):
		if not self.WELCOMED:
			return

		for channel in config['userlimit']:
			usercount = len(self.channel_userlists[channel])
			if usercount != self.channel_usercounts.get(channel, 0):
				self.client.send('MODE', channel, '+l %d' % (usercount+2))
			self.channel_usercounts[channel] = usercount

	def whoisbot(self, nick, chan, user, msg):
		"""Add a bot to the known bots list based on WHOIS."""
		logging.info("Adding '%s' to the known bots list." % user)
		self.KNOWN_BOTS.add(user)

	def whoisoperator(self, nick, chan, user, msg):
		"""Check and see if this is a network service, if so, add it to known bots."""
		if msg == 'is a Network Service':
			logging.info("Adding '%s' to the known bots list." % user)
			self.KNOWN_BOTS.add(user)

	def namreply(self, nick, chan, equals, channel, nicklist):
		"""Process server's notification of channel occupants."""
		nicks = set(x.lstrip('+@%~&').lower() for x in nicklist.split())
		logging.info("[namreply] %s -> %r" % (channel, nicks))
		self.channel_userlists[channel] = nicks

	def nick(self, nick, newnick):
		"""Process server's notification of a nick change."""
		nick = nick.split('!')[0].lower()
		newnick = newnick.lower()
		logging.info("[renick] %s -> %s" % (nick, newnick))
		for userlist in self.channel_userlists.itervalues():
			if nick in userlist:
				userlist.discard(nick)
				userlist.add(newnick)

	def part(self, nick, chan, msg=None):
		"""Process server's notification of a user leaving a channel."""
		nick = nick.split('!')[0].lower()
		logging.info("[part] %s -> %s" % (nick, chan))
		self.channel_userlists[chan].discard(nick)

	def quit(self, nick, msg=None):
		"""Process server's notification of a user leaving the server."""
		nick = nick.split('!')[0].lower()
		logging.info("[quit] %s (%s)" % (nick, msg))
		for userlist in self.channel_userlists.itervalues():
			userlist.discard(nick)

	def join(self, nick, chan):
		"""When a user joins a channel..."""
		nick = nick.split('!')[0]
		logging.info("[join] %s -> %s" % (nick, chan))
		self.channel_userlists[chan].add(nick.lower())

		last_join = self.last_join[chan].get(nick, 0)
		now = time.time()
		if last_join + 60 > now:
			# On-join actions only trigger once a minute per channel
			return
		self.last_join[chan][nick] = now

		# See if they have a catchphrase for this channel
		catchphrase = db.execute("SELECT phrase FROM catchphrases WHERE nick = ? AND chan = ?", (nick, chan)).fetchone()
		db.rollback()
		if catchphrase and last_join + 3600 < now:
			self._msg(chan, "« %s » - %s".decode('utf-8') % (catchphrase[0], nick))

		# Check to see if they have replay enabled
		replay_lines = db.execute("SELECT lines FROM replay WHERE nick = ? AND chan = ?", (nick, chan)).fetchone()
		if replay_lines:
			lines = replay_lines[0]

			recent = list(self.replay_buffers[chan])[-1*lines:]
			if recent:
				msg = '\n'.join("%s ago - [%s] <%s> %s" % (timeago(int(time.time() - x[0])), chan, x[1], x[2]) for x in recent)
				self._msg(nick, msg)
				self._msg(nick, "Replay for %s complete." % chan)

		# Check to see if they have any voicemail
		voicemail = db.execute("SELECT COUNT(*) FROM voicemail WHERE tonick = ?", (nick.lower(),)).fetchone()[0]
		db.rollback()
		if voicemail > 0:
			self._msg(nick, "You have %d pending voicemails. Use '%svoicemail get <quantity>' to retrieve them." % (voicemail, config['sigil']))

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

	def _is_nick_ignored(self, nick):
		"""Check to see if we should be ignoring this nick."""

		just_nick = nick.split('!')[0]
		if just_nick not in self.KNOWN_NICKS:
			self.client.send("WHOIS", just_nick)
			self.KNOWN_NICKS.add(just_nick)
		elif just_nick in self.KNOWN_BOTS:
			return True

		return False

	def _record_for_replay(self, nick, chan, msg):
		"""Update the replay buffer for a channel."""
		if not chan.startswith('#'):
			return
		self.replay_buffers[chan].append((time.time(), nick.split('!')[0], msg))

	def privmsg(self, nick, chan, msg):
		self._seen(nick, chan)
		if self._is_nick_ignored(nick):
			logging.debug("[ignored message] %s -> %s" % (nick, chan))
		else:
			logging.debug("[message] %s -> %s: %s" % (nick, chan, msg))
			self._record_for_replay(nick, chan, msg)
			self._parse_line(nick, chan, msg)

	def notice(self, nick, chan, msg):
		self._seen(nick, chan)
		if self._is_nick_ignored(nick):
			logging.debug("[ignored notice] %s -> %s" % (nick, chan))
		else:
			logging.debug("[notice] %s -> %s: %s" % (nick, chan, msg))
			self._record_for_replay(nick, chan, msg)
			self._parse_line(nick, chan, msg)

	def _seen(self, nick, chan):
		"""Record new information for when this nick was seen."""
		db.execute("INSERT OR REPLACE INTO seen (nick, chan, timestamp) VALUES (?,?,?)", (
			nick.split('!')[0].lower(), chan, time.time(),
		))
		db.commit()

	def _url(self, url, nick, chan):
		"""Record when this URL was seen."""
		prev = db.execute("SELECT nick, chan, timestamp FROM urls WHERE url = ?", (url,)).fetchone()
		db.rollback()
		if prev:
			return {'nick': prev[0], 'chan': prev[1], 'timestamp': prev[2]}
		else:
			db.execute("INSERT OR IGNORE INTO urls (url, nick, chan, timestamp) VALUES (?,?,?,?)", (
				url, nick.split('!')[0], chan, time.time(),
			))
			db.commit()
			return None

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
		if chan == self.client.nick:
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

		# See if this is an action we recognize
		m = self.ACTION_RE.match(msg)
		if m:
			act = m.group(1)
			cmd_func = '_cmd_%s' % act.upper()
			if hasattr(self, cmd_func):
				func = getattr(self, cmd_func)
				if hasattr(func, 'is_action') and func.is_action:
					logging.info("[action] %s -> %s: %s" % (nick, chan, act))
					func(nick, chan, None)
					return
			logging.warning('Unknown action "%s".' % act)

		# See if this is a karma increase
		# (only for actual channels)
		m = self.KARMA_RE.match(msg)
		if chan.startswith('#') and m:
			self._karma(nick, chan, msg, m.group(1))
			return

		# See if this is a highlight for someone not currently in-channel
		# (only for actual channels, not PMs)
		m = self.HIGHLIGHT_RE.match(msg)
		if chan.startswith('#') and m:
			self._highlight(nick, chan, msg, m.group(1))
			# Note that we don't return here - we still announce URLs if present

		# See if there's a URL we should recognize
		m = self.URL_RE.search(msg)
		if m:
			logging.info("[url] %s -> %s: %s" % (nick, chan, m.group()))
			prev = self._url(m.group(), nick, chan)
			self._url_announce(chan, m.group(), prev, msg)
			return

		# If we've gotten here and we're in a PM, we should say something
		if pm and not chan.endswith(('.com', '.net', '.org', '.edu')):
			self._msg(chan, "Sorry, I don't understand that (did you forget to use the command prefix?)."
				" See '%shelp' for commands." % (config['sigil']))

	def _karma(self, nick, chan, msg, target):
		"""Check to see if we should add karma for a user."""
		nick = nick.split('!')[0].lower()
		now = time.time()
		target = target.lower()

		# Only allow a given user to give another given user karma once
		# an hour.
		if self.last_karma[nick].get(target) > now-3600:
			return
		self.last_karma[nick][target] = now

		if nick == target:
			self._kick(chan, nick, "instant karma")
			return

		existing = db.execute("SELECT karma FROM karma WHERE nick = ?", (target,)).fetchone()
		if existing:
			db.execute("UPDATE karma SET karma = ? WHERE nick = ?", (existing[0]+1, target))
		else:
			db.execute("INSERT INTO karma (nick, karma) VALUES (?,?)", (target, 1))
		db.commit()

	def _highlight(self, nick, chan, msg, target, db_conn=None):
		"""Check to see if we need to store a voicemail for a highlight message."""
		if db_conn is None:
			db_conn = db

		# Don't store voicemail for PMs
		if not chan.startswith('#'):
			return

		nick = nick.split('!')[0]
		target = target.lower()
		if target in self.channel_userlists[chan]:
			# Don't need voicemail for present users
			return

		seen = db_conn.execute("SELECT nick FROM seen WHERE nick = ?", (target.lower(),)).fetchone()
		db_conn.rollback()
		if not seen:
			# Don't need voicemail for a nick we've never seen say anything
			return

		# We've seen the nick before and they're not online, so store a voicemail.
		result = db_conn.execute("INSERT INTO voicemail (fromnick, tonick, chan, contents, timestamp) VALUES (?,?,?,?,?)",
			(nick, target, chan, msg, time.time()))
		db_conn.commit()
		self._msg(chan, "Added voicemail #%d for absent user %s." % (result.lastrowid, target))

	def _url_announce(self, chan, url, prev, msg):
		"""Announce the info for a detected URL in the channel it was detected in."""

		if chan not in config['urlannounce']:
			logging.info("Not announcing URL in channel %s [not in urlannounce list]." % chan)
			return

		try:
			if not url.startswith("http"):
				url = "http://%s" % url
			orig_domain = urlparse(url).netloc
			result = urllib2.urlopen(url, timeout=5)
			final_url = result.geturl()
			final_domain = urlparse(final_url).netloc

			report_components = []

			if orig_domain != final_domain:
				report_components.append("[%s]" % final_domain)

			if result.info().getmaintype() == 'text':
				# Try parsing it with BeautifulSoup
				parsed = soup(result.read(204800), convertEntities=soup.HTML_ENTITIES) # Only 200k or less.
				title_tag = parsed.find('title')
				if title_tag:
					title_segments = re.split(r'[^a-z]+', title_tag.string[:100].lower())
					title_segment_letters = [s for s in title_segments if s]

					f = url.lower()
					title_segments_found = [s for s in title_segment_letters if s in f]

					found_len = len(''.join(title_segments_found))
					total_len = len(''.join(title_segment_letters))

					condensed_title = ' '.join(title_tag.string.split())[:100]

					if ('trigger warning' in msg.lower()) or ('TW' in msg):
						logging.info("Not reporting title '%s' because of trigger warning in '%s'." % (condensed_title, msg))
					elif found_len < 0.6 * total_len:
						logging.info("Reporting title '%s' (found: %s, total: %s)" % (
							condensed_title, found_len, total_len))
						report_components.append('"%s"' % condensed_title)
					else:
						logging.info("Not reporting title '%s' (found: %s, total: %s)" % (
							condensed_title, found_len, total_len))


			# Only announce the url if something caught our attention
			if report_components:
				self._msg(chan, "Link points to %s" % ' - '.join(report_components))
			if prev:
				self._msg(chan, "(First linked by %s in %s, %s ago.)" % (prev['nick'], prev['chan'],
					timeago(int(time.time()-prev['timestamp']))))

		except urllib2.URLError:
			logging.info("URLError while retrieving %s" % url, exc_info=True)
		except ValueError:
			logging.warning("Unable to examine URL %s" % url, exc_info=True)

	# COMMANDS
	def _cmd_ABOUT(self, nick, chan, arg):
		"""about - Provides basic information about this bot."""
		self._msg(chan,
			"I'm an IRC bot. My owner is Aaeriele and her owner is DaBigCheez.\nMore info is available at http://git.aiiane.com/kitn",
		)
	_cmd_HELP = _cmd_ABOUT # For now, 'help' will just alias to 'about'. Might add more interactive help later.

	def _cmd_AT(self, nick, chan, arg):
		"""at - Set up a reminder that occurs at the specified time."""
		usage = lambda: self._msg(chan, "Usage: at <time> <timezone> <text>")

		if not arg:
			return usage()

		m = re.match(r"(\d+(?::\d+)?)\s?(am|AM|pm|PM)?\s+(\S+)\s+(.+)$", arg)
		if not m:
			return usage()

		time_val = m.group(1).split(':', 1)
		am_pm = m.group(2)
		tz_string = m.group(3)
		content = m.group(4)

		if len(time_val) == 1:
			if len(time_val[0]) == 4:
				# Military time
				hour, minute = int(time_val[0][:-2]), int(time_val[0][-2:])
			else:
				hour, minute = int(time_val[0]), 0
		else:
			hour, minute = int(time_val[0]), int(time_val[1])

		if am_pm in ('pm', 'PM') and hour < 12:
			hour += 12
		elif am_pm in ('am', 'AM') and hour == 12:
			hour = 0

		if hour > 23 or minute > 59:
			return self._msg(chan, "%d:%d is not a valid time." % (hour, minute))

		# So that things like 'pst' or 'mdt' can be used
		if len(tz_string) <= 3:
			tz_string = tz_string.upper()

		if tz_string in self.TIMEZONES:
			timezone = self.TIMEZONES[tz_string]
		else:
			try:
				timezone = pytz.timezone(tz_string)
			except pytz.exceptions.UnknownTimeZoneError:
				return self._msg(chan, "'%s' is not a recognized timezone." % tz_string)

		dateobj = datetime.datetime.now(timezone).replace(hour=hour, minute=minute, second=0)
		if dateobj < datetime.datetime.now(timezone):
			dateobj += datetime.timedelta(days=1)

		timestamp = time.mktime(dateobj.astimezone(pytz.timezone('America/Los_Angeles')).timetuple())
		nick = nick.split('!')[0]
		result = db.execute("INSERT INTO reminders (nick, chan, timestamp, content) VALUES (?,?,?,?)",
			(nick, chan, timestamp, content))
		r_id = result.lastrowid
		db.commit()

		logging.info("Added reminder #%s at %s" % (r_id, timestamp))
		self._msg(chan, "%s: reminder #%s added for %s." % (nick, r_id, dateobj.strftime('%x %X %Z')))

	def _cmd_BUG(self, nick, chan, arg):
		"""bug - Report a bug with Kitn (creates an issue on the issue tracker)"""
		usage = lambda: self._msg(chan, "Usage: bug <text>")

		if not arg:
			return usage()

		data = {
			'title': arg[:100],
			'content': "%s\n\n(Added via IRC command by %s)" % (arg, nick),
			'responsible': 'Aiiane',
			'kind': 'bug',
		}

		auth = base64.encodestring("%(username)s:%(password)s" % config['bitbucket'])[:-1]
		req = urllib2.Request('https://api.bitbucket.org/1.0/repositories/Aiiane/kitn/issues/',
			urlencode(data), {"Authorization": "Basic %s" % auth})

		try:
			result = urllib2.urlopen(req, timeout=5)
		except urllib2.URLError:
			logging.error("Failed to post new issue on Bitbucket:", exc_info=True)
			return self._msg(chan, "Unable to create new issue.")

		result = json.load(result)
		self._msg(chan, "[%(status)s] %(title)s - %(comment_count)s comment(s), created on %(created_on)s" % result)
		self._msg(chan, "http://git.aiiane.com/kitn/issue/%(local_id)s" % result)

	def _cmd_CALC(self, nick, chan, arg):
		"""calc - Invoke the Google calculator with a given query and return the result."""
		usage = lambda: self._msg(chan, "Usage: calc <expression>")

		if not arg:
			return usage()

		data = urlencode({
			'q': arg,
			'hl': 'en',
		})

		try:
			result = urllib2.urlopen("http://www.google.com/ig/calculator?%s" % data, timeout=5)
		except urllib2.URLError:
			logging.error("Error while querying Google Calculator:", exc_info=True)
			return self._msg(chan, "An error occurred while querying the Google calculator.")

		response = result.read()
		m = re.match(r'''\{lhs: "(.*)",rhs: "(.*)",error: "(.*)",icc: (.*)\}''', response)
		if not m:
			logging.error("Unable to parse response from Google calculator: '%s'" % response)
			return self._msg(chan, "Unable to parse response from querying the Google calculator.")

		if m.group(3) != "":
			return self._msg(chan, "Unable to parse expression.")

		POWER_RE = re.compile(r'''\\x3csup\\x3e([\d,.]+)\\x3c/sup\\x3e''')

		lhs, rhs = m.group(1), m.group(2)

		lhs = POWER_RE.sub(r"^\1", lhs).replace(r"\x26#215;", 'x')
		rhs = POWER_RE.sub(r"^\1", rhs).replace(r"\x26#215;", 'x')

		self._msg(chan, "%s = %s" % (lhs, rhs))

	def _cmd_CANCEL(self, nick, chan, arg):
		"""cancel - Cancels the specified reminder."""
		usage = lambda: self._msg(chan, "Usage: cancel <reminder #>")

		if not arg:
			return usage()

		try:
			r_id = int(arg)
		except (TypeError, ValueError):
			return usage()

		nick = nick.split('!')[0]
		result = db.execute("DELETE FROM reminders WHERE id = ? AND nick = ?", (r_id, nick))
		db.commit()

		if result.rowcount:
			return self._msg(chan, "%s: cancelled reminder #%s." % (nick, r_id))
		else:
			return self._msg(chan, "%s: unable to cancel reminder #%s (non-existant? not yours?)." % (nick, r_id))

	def _cmd_CATCHPHRASE(self, nick, chan, arg):
		"""catchphrase - Sets or removes an on-join catchphrase for this nick+channel."""

		if not chan.startswith('#'):
			return self._msg(chan, 'You can only set a catchphrase in a regular channel.')

		nick = nick.split('!')[0]

		if not arg:
			catchphrase = db.execute("SELECT phrase FROM catchphrases WHERE nick = ? AND chan = ?", (nick, chan)).fetchone()
			db.rollback()
			if catchphrase:
				self._msg(chan, "« %s » - %s".decode('utf-8') % (catchphrase[0], nick))
			else:
				self._msg(chan, "%s does not have a catchphrase set." % nick)
		elif arg == 'delete':
			db.execute("DELETE FROM catchphrases WHERE nick = ? and chan = ?", (nick, chan))
			db.commit()
			self._msg(chan, "%s: catchphrase for %s cleared." % (nick, chan))
		else:
			existing = db.execute("SELECT id FROM catchphrases WHERE nick = ? AND chan = ?", (nick, chan)).fetchone()
			if existing:
				db.execute("UPDATE catchphrases SET phrase = ? WHERE id = ?", (arg, existing[0]))
			else:
				db.execute("INSERT INTO catchphrases (nick, chan, phrase) VALUES (?,?,?)", (nick, chan, arg))
			db.commit()
			self._msg(chan, "%s: catchphrase set to « %s »" % (nick, arg))

	@is_action
	def _cmd_CATNIP(self, nick, chan, arg):
		"""catnip - Give the kitn catnip."""
		self._emote(chan, "perks up and paws at %s excitedly" % nick.split('!')[0])

	def _cmd_CHOOSE(self, nick, chan, arg):
		"""choose - Given a set of items, pick one randomly."""
		usage = lambda: self._msg(chan, "Usage: choose <item> <item> ...")

		items = arg.split()
		if not items:
			return usage()
		else:
			self._msg(chan, "%s: %s" % (nick.split('!')[0], random.choice(items)))

	@is_action
	def _cmd_CUDDLE(self, nick, chan, arg):
		"""cuddle - Ask the bot for a cuddle."""
		self._emote(chan, "cuddles %s" % nick.split('!')[0])

	def _cmd_DAILY(self, nick, chan, arg):
		"""daily - Set up a daily reminder."""
		usage = lambda: self._msg(chan, "Usage: daily [add <text> | remove <id>]")

		if not arg:
			return usage()

		args = arg.split(None, 1)
		if len(args) != 2:
			return usage()

		nick = nick.split('!')[0]

		if args[0] == 'add':
			now = time.time()

			result = db.execute("INSERT INTO daily (nick, chan, timestamp, content) VALUES (?,?,?,?)",
				(nick, chan, now+86400, args[1]))
			r_id = result.lastrowid
			db.commit()

			logging.info("Added daily reminder #%s at %s" % (r_id, now))
			return self._msg(chan, "%s: daily reminder #%s added for %s PST." % (nick, r_id,
				datetime.datetime.fromtimestamp(now).strftime('%X')))

		elif args[0] == 'remove':
			try:
				r_id = int(args[1])
			except (TypeError, ValueError):
				return self._msg(chan, "Reminder ID must be numeric.")
			
			exists = db.execute("SELECT nick FROM daily WHERE id = ?", (r_id,)).fetchone()
			db.rollback()
			if not exists:
				return self._msg(chan, "No daily reminder exists with that ID.")
			if exists[0] != nick:
				return self._msg(chan, "You may not remove daily reminders set by someone else.")

			db.execute("DELETE FROM daily WHERE id = ?", (r_id,))
			db.commit()
			return self._msg(chan, "%s: removed daily reminder #%s." % (nick, r_id))

		else:
			return usage()

	def _cmd_DEFINE(self, nick, chan, arg):
		"""wp - Search wiktionary and return a snippet about the top result."""
		usage = lambda: self._msg(chan, "Usage: define <query>")

		if not arg:
			return usage()

		wp_query_url = "http://en.wiktionary.org/w/api.php?%s" % urlencode({
				"action": "query",
				"list": "search",
				"srsearch": arg,
				"format": "json",
			})
		try:
			data = urllib2.urlopen(wp_query_url, timeout=5)
			results = json.load(data)['query']['search']
			if results:
				title = results[0]['title']
				url = "http://en.wiktionary.org/wiki/%s" % quote_plus(title.replace(' ', '_'))
				snippet = ''.join(e.string for e in soup(results[0]['snippet'], convertEntities=soup.HTML_ENTITIES) if e)
				self._msg(chan, "%s <%s>" % (snippet, url))
			else:
				self._msg(chan, "No results found for '%s'." % arg)
		except urllib2.URLError:
			self._msg(chan, "Unable to perform Wiktionary search.")

	def _cmd_FEATURE(self, nick, chan, arg):
		"""bug - Request a feature for Kitn (creates an issue on the issue tracker)"""
		usage = lambda: self._msg(chan, "Usage: feature <text>")

		if not arg:
			return usage()

		data = {
			'title': arg[:100],
			'content': "%s\n\n(Added via IRC command by %s)" % (arg, nick),
			'responsible': 'Aiiane',
			'kind': 'enhancement',
		}

		auth = base64.encodestring("%(username)s:%(password)s" % config['bitbucket'])[:-1]
		req = urllib2.Request('https://api.bitbucket.org/1.0/repositories/Aiiane/kitn/issues/',
			urlencode(data), {"Authorization": "Basic %s" % auth})

		try:
			result = urllib2.urlopen(req, timeout=5)
		except urllib2.URLError:
			logging.error("Failed to post new issue on Bitbucket:", exc_info=True)
			return self._msg(chan, "Unable to create new issue.")

		result = json.load(result)
		self._msg(chan, "[%(status)s] %(title)s - %(comment_count)s comment(s), created on %(created_on)s" % result)
		self._msg(chan, "http://git.aiiane.com/kitn/issue/%(local_id)s" % result)

	def _cmd_FORGET(self, nick, chan, arg):
		"""forget - Remove a factoid from the bot's knowledge."""
		usage = lambda: self._msg("Usage: forget <keyword>")

		if not arg:
			return usage()

		result = db.execute("DELETE FROM factoids WHERE keyword = ?", (arg,))
		db.commit()
		if result.rowcount:
			self._msg(chan, "Removed factoid '%s'." % (arg,))
		else:
			self._msg(chan, "No factoid '%s' found." % (arg,))

	def _cmd_GOOGLE(self, nick, chan, arg):
		"""google - Does a google search for the supplied query and returns the first result."""
		usage = lambda: self._msg(chan, "Usage: google <query>")

		if not arg:
			return usage()

		query = urlencode({
			'v': '1.0',
			'key': config['google']['apikey'],
			'q': arg,
		})

		try:
			result = json.load(urllib2.urlopen('https://ajax.googleapis.com/ajax/services/search/web?%s' % query))
			self._msg(chan, "%(titleNoFormatting)s <%(unescapedUrl)s>" % (result['responseData']['results'][0]))
		except:
			logging.warning("Error while attempting to retrieve results from Google API:", exc_info=True)
			self._msg(chan, "An error was encountered while trying to complete the search request.")

	@is_action
	def _cmd_HUG(self, nick, chan, arg):
		"""hug - Ask the bot for a hug."""
		self._emote(chan, "hugs %s" % nick.split('!')[0])

	def _cmd_IN(self, nick, chan, arg):
		"""in - Set up a reminder that occurs after a specified period of time."""
		usage = lambda: self._msg(chan, "Usage: in <amount> <time unit> <text>")

		if not arg:
			return usage()

		args = arg.split()

		if len(args) < 2:
			return usage()

		# Attempt to parse the time specifier
		time_units = {
			's': 1, 'sec': 1, 'secs': 1, 'second': 1, 'seconds': 1,
			'm': 60, 'min': 60, 'mins': 60, 'minute': 60, 'minutes': 60,
			'h': 3600, 'hr': 3600, 'hrs': 3600, 'hour': 3600, 'hours': 3600,
			'd': 86400, 'day': 86400, 'days': 86400,
			'w': 604800, 'wk': 604800, 'wks': 604800, 'week': 604800, 'weeks': 604800,
		}

		m = re.match(r"(\d+(?:\.\d+)?)(\D+)$", args[0])
		if m:
			args[0:1] = [m.group(1), m.group(2)]

		# After we've expanded any potential abbreviation, we expect 3 args
		if len(args) < 3:
			return usage()

		try:
			time_amount = float(args[0])
		except (ValueError, TypeError):
			return usage()

		if not time_amount > 0:
			return self._msg(chan, "Reminders may not be set in the past.")

		if args[1] not in time_units:
			return self._msg(chan, "'%s' is not a valid time unit. Valid options: %s" % (
				args[1], ', '.join(sorted(time_units, key=lambda x: (time_units[x], x))),
			))

		nick = nick.split('!')[0]
		timestamp = int(time.time() + (time_amount * time_units[args[1]]))
		content = ' '.join(args[2:])
		result = db.execute("INSERT INTO reminders (nick, chan, timestamp, content) VALUES (?,?,?,?)",
			(nick, chan, timestamp, content))
		r_id = result.lastrowid
		db.commit()

		logging.info("Added reminder #%s at %s" % (r_id, timestamp))
		self._msg(chan, "%s: reminder #%s added for %s PST." % (nick, r_id,
			datetime.datetime.fromtimestamp(timestamp).strftime('%x %X')))

	def _cmd_ISSUE(self, nick, chan, arg):
		"""issue - look up an issue on Kitn's issue tracker."""
		usage = lambda: self._msg(chan, "Usage: issue <number>")

		if not arg:
			return usage()

		try:
			issue = int(arg)
		except:
			return usage()

		data = urllib2.urlopen("https://api.bitbucket.org/1.0/repositories/Aiiane/kitn/issues/%d/" % issue)
		result = json.load(data)
		self._msg(chan, "[%(status)s] %(title)s - %(comment_count)s comment(s), created on %(created_on)s" % result)
		self._msg(chan, "http://git.aiiane.com/kitn/issue/%d" % issue)

	@admin_only
	def _cmd_JOIN(self, nick, chan, arg):
		"""part - Make the bot join the specified channel."""
		usage = lambda: self._msg(chan, "Usage: join <channel>")

		if not arg:
			return usage()

		self._msg(chan, "Joining channel %s." % arg)
		helpers.join(self.client, arg)

	def _cmd_KARMA(self, nick, chan, arg):
		"""karma - Look up the karma for a specified user."""
		usage = lambda: self._msg(chan, "Usage: karma <nick>")

		if not arg:
			return usage()

		karma = db.execute("SELECT karma FROM karma WHERE nick = ?", (arg.lower(),)).fetchone()
		db.rollback()
		if karma:
			return self._msg(chan, "User '%s' has %s karma." % (arg, karma[0]))
		else:
			return self._msg(chan, "User '%s' has no karma." % (arg,)) 

	def _cmd_LEARN(self, nick, chan, arg):
		"""learn - Teach the bot a factoid identified by a keyword."""
		usage = lambda: self._msg(chan, "Usage: learn <keyword> <text>")

		if not arg:
			return usage()

		args = arg.split()
		if len(args) < 2:
			return usage()

		try:
			db.execute("INSERT INTO factoids (keyword, content, nick, timestamp) VALUES (?,?,?,?)", (
				args[0], ' '.join(args[1:]), nick.split('!')[0], time.time(),
			))
			db.commit()
		except sqlite3.IntegrityError:
			return self._msg(chan, "The factoid '%s' already exists.\n"
				"(Use the 'relearn' command to overwrite it, or the 'forget' command to remove it.)" % args[0])

		self._msg(chan, "Factoid '%s' added." % args[0])

	def _cmd_MEME(self, nick, chan, arg):
		"""meme - search for a meme on KnowYourMeme"""
		usage = lambda: self._msg(chan, "Usage: meme <query>")

		if not arg:
			return usage()

		self._msg(chan, "http://knowyourmeme.com/search?%s" % urlencode({'q': arg}))

	def _cmd_MLP(self, nick, chan, arg):
		"""mlp - Link to the provided name on the MLP wiki."""
		usage = lambda: self._msg(chan, "Usage: mlp <page name>")

		if not arg:
			return usage()

		page = '_'.join((arg[0].upper() + arg[1:]).split())
		self._msg(chan, "http://mlp.wikia.com/wiki/%s" % page)

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

	@is_action
	def _cmd_PET(self, nick, chan, arg):
		"""pet - Pet the kitn."""
		self._emote(chan, "purrs")

	def _cmd_PRONOUNS(self, nick, chan, arg):
		"""pronouns - Get or set preferred pronouns for a nick."""
		usage = lambda: self._msg(chan, "Usage: pronouns get <nick>, pronouns set <text>")

		if not arg:
			return usage()
		args = arg.split()

		if len(args) < 2:
			return usage()

		if args[0] == 'set':
			nick = nick.split('!')[0]
			db.execute("INSERT OR REPLACE INTO pronouns (nick, content) VALUES (?,?)", (nick.lower(), ' '.join(args[1:])))
			db.commit()
			self._msg(chan, "%s: done!" % nick)
		elif args[0] == 'get':
			result = db.execute("SELECT content FROM pronouns WHERE nick = ?", (args[1].lower(),)).fetchone()
			if not result:
				self._msg(chan, "I don't know %s's pronouns." % args[1])
			else:
				self._msg(chan, "Pronouns for %s are %s." % (args[1], result[0]))
			db.rollback()
		else:
			return usage()

	@admin_only
	def _cmd_QUIT(self, nick, chan, arg):
		helpers.quit(self.client, 'Shutting down...')

	def _cmd_QUOTE(self, nick, chan, arg):
		"""quote - Add, remove, or look up quotes."""
		usage = lambda: self._msg(chan, "Usage: quote [random | add <text> | remove <id> | get <id>]")

		if not arg:
			return usage()

		args = arg.split(None, 1)
		if args[0] == 'random':
			max_quote_id = db.execute("SELECT MAX(id) FROM quotes").fetchone()
			if not max_quote_id:
				db.rollback()
				return self._msg(chan, "No quotes found.")

			cutoff = random.randint(1, max_quote_id[0])
			quote = db.execute("""
				SELECT id, adder, content, chan, timestamp
				FROM quotes
				WHERE id >= ?
				ORDER BY id
				LIMIT 1
				""", (cutoff,)).fetchone()
			db.rollback()
			self._msg(chan, "#%s - %s (added by %s, %s ago)" % (
					quote[0], quote[2], quote[1], timeago(int(time.time()-quote[4]))
				))

		elif args[0] == 'add':
			if len(args) != 2:
				return usage()

			just_nick = nick.split('!')[0].lower()
			join_time = self.last_join[chan].get(just_nick, 0)
			if join_time > time.time() - 30:
				logging.info("Marking %s as 'bot' because of quote add abuse.", nick)
				self.KNOWN_BOTS.add(just_nick)
				return

			result = db.execute("INSERT INTO quotes (adder, content, chan, timestamp) VALUES (?,?,?,?)",
					(just_nick, args[1], chan, time.time()),
				)
			db.commit()
			self._msg(chan, "Quote #%s added." % result.lastrowid)

		elif args[0] == 'remove':
			if len(args) != 2:
				return usage()
			try:
				quote_id = int(args[1])
			except (ValueError, TypeError):
				return usage()

			adder = db.execute("SELECT adder FROM quotes WHERE id = ?", (quote_id,)).fetchone()
			db.rollback()
			if not adder:
				return self._msg(chan, "Quote #%s not found." % args[1])
			if adder[0] != nick.split('!')[0].lower():
				return self._msg(chan, "You may not remove quotes you did not add.")

			db.execute("DELETE FROM quotes WHERE id = ?", (quote_id,))
			db.commit()
			self._msg(chan, "Quote #%s removed." % quote_id)

		elif args[0] == 'get':
			if len(args) != 2:
				return usage()
			try:
				quote_id = int(args[1])
			except (ValueError, TypeError):
				return usage()

			quote = db.execute("""
				SELECT id, adder, content, chan, timestamp
				FROM quotes
				WHERE id = ?""", (quote_id,)).fetchone()
			db.rollback()
			if not quote:
				return self._msg(chan, "Quote #%s not found." % quote_id)

			self._msg(chan, "#%s - %s (added by %s, %s ago)" % (
					quote[0], quote[2], quote[1], timeago(int(time.time()-quote[4]))
				))

		else:
			return usage()

	def _cmd_RECALL(self, nick, chan, arg):
		"""recall - Display the text of a factoid, if it exists."""
		usage = lambda: self._msg("Usage: recall <keyword>")

		if not arg:
			return usage()

		result = db.execute("SELECT keyword, content, nick, timestamp from factoids WHERE keyword = ?", (arg,)).fetchone()
		db.rollback()
		if not result:
			self._msg(chan, "%s: I don't know '%s'." % (nick.split('!')[0], arg))
		else:
			self._msg(chan, "%s: %s" % (nick.split('!')[0], result[1]))

	def _cmd_RELEARN(self, nick, chan, arg):
		"""relearn - Teach the bot a factoid identified by a keyword, even if it already exists."""
		usage = lambda: self._msg(chan, "Usage: relearn <keyword> <text>")

		if not arg:
			return usage()

		args = arg.split()
		if len(args) < 2:
			return usage()

		db.execute("INSERT OR REPLACE INTO factoids (keyword, content, nick, timestamp) VALUES (?,?,?,?)", (
			args[0], ' '.join(args[1:]), nick.split('!')[0], time.time(),
		))
		db.commit()

		self._msg(chan, "Factoid '%s' added." % args[0])

	def _cmd_REMINDERS(self, nick, chan, arg):
		"""reminders - Get a list of active reminders."""

		nick = nick.split('!')[0]

		if chan.startswith('#'):
			return self._msg(chan, "%s: that command must be used in PM." % nick)

		reminders = db.execute("SELECT id, chan, content, timestamp FROM reminders WHERE nick = ?", (nick,)).fetchall()
		daily_reminders = db.execute("SELECT id, chan, content, timestamp FROM daily WHERE nick = ?", (nick,)).fetchall()

		if not reminders and not daily_reminders:
			return self._msg(chan, "You have no reminders set.")

		if reminders:
			self._msg(chan, "Pending once-off reminders:")
			for r in reminders:
				self._msg(chan, "#%s (%s, %s PST): %s" % (r[0], r[1], datetime.datetime.fromtimestamp(r[3]).strftime('%X'), r[2]))

		if daily_reminders:
			self._msg(chan, "Daily reminders:")
			for r in daily_reminders:
				self._msg(chan, "#%s (%s, %s PST): %s" % (r[0], r[1], datetime.datetime.fromtimestamp(r[3]).strftime('%X'), r[2]))

	@admin_only
	def _cmd_RENORMALIZE(self, nick, chan, arg):
		"""renormalize - Rebuild the quotes table so that it has sequential IDs."""

		try:
			db.execute("""
				CREATE TABLE quotes_new (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					adder TEXT,
					chan TEXT,
					content TEXT,
					timestamp INTEGER
				)""")

			quotes_cursor = db.execute("SELECT adder, chan, content, timestamp FROM quotes")
			if not quotes_cursor:
				self._msg(chan, "Unable to rebuild quotes table; couldn't get quotes.")
				db.rollback()
				return

			quote_counter = 0
			for vals in quotes_cursor:
				db.execute("INSERT INTO quotes_new (adder, chan, content, timestamp) VALUES (?,?,?,?)", vals)
				quote_counter += 1

			db.execute("DROP TABLE quotes")
			db.execute("ALTER TABLE quotes_new RENAME TO quotes")
			db.commit()

			self._msg(chan, "Successfully rebuilt quotes table with %d entries." % quote_counter)

		except:
			logging.error("Unable to rebuild quotes table:", exc_info=True)
			self._msg(chan, "Unable to rebuild quotes table.")
			db.rollback()
			return

	def _cmd_REPLAY(self, nick, chan, arg):
		"""replay - Request replay-on-join for the current channel and user, or turn it off."""
		usage = lambda: self._msg(chan, "Usage: replay <number> (0 for off).")

		try:
			lines = int(arg)
		except:
			return usage()

		lines = max(0, min(lines, config['limits']['replay']))

		nick = nick.split('!')[0]
		if not lines:
			db.execute("DELETE FROM replay WHERE nick = ? AND chan = ?", (nick, chan))
			db.commit()
			return self._msg(chan, '%s: You will no longer receive message replay on join for this channel.' % nick)
		else:
			existing = db.execute("SELECT id FROM replay WHERE nick = ? AND chan = ?", (nick, chan)).fetchone()
			if existing:
				db.execute("UPDATE replay SET lines = ? WHERE id = ?", (lines, existing[0]))
			else:
				db.execute("INSERT INTO replay (nick, chan, lines) VALUES (?,?,?)", (nick, chan, lines))
			db.commit()
			return self._msg(chan, '%s: You will now receive up to %d lines of replay when joining this channel.' % (nick, lines))

	@is_action
	def _cmd_SCRITCH(self, nick, chan, arg):
		"""scritch - Scritch the kitn."""
		self._emote(chan, "purrs")

	# Alternate spelling
	_cmd_SKRITCH = _cmd_SCRITCH

	def _cmd_SEARCH(self, nick, chan, arg):
		"""search - Does a web search for the supplied query and returns the first result."""
		usage = lambda: self._msg(chan, "Usage: search <query>")

		if not arg:
			return usage()

		query = urlencode({
			'AppId': config['bing']['appid'],
			'Version': '2.2',
			'Market': 'en-US',
			'Query': arg,
			'Sources': 'web',
			'Web.Count': 1,
			'JsonType': 'raw',
		})

		try:
			result = json.load(urllib2.urlopen('http://api.bing.net/json.aspx?%s' % query))
			self._msg(chan, "%(Title)s <%(Url)s>" % (result['SearchResponse']['Web']['Results'][0]))
		except:
			logging.warning("Error while attempting to retrieve results from Bing API:", exc_info=True)
			self._msg(chan, "An error was encountered while trying to complete the search request.")

	def _cmd_SEEN(self, nick, chan, arg):
		"""seen - Get the time that a nick was last seen active."""
		usage = lambda: self._msg(chan, "Usage: seen <nick or glob>")

		if not arg:
			return usage()

		result = db.execute("""
			SELECT nick, timestamp
			FROM seen
			WHERE nick GLOB ?
			ORDER BY timestamp DESC
			LIMIT 1
			""", (arg.lower(),)).fetchone()
		db.rollback()

		if result:
			secs_ago = int(time.time() - result[1])

			if secs_ago < 60:
				timeago = "%d second(s)" % secs_ago
			elif secs_ago < 3600:
				timeago = "%d minute(s)" % (secs_ago // 60)
			elif secs_ago < 86400:
				timeago = "%d hour(s)" % (secs_ago // 3600)
			else:
				timeago = "%d day(s)" % (secs_ago // 86400)

			self._msg(chan, "%s was last seen %s ago." % (result[0], timeago))
		else:
			self._msg(chan, "I haven't seen anyone matching '%s'." % arg)

	@is_action
	def _cmd_SNUGGLE(self, nick, chan, arg):
		"""snuggle - Ask the bot for a snuggle."""
		self._emote(chan, "snuggles %s" % nick.split('!')[0])

	@admin_only
	def _cmd_SRV(self, nick, chan, arg):
		if arg:
			self.client.send(arg)

	def _cmd_TROPE(self, nick, chan, arg):
		"""trope - provides a link to the corresponding TVTropes page."""
		usage = lambda: self._msg(chan, "Usage: trope <keyword>")

		if not arg:
			return usage()

		self._msg(chan, "http://tvtropes.org/pmwiki/pmwiki.php/Main/%s" % arg)

	def _cmd_UTC(self, nick, chan, arg):
		"""utc - Responds with the current time, UTC."""
		self._msg(chan, datetime.datetime.utcnow().replace(microsecond=0).isoformat(' '))

	def _cmd_VOICEMAIL(self, nick, chan, arg):
		"""voicemail - Access messages that were left while a user was offline."""
		usage = lambda: self._msg(chan, "Usage: voicemail [get <quantity> | clear]")

		nick = nick.split('!')[0].lower()

		if chan.startswith('#'):
			return self._msg(chan, "%s: that command must be used in PM." % nick)

		if not arg:
			return usage()
		args = arg.split()

		if args[0] == 'clear':
			if len(args) > 1:
				return usage()
			db.execute("DELETE FROM voicemail WHERE tonick = ?", (nick,))
			db.commit()
			return self._msg(chan, "All pending voicemail for your nick has been cleared.")
		elif args[0] == 'get':
			if len(args) != 2:
				return usage()

			try:
				lines = int(args[1])
			except (TypeError, ValueError):
				return usage()

			if lines < 1:
				return usage()

			lines = min(lines, 10)

			results = db.execute("""SELECT id, fromnick, chan, contents, timestamp
						FROM voicemail
						WHERE tonick = ?
						ORDER BY timestamp
						LIMIT ?""", (nick, lines)).fetchall()
			db.rollback()
			if not results:
				return self._msg(chan, "You have no pending voicemail.")
			else:
				for id, fromnick, channel, contents, timestamp in results:
					self._msg(chan, "%s ago - [%s] <%s> %s" % (
						timeago(int(time.time()) - timestamp), channel, fromnick, contents))
					db.execute("DELETE FROM voicemail WHERE id = ?", (id,))
				db.commit()
		else:
			return usage()

	def _cmd_WHOAMI(self, nick, chan, arg):
		"""whoami - Responds with the full nickstring for the user who runs it."""
		self._msg(chan, nick)

	def _cmd_URLFORGET(self, nick, chan, arg):
		"""urlforget - Remove URLs from memory according to a pattern."""
		usage = lambda: self._msg(chan, "Usage: urlforget <glob>")

		if not arg:
			return usage()

		result = db.execute("DELETE FROM urls WHERE url GLOB ?", (arg,))
		db.commit()
		self._msg(chan, "%d urls matching '%s' forgotten." % (result.rowcount, arg))

	def _cmd_URLSEARCH(self, nick, chan, arg):
		"""urlsearch - Search for a previously seen URL that matches a glob."""
		usage = lambda: self._msg(chan, "Usage: urlsearch <glob>")

		if not arg:
			return usage()

		if arg[0] != '*':
			arg = '*' + arg
		if arg[-1] != '*':
			arg = arg + '*'

		result = db.execute("SELECT url FROM urls WHERE url GLOB ? ORDER BY timestamp DESC LIMIT 1", (arg,)).fetchone()
		db.rollback()
		if result:
			self._msg(chan, result[0])
		else:
			self._msg(chan, "No results found for '%s'." % arg)

	def _cmd_WP(self, nick, chan, arg):
		"""wp - Search wikipedia and return a snippet about the top result."""
		usage = lambda: self._msg(chan, "Usage: wp <query>")

		if not arg:
			return usage()

		wp_query_url = "http://en.wikipedia.org/w/api.php?%s" % urlencode({
				"action": "query",
				"list": "search",
				"srsearch": arg,
				"format": "json",
			})
		try:
			data = urllib2.urlopen(wp_query_url, timeout=5)
			results = json.load(data)['query']['search']
			if results:
				title = results[0]['title']
				url = "http://www.wikipedia.org/wiki/%s" % quote_plus(title.replace(' ', '_'))
				snippet = ''.join(e.string for e in soup(results[0]['snippet'], convertEntities=soup.HTML_ENTITIES) if e)
				self._msg(chan, "%s <%s>" % (snippet, url))
			else:
				self._msg(chan, "No results found for '%s'." % arg)
		except urllib2.URLError:
			self._msg(chan, "Unable to perform Wikipedia search.")

	def _cmd_XKCD(self, nick, chan, arg):
		"""xkcd - Provides a link to the specified XKCD comic, or the most recent if not specified."""
		try:
			comic = int(arg)
			comic_json_uri = "http://xkcd.com/%d/info.0.json" % comic
		except (TypeError, ValueError):
			comic_json_uri = "http://xkcd.com/info.0.json"

		try:
			data = urllib2.urlopen(comic_json_uri, timeout=3)
			xkcd_json = json.load(data)
			self._msg(chan, "xkcd #%d: %s <http://xkcd.com/%d/>" % (
				xkcd_json['num'], xkcd_json['title'], xkcd_json['num'],
			))
		except urllib2.URLError:
			self._msg(chan, "Unable to look up comic #%d." % comic)

	def _cmd_YOUTUBE(self, nick, chan, arg):
		"""youtube - Does a YouTube search for the supplied query and returns the first result."""
		usage = lambda: self._msg(chan, "Usage: youtube <query>")

		if not arg:
			return usage()

		query = urlencode({
			'q': arg,
			'orderBy': 'relevance',
			'alt': 'json',
			'max-results': 1,
		})

		try:
			result = json.load(urllib2.urlopen('http://gdata.youtube.com/feeds/api/videos?%s' % query))
			videos = result['feed']['entry']

			if not videos:
				return self._msg(chan, "No results were found for the search request.")

			video = videos[0]
			self._msg(chan, "%(title)s <%(url)s>" % {
					'title': video['title']['$t'],
					'url': '> <'.join(l['href'] for l in video['link'] if l['rel'] == 'alternate'),
				})
		except:
			logging.warning("Error while attempting to retrieve results from YouTube API:", exc_info=True)
			self._msg(chan, "An error was encountered while trying to complete the search request.")

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
		CREATE TABLE IF NOT EXISTS misc (
			keyword TEXT PRIMARY KEY,
			content TEXT
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS pronouns (
			nick TEXT PRIMARY KEY,
			content TEXT
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS reminders (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER,
			nick TEXT,
			chan TEXT,
			content TEXT
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS factoids (
			keyword TEXT PRIMARY KEY,
			content TEXT,
			nick TEXT,
			timestamp INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS seen (
			nick TEXT PRIMARY KEY,
			chan TEXT,
			timestamp INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS urls (
			url TEXT PRIMARY KEY,
			nick TEXT,
			chan TEXT,
			timestamp INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS replay (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			nick TEXT,
			chan TEXT,
			lines INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS catchphrases (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			nick TEXT,
			chan TEXT,
			phrase TEXT
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS voicemail (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			fromnick TEXT,
			tonick TEXT,
			chan TEXT,
			contents TEXT,
			timestamp INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS karma (
			nick TEXT PRIMARY KEY,
			karma INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS quotes (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			adder TEXT,
			chan TEXT,
			content TEXT,
			timestamp INTEGER
		)""")
	db.execute("""
		CREATE TABLE IF NOT EXISTS daily (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp INTEGER,
			nick TEXT,
			chan TEXT,
			content TEXT
		)""")
	db.commit()

	app = IRCApp()
	clients = {}

	for server, conf in config['servers'].iteritems():
		client = IRCClient(
			KitnHandler,
			host=server,
			port=conf['port'],
			nick=conf['nick'],
			real_name=conf['name'],
		)
		clients[server] = client
		app.addClient(client, autoreconnect=True)

	app.run()
