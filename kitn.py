#!/usr/bin/env python
import datetime
import functools
import json
import logging
import random
import re
import sqlite3
import threading
import time
from urllib import urlencode
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
		if nick == 'Aaeriele!aiiane@hide-F3E0B19.aiiane.com':
			return f(self, nick, chan, arg)
		else:
			return self._msg(chan, "You are not allowed to run that command.")
	return wrapper

def is_action(f):
	f.is_action = True
	return f


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

		# Commands - match either "<nick>: " or the sigil character as a prefix
		self.COMMAND_RE = re.compile(r"^(?:%s:\s+|%s)(\w+)(?:\s+(.*))?$" % (
			self.client.nick,
			re.escape(config['sigil']),
		))

		# Actions - match "\x01ACTION <something>s <nick>\x01"
		self.ACTION_RE = re.compile("\x01ACTION (\\w+)s %s\x01" % self.client.nick)

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
			self._msg(chan, "%s: %s" % (nick, content))
			db.execute("DELETE FROM reminders WHERE id = ?", (r_id,))
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

	def whoisbot(self, nick, chan, user, msg):
		"""Add a bot to the known bots list based on WHOIS."""
		logging.info("Adding '%s' to the known bots list." % user)
		self.KNOWN_BOTS.add(user)

	def whoisoperator(self, nick, chan, user, msg):
		"""Check and see if this is a network service, if so, add it to known bots."""
		if msg == 'is a Network Service':
			logging.info("Adding '%s' to the known bots list." % user)
			self.KNOWN_BOTS.add(user)

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
			helpers.join(client, channel)

		# If server-specific user modes are specified, set them.
		modes = s.get('modes')
		if modes:
			client.send('MODE', s['nick'], modes)

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

	def privmsg(self, nick, chan, msg):
		self._seen(nick, chan)
		if self._is_nick_ignored(nick):
			logging.debug("[ignored message] %s -> %s" % (nick, chan))
		else:
			logging.debug("[message] %s -> %s: %s" % (nick, chan, msg))
			self._parse_line(nick, chan, msg)

	def notice(self, nick, chan, msg):
		self._seen(nick, chan)
		if self._is_nick_ignored(nick):
			logging.debug("[ignored notice] %s -> %s" % (nick, chan))
		else:
			logging.debug("[notice] %s -> %s: %s" % (nick, chan, msg))
			self._parse_line(nick, chan, msg)

	def _seen(self, nick, chan):
		"""Record new information for when this nick was seen."""
		db.execute("INSERT OR REPLACE INTO seen (nick, chan, timestamp) VALUES (?,?,?)", (
			nick.split('!')[0].lower(), chan, time.time(),
		))
		db.commit()

	def _url(self, url, nick, chan):
		"""Record when this URL was seen."""
		db.execute("INSERT OR IGNORE INTO urls (url, nick, chan, timestamp) VALUES (?,?,?,?)", (
			url, nick.split('!')[0], chan, time.time(),
		))
		db.commit()

	def _msg(self, chan, msg):
		helpers.msg(self.client, chan, msg)

	def _ctcp(self, chan, msg):
		self._msg(chan, "\x01%s\x01" % msg)

	def _emote(self, chan, msg):
		self._ctcp(chan, "ACTION %s" % msg)

	def _parse_line(self, nick, chan, msg):
		"""Parse an incoming line of chat for commands and URLs."""

		# PMs to us should generally be replied to the other party, not ourself
		if chan == self.client.nick:
			chan = nick.split('!')[0]

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

		# See if there's a URL we should recognize
		m = self.URL_RE.search(msg)
		if m:
			logging.info("[url] %s -> %s: %s" % (nick, chan, m.group()))
			self._url(m.group(), nick, chan)
			self._url_announce(chan, m.group())
			return

	def _url_announce(self, chan, url):
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

					if found_len < 0.6 * total_len:
						logging.info("Reporting title '%s' (found: %s, total: %s)" % (
							condensed_title, found_len, total_len))
						report_components.append('"%s"' % condensed_title)
					else:
						logging.info("Not reporting title '%s' (found: %s, total: %s)" % (
							condensed_title, found_len, total_len))


			# Only announce the url if something caught our attention
			if report_components:
				self._msg(chan, "Link points to %s" % ' - '.join(report_components))

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
			hour, minute = int(time_val[0]), 0
		else:
			hour, minute = int(time_val[0]), int(time_val[1])

		if am_pm in ('pm', 'PM') and hour < 12:
			hour += 12
		elif am_pm in ('am', 'AM') and hour == 12:
			hour = 0

		if hour > 23 or minute > 59:
			return self._msg(chan, "%d:%d is not a valid time." % (hour, minute))

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

		m = re.match(r"(\d+)(\D+)$", args[0])
		if m:
			args[0:1] = [m.group(1), m.group(2)]

		# After we've expanded any potential abbreviation, we expect 3 args
		if len(args) < 3:
			return usage()

		try:
			time_amount = int(args[0])
		except (ValueError, TypeError):
			return usage()

		if not time_amount > 0:
			return self._msg(chan, "Reminders may not be set in the past.")

		if args[1] not in time_units:
			return self._msg(chan, "'%s' is not a valid time unit. Valid options: %s" % (
				args[1], ', '.join(sorted(time_units, key=lambda x: (time_units[x], x))),
			))

		nick = nick.split('!')[0]
		timestamp = time.time() + (time_amount * time_units[args[1]])
		content = ' '.join(args[2:])
		result = db.execute("INSERT INTO reminders (nick, chan, timestamp, content) VALUES (?,?,?,?)",
			(nick, chan, timestamp, content))
		r_id = result.lastrowid
		db.commit()

		logging.info("Added reminder #%s at %s" % (r_id, timestamp))
		self._msg(chan, "%s: reminder #%s added for %s PST." % (nick, r_id,
			datetime.datetime.fromtimestamp(timestamp).strftime('%x %X')))

	@admin_only
	def _cmd_JOIN(self, nick, chan, arg):
		"""part - Make the bot join the specified channel."""
		usage = lambda: self._msg(chan, "Usage: join <channel>")

		if not arg:
			return usage()

		self._msg(chan, "Joining channel %s." % arg)
		helpers.join(self.client, arg)

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

	@is_action
	def _cmd_SNUGGLE(self, nick, chan, arg):
		"""snuggle - Ask the bot for a snuggle."""
		self._emote(chan, "snuggles %s" % nick.split('!')[0])

	@admin_only
	def _cmd_SRV(self, nick, chan, arg):
		if arg:
			self.client.send(arg)

	def _cmd_UTC(self, nick, chan, arg):
		"""utc - Responds with the current time, UTC."""
		self._msg(chan, datetime.datetime.utcnow().replace(microsecond=0).isoformat(' '))

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

		result = db.execute("SELECT url FROM urls WHERE url GLOB ? ORDER BY timestamp DESC LIMIT 1", (arg,)).fetchone()
		db.rollback()
		if result:
			self._msg(chan, result[0])
		else:
			self._msg(chan, "No results found for '%s'." % arg)

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
