#!/usr/bin/env python
import json
import logging
import random
import re
import sqlite3
import string
import threading
import time
import urllib2
from urlparse import urlparse

from BeautifulSoup import BeautifulSoup as soup
from oyoyo.client import IRCApp, IRCClient
from oyoyo.cmdhandler import DefaultCommandHandler
from oyoyo import helpers
import yaml

logging.basicConfig(level=logging.INFO)
config = None
db = None

class KitnHandler(DefaultCommandHandler):

	def __init__(self, *args, **kwargs):
		super(KitnHandler, self).__init__(*args, **kwargs)

		# Commands - match either "<nick>: " or the sigil character as a prefix
		self.COMMAND_RE = re.compile(r"^(?:%s:\s+|%s)(\w+)(?:\s+(.*))?$" % (
			self.client.nick,
			re.escape(config['sigil']),
		))

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
		reminders = db.execute("SELECT id, nick, chan, content FROM reminders WHERE timestamp < ?", (time.time(),)).fetchall()
		for r_id, nick, chan, content in reminders:
			logging.info("Resolving reminder #%s" % r_id)
			self._msg(chan, "%s: %s" % (nick, content))
			db.execute("DELETE FROM reminders WHERE id = ?", (r_id,))
		db.commit()

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

	def privmsg(self, nick, chan, msg):
		logging.info("[message] %s -> %s: %s" % (nick, chan, msg))
		self._parse_line(nick, chan, msg)

	def notice(self, nick, chan, msg):
		logging.info("[notice] %s -> %s: %s" % (nick, chan, msg))
		self._parse_line(nick, chan, msg)

	def _msg(self, chan, msg):
		helpers.msg(self.client, chan, msg)

	def _parse_line(self, nick, chan, msg):	
		"""Parse an incoming line of chat for commands and URLs."""

		# PMs to us should generally be replied to the other party, not ourself
		if chan == self.client.nick:
			chan = nick.split('!')[0]

		# See if this is a command we recognize
		m = self.COMMAND_RE.match(msg)
		if m:
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

		# See if there's a URL we should recognize
		m = self.URL_RE.search(msg)
		if m:
			logging.info("Found url in %s: %s" % (chan, m.group()))
			self._url_announce(chan, m.group())

	def _url_announce(self, chan, url):
		"""Announce the info for a detected URL in the channel it was detected in."""
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
				parsed = soup(result.read())
				title_tag = parsed.find('title')
				if title_tag:
					title_segments = re.split(r'[^a-z]+', title_tag.string[:100].lower())
					title_segment_letters = (
							''.join(L for L in segment.lower() if L in string.lowercase)
							for segment in title_segments
						)
					title_segment_letters = [s for s in title_segment_letters if s]

					f = final_url.lower()
					title_segments_found = [s for s in title_segment_letters if s in f]

					found_len = len(''.join(title_segments_found))
					total_len = len(''.join(title_segment_letters))

					if found_len < 0.6 * total_len:
						logging.info("Reporting title '%s' (found: %s, total: %s)" % (
							title_tag.string[:100], found_len, total_len))
						report_components.append('"%s"' % title_tag.string[:100])
					else:
						logging.info("Not reporting title '%s' (found: %s, total: %s)" % (
							title_tag.string[:100], found_len, total_len))
						

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
			"I'm an IRC bot. My owner is Aaeriele and her owner is DaBigCheez.",
		)

	def _cmd_CHOOSE(self, nick, chan, arg):
		"""choose - Given a set of items, pick one randomly."""
		usage = lambda: self._msg(chan, "Usage: choose <item> <item> ...")

		items = arg.split()
		if not items:
			return usage()
		else:
			self._msg(chan, "%s: %s" % (nick.split('!')[0], random.choice(items)))

	def _cmd_IN(self, nick, chan, arg):
		"""in - Set up a reminder that occurs after a specified period of time."""
		usage = lambda: self._msg(chan, "Usage: in <amount> <time unit> <text>")

		args = arg.split()
		if len(args) < 3:
			return usage()

		# Attempt to parse the time specifier
		time_units = {
			's': 1, 'sec': 1, 'secs': 1, 'second': 1, 'seconds': 1,
			'm': 60, 'min': 60, 'mins': 60, 'minute': 60, 'minutes': 60,
			'h': 3600, 'hr': 3600, 'hrs': 3600, 'hour': 3600, 'hours': 3600,
			'd': 86400, 'day': 86400, 'days': 86400,
			'w': 604800, 'wk': 604800, 'wks': 604800, 'week': 604800, 'weeks': 604800,
		}
		
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
		self._msg(chan, "%s: reminder #%s added." % (nick, r_id))

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


if __name__ == '__main__':

	with open('config.yaml') as f:
		config = yaml.safe_load(f)

	db = sqlite3.connect(config['database']['path'])
	db.execute("""
		CREATE TABLE IF NOT EXISTS pronouns (
			nick TEXT PRIMARY KEY,
			content TEXT
		)""")
	db.commit()
	db.execute("""
		CREATE TABLE IF NOT EXISTS reminders (
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
		app.addClient(client)

	app.run()
