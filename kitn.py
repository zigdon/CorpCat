#!/usr/bin/env python
import functools
import json
import logging
import re
import time
import traceback
import urllib2

from oyoyo.client import IRCApp, IRCClient
from oyoyo.cmdhandler import DefaultCommandHandler
from oyoyo import helpers
import yaml

logging.basicConfig(level=logging.INFO)
config = None

class KitnHandler(DefaultCommandHandler):

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
		self._parse_cmd(nick, chan, msg)

	def notice(self, nick, chan, msg):
		logging.info("[notice] %s -> %s: %s" % (nick, chan, msg))
		self._parse_cmd(nick, chan, msg)

	def _parse_cmd(self, nick, chan, msg):	
		# Match either "<nick>: " or the sigil character
		COMMAND_RE = re.compile(r"^(?:%s:\s+|%s)(\w+)(?:\s+(.*))?$" % (
			self.client.nick,
			re.escape(config['sigil']),
		))

		# See if this is a command we recognize
		m = COMMAND_RE.match(msg)
		if m:
			cmd = m.group(1)
			arg = m.group(2)
			cmd_func = '_cmd_%s' % cmd.upper()
			if hasattr(self, cmd_func):
				try:
					getattr(self, cmd_func)(nick, chan, arg)
				except:
					logging.error("Exception while attempting to process command '%s'" % cmd, exc_info=True)
			else:
				logging.warning('Unknown command "%s".' % cmd)

	def _msg(self, chan, msg):
		helpers.msg(self.client, chan, msg)

	# COMMANDS
	def _cmd_ABOUT(self, nick, chan, arg):
		"""about - Provides basic information about this bot."""
		self._msg(chan,
			"I'm an IRC bot. My owner is Aaeriele and her owner is DaBigCheez.",
		)

	def _cmd_XKCD(self, nick, chan, arg):
		"""xkcd - Provides a link to the specified XKCD comic, or the most recent if not specified."""
		try:
			comic = int(arg)
			comic_json_uri = "http://xkcd.com/%d/info.0.json" % comic
		except TypeError, ValueError:
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
