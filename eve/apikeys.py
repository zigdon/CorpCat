import functools
import logging

from kitnirc.modular import Module
from kitnirc.user import User

_log = logging.getLogger(__name__)

def admin_only(f):
    @functools.wraps(f)
    def wrapper(self, client, user, chan, arg):
        if any(user == admin for admin, level in self.controller.config.items('admin')):
            return f(self, client, user, chan, arg)
        else:
            _log.info("%s not allowed to run %s" % (nick, f))

    return wrapper


class EveApiKeys(Module):
    @Module.handle("PRIVMSG")
    def cmd_dispatch(self, client, user, channel, msg):
        words = msg.split()
        user = User(user)

        cmd_func = '_cmd_%s' % words[0].upper()
        if hasattr(self, cmd_func):
            getattr(self, cmd_func)(client, user, channel, words[1:])

    @admin_only
    def _cmd_QUIT(self, client, user, channel, arg):
        _log.info('Quitting at the request of %s' % user.nick)
        client.disconnect()

module = EveApiKeys
