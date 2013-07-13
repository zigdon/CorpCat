import functools
import logging

from kitnirc.modular import Module
from kitnirc.user import User
from kitnirc.contrib.admintools import AdminModule

from corpschema import CorpSchema

_log = logging.getLogger(__name__)

def admin_only(f):
    @functools.wraps(f)
    def wrapper(self, client, user, chan, arg):
        if AdminModule.is_admin(user):
            return f(self, client, user, chan, arg)
        else:
            _log.info("%s not allowed to run %s" % (nick, f))

    return wrapper

class EveApiKeys(Module):
    schema = None

    def start(self, reloading=False):
        super(EveApiKeys, self).start(reloading)

        self.schema = CorpSchema(self.controller.config.get('database', 'path'))

    def stop(self, reloading=False):
        super(EveApiKeys, self).stop(reloading)

        self.schema = None

    @Module.handle("WELCOME")
    def autojoin(self, client, *params):
        channels = self.controller.config.items('channels')
        _log.info('Autojoining %d channels.' % len(channels))

        for channel, _ in channels:
            client.join('#' + channel)

    @Module.handle("PRIVMSG")
    def cmd_dispatch(self, client, user, channel, msg):
        words = msg.split()
        user = User(user)

        if not isinstance(channel, User):
            if words[0] == '%s:' % client.user.nick:
                words = words[1:]
                pm = False
            else:
                return
        else:
            pm = True


        cmd_func = '_cmd_%s' % words[0].upper()
        if hasattr(self, cmd_func):
            msg = getattr(self, cmd_func)(client, user, channel, words[1:])

            if msg:
                if pm:
                    client.msg(user, msg)
                else:
                    msg = '%s: %s' % (user.nick, msg)
                    client.msg(channel, msg)



module = EveApiKeys
