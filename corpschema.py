from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class CorpSchema(object):
    def __init__(self, path):
        engine = create_engine('sqlite:///%s' % path)
        Base.metadata.create_all(engine)
        self.session = sessionmaker(bind=engine)()

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

