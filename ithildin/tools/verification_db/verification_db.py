# pylint: disable=maybe-no-member

import enum

from sqlalchemy import create_engine, Column, Enum, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

from . import verifications_db_path
from ithildin.analysis.loader import STRATEGIES
from ithildin.support.singleton import Singleton

engine = create_engine(f'sqlite:///{verifications_db_path}')
Session = sessionmaker(bind=engine)
Base = declarative_base()


class Contract(Base):
    __tablename__ = 'contracts'

    id = Column(Integer, primary_key=True)
    address = Column(String(42), unique=True, index=True)
    compiler_version = Column(String(10))
    functions = relationship('Function')

    def __repr__(self):
        return (
            '<Contract '
            'id={0.id} '
            'address={0.address} '
            'functions={0.functions}'
            '>'
        ).format(self)


class Function(Base):
    __tablename__ = 'functions'

    id = Column(Integer, primary_key=True)
    contract_id = Column(Integer, ForeignKey('contracts.id'), nullable=False)
    signature = Column(String(255), nullable=False, index=True)
    signature_hash = Column(String(10), nullable=False, index=True)
    strategies = relationship('FlaggedFunction', back_populates='function')

    def __repr__(self):
        return (
            '<Function '
            'id={0.id} '
            'contract_id={0.contract_id} '
            'signature={0.signature} '
            'signature_hash={0.signature_hash} '
            'strategies={0.strategies}'
            '>'
        ).format(self)


class Strategy(Base):
    __tablename__ = 'strategies'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, index=True)
    functions = relationship('FlaggedFunction', back_populates='strategy')

    def __repr__(self):
        return (
            '<Strategy '
            'id={0.id} '
            'name={0.name} '
            'functions={0.functions}'
            '>'
        ).format(self)


class Flag(enum.Enum):
    VALID = 'VALID'
    INVALID = 'INVALID'
    UNKNOWN = 'UNKNOWN'


class FlaggedFunction(Base):
    __tablename__ = 'flagged_functions'

    function_id = Column(Integer, ForeignKey('functions.id'), primary_key=True)
    strategy_id = Column(Integer, ForeignKey('strategies.id'), primary_key=True)
    flag = Column(Enum(Flag))
    function = relationship('Function', back_populates='strategies')
    strategy = relationship('Strategy', back_populates='functions')

    def __repr__(self):
        return (
            '<FlaggedFunction '
            'function_id={0.function_id} '
            'strategy_id={0.strategy_id} '
            'strategy_id={0.strategy_id} '
            'flag={0.flag} '
            'function={0.function} '
            'strategy={0.strategy}'
            '>'
        ).format(self)


Base.metadata.create_all(engine)


class VerificationDB(metaclass=Singleton):

    def __init__(self) -> None:
        self._session = Session()
        self._init_db()

    def _init_db(self) -> None:
        for strategy_name in STRATEGIES.keys():
            if self.session.query(Strategy).filter(Strategy.name == strategy_name).first() is None:
                self.session.add(Strategy(name=strategy_name))
        self.session.commit()

    @property
    def session(self):
        return self._session
