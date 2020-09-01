from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Set, Text

from mythril.ethereum.evmcontract import EVMContract
from sc3a.loader.contract_loader import ContractLoader, BinaryLoader, SolidityLoader


class LoaderFactoryType(Enum):
    BINARY = 1
    SOLIDITY = 2


class ContractLoaderFactory(ABC):

    def __init__(self, **options) -> None:
        missing_options = self._required_options - options.keys()
        if len(missing_options) > 0:
            raise KeyError('Missing option(s): %s' % str(missing_options))
        self._options = options

    @property
    @abstractmethod
    def _required_options(self) -> Set:
        pass

    @abstractmethod
    def create(self) -> ContractLoader:
        pass


class BinaryLoaderFactory(ContractLoaderFactory):

    def create(self) -> ContractLoader:
        return BinaryLoader(self._options.get('path'))

    @property
    def _required_options(self) -> Set:
        return {'path'}


class SolidityLoaderFactory(ContractLoaderFactory):

    def create(self) -> ContractLoader:
        return SolidityLoader(self._options.get('path'))

    @property
    def _required_options(self) -> Set:
        return {'path'}


def get_factory(type: LoaderFactoryType, **options) -> ContractLoaderFactory:
    switcher = {
        LoaderFactoryType.BINARY:   BinaryLoaderFactory(**options),
        LoaderFactoryType.SOLIDITY: SolidityLoaderFactory(**options)
    }
    if type not in switcher:
        raise NotImplementedError('This factory has not been implemented yet')
    return switcher.get(type)
