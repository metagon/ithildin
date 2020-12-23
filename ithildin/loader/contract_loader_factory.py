from abc import ABC, abstractmethod
from enum import Enum
from typing import Set, Text, Union

from ithildin.loader.contract_loader import FileLoader, BinaryLoader, SolidityLoader, Web3Loader


class LoaderFactoryType(Enum):
    BINARY = 1
    SOLIDITY = 2
    WEB3 = 3


class ContractLoaderFactory(ABC):

    def __init__(self, **options) -> None:
        missing_options = self._required_options - options.keys()
        if len(missing_options) > 0:
            raise AttributeError('Missing option(s): %s' % str(missing_options))
        self._options = options

    @property
    @abstractmethod
    def _required_options(self) -> Set[Text]:
        pass

    @abstractmethod
    def create(self) -> Union[FileLoader, Web3Loader]:
        pass


class BinaryLoaderFactory(ContractLoaderFactory):

    def create(self) -> FileLoader:
        return BinaryLoader(self._options.get('path'))

    @property
    def _required_options(self) -> Set[Text]:
        return {'path'}


class SolidityLoaderFactory(ContractLoaderFactory):

    def create(self) -> FileLoader:
        return SolidityLoader(self._options.get('path'), solc=self._options.get('solc'))

    @property
    def _required_options(self) -> Set[Text]:
        return {'path', 'solc'}


class Web3LoaderFactory(ContractLoaderFactory):

    def create(self) -> Web3Loader:
        return Web3Loader(self._options.get('address'), self._options.get('rpc'))

    @property
    def _required_options(self) -> Set[Text]:
        return {'address', 'rpc'}


def get_factory(loader_type: LoaderFactoryType, **options) -> ContractLoaderFactory:
    switcher = {
        LoaderFactoryType.BINARY:   BinaryLoaderFactory,
        LoaderFactoryType.SOLIDITY: SolidityLoaderFactory,
        LoaderFactoryType.WEB3:     Web3LoaderFactory
    }
    if loader_type not in switcher:
        raise NotImplementedError('This factory has not been implemented yet')
    return switcher.get(loader_type)(**options)
