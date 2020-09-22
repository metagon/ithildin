import logging
from abc import ABC, abstractmethod

from mythril.ethereum.evmcontract import EVMContract
from mythril.solidity.soliditycontract import SolidityContract

log = logging.getLogger(__name__)


class ContractLoader(ABC):

    @abstractmethod
    def contract(self) -> EVMContract:
        pass


class FileLoader(ContractLoader, ABC):

    def __init__(self, file_path):
        self._file_path = file_path

    @abstractmethod
    def contract(self) -> EVMContract:
        pass


class BinaryLoader(FileLoader):

    def contract(self) -> EVMContract:
        try:
            with open(self._file_path) as contract_bin:
                bytecode = contract_bin.read()
        except IOError as e:
            log.error('Failed to open contract binary file: %s', e)
            raise IOError('Failed to open contract binary file')
        return EVMContract(code=bytecode, creation_code=bytecode)


class SolidityLoader(FileLoader):

    def contract(self) -> EVMContract:
        return SolidityContract(self._file_path)
