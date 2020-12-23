import logging
import re

from ithildin.exception import ValidationError

from abc import ABC, abstractmethod
from typing import Optional, Text

from mythril.ethereum.evmcontract import EVMContract
from mythril.ethereum.interface.rpc.client import EthJsonRpc, GETH_DEFAULT_RPC_PORT
from mythril.solidity.soliditycontract import SolidityContract
from mythril.support.loader import DynLoader

log = logging.getLogger(__name__)


class FileLoader(ABC):

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
        return EVMContract(creation_code=bytecode)


class SolidityLoader(FileLoader):

    def __init__(self, file_path, solc: Optional[Text] = 'solc'):
        super().__init__(file_path)
        self._solc = solc

    def contract(self) -> EVMContract:
        return SolidityContract(self._file_path, solc_binary=self._solc)


class Web3Loader:

    def __init__(self, address: Text, web3: Optional[Text] = None):
        assert address is not None, "No contract address provided"

        if web3 is None:
            rpc = EthJsonRpc()
        else:
            match = re.match(r'(http(s)?:\/\/)?([a-zA-Z0-9\.\-]+)(:([0-9]+))?', web3)
            if match:
                host = match.group(3)
                port = match.group(5) if match.group(4) else GETH_DEFAULT_RPC_PORT
                tls = bool(match.group(2))
                log.debug('Parsed Web3 provider params: host=%s, port=%s, tls=%r', host, port, tls)
                rpc = EthJsonRpc(host, port, tls)
            else:
                raise ValidationError('Invalid Web3 URL provided: "%s"' % web3)
        self._dyn_loader = DynLoader(rpc)
        self._address = address

    @property
    def dyn_loader(self) -> DynLoader:
        return self._dyn_loader

    @property
    def address(self) -> Text:
        return self._address
