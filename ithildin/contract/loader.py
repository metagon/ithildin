import logging
import re

from ithildin.exception import ValidationError

from abc import ABC, ABCMeta, abstractmethod
from typing import Optional, Text

from mythril.ethereum.evmcontract import EVMContract
from mythril.ethereum.interface.rpc.client import EthJsonRpc
from mythril.disassembler.disassembly import Disassembly
from mythril.solidity.soliditycontract import SolidityContract
from mythril.support.loader import DynLoader

log = logging.getLogger(__name__)


class ContractLoader(ABC):

    @abstractmethod
    def disassembly(self) -> Optional[Disassembly]:
        pass


class FileLoader(ContractLoader, metaclass=ABCMeta):

    def __init__(self, file_path):
        self._file_path = file_path

    def disassembly(self) -> Disassembly:
        return self.contract().disassembly

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


class JsonRpcLoader(ContractLoader):

    def __init__(self, address: Text, rpc: Optional[Text] = None):
        assert address is not None, "No contract address provided"

        if rpc is None:
            eth_json_rpc = EthJsonRpc()
        else:
            match = re.match(r'(http(s)?:\/\/)?([a-zA-Z0-9\.\-]+)(:([0-9]+))?(\/.+)?', rpc)
            if match:
                host = match.group(3)
                port = match.group(5) if match.group(4) else None
                path = match.group(6) if match.group(6) else ''
                tls = bool(match.group(2))
                log.debug('Parsed RPC provider params: host=%s, port=%s, tls=%r, path=%s', host, port, tls, path)
                eth_json_rpc = EthJsonRpc(host=host + path, port=port, tls=tls)
            else:
                raise ValidationError('Invalid JSON RPC URL provided: "%s"' % rpc)
        self._dyn_loader = DynLoader(eth_json_rpc)
        self._address = address

    @property
    def dyn_loader(self) -> DynLoader:
        return self._dyn_loader

    @property
    def address(self) -> Text:
        return self._address

    def disassembly(self) -> Optional[Disassembly]:
        return self.dyn_loader.dynld(self.address)
