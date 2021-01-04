import logging
import time
from typing import Optional, Text, Union

from ithildin.analysis.loader import StrategyLoader
from ithildin.contract.loader import FileLoader, JsonRpcLoader
from ithildin.report.analysis import Report

from mythril.laser.ethereum import svm
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.support.loader import DynLoader


log = logging.getLogger(__name__)


class LaserWrapper:

    def __init__(self, strategy_loader: Optional[StrategyLoader] = StrategyLoader()):
        self.strategy_loader = strategy_loader

    def execute(self,
                timeout: Optional[float] = 60,
                max_depth: Optional[int] = 128,
                creation_code: Optional[Text] = None,
                target_address: Optional[Text] = None,
                dyn_loader: Optional[DynLoader] = None,
                contract_loader: Optional[Union[FileLoader, JsonRpcLoader]] = None) -> Report:
        if contract_loader is not None:
            if isinstance(contract_loader, FileLoader):
                creation_code = contract_loader.contract().creation_disassembly.bytecode
            elif isinstance(contract_loader, JsonRpcLoader):
                target_address = contract_loader.address
                dyn_loader = contract_loader.dyn_loader
            else:
                raise ValueError('Invalid type for contract_loader parameter')

        world_state = None
        if creation_code is not None and target_address is None:
            log.info('Running symbolic execution in creation mode...')
            laser = svm.LaserEVM(execution_timeout=timeout,
                                 max_depth=max_depth,
                                 requires_statespace=False)
        elif creation_code is None and target_address is not None:
            assert dyn_loader is not None, "Dynamic Loader has not been provided"
            log.info('Running symbolic execution in existing mode...')
            laser = svm.LaserEVM(dynamic_loader=dyn_loader,
                                 execution_timeout=timeout,
                                 max_depth=max_depth,
                                 requires_statespace=False)
            world_state = WorldState()
            world_state.accounts_exist_or_load(target_address, dyn_loader)
        else:
            raise ValueError('Either creation_code or target_address needs to be provided')

        for strategy in self.strategy_loader.get_strategies():
            for hook in strategy.pre_hooks:
                laser.register_hooks('pre', {hook: [strategy.execute]})
            for hook in strategy.post_hooks:
                laser.register_hooks('post', {hook: [strategy.execute]})

        # Run symbolic execution
        start_time = time.time()
        laser.sym_exec(creation_code=creation_code,
                       contract_name='Unknown',
                       world_state=world_state,
                       target_address=int(target_address, 16) if target_address else None)
        log.info('Symbolic execution finished in %.2f seconds.', time.time() - start_time)

        report = Report(start_time=start_time, end_time=time.time())
        report.contract_code = creation_code
        report.contract_address = target_address
        for strategy in self.strategy_loader.get_strategies():
            report.add_report(strategy.generate_report())
        self._post_process_report(report, target_address, dyn_loader)
        return report

    def _post_process_report(self, report: Report, target_address: Text, dyn_loader: DynLoader) -> None:
        if dyn_loader is None or target_address is None:
            return
        for report_item in report.reports:
            for result in report_item.results:
                if result.storage_address is not None:
                    result.storage_content = dyn_loader.read_storage(target_address, result.storage_address)
