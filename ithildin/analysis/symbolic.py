import logging
import time
from typing import Optional, Text, Union

from ithildin.analysis.loader import StrategyLoader
from ithildin.contract.loader import FileLoader, JsonRpcLoader
from ithildin.report.analysis import Report

from mythril.laser.ethereum import svm
from mythril.laser.ethereum.state.world_state import WorldState
from mythril.laser.ethereum.strategy.extensions.bounded_loops import BoundedLoopsStrategy
from mythril.laser.plugin.loader import LaserPluginLoader
from mythril.support.loader import DynLoader

from mythril.laser.plugin.plugins import (
    MutationPrunerBuilder,
    DependencyPrunerBuilder,
    CoveragePluginBuilder,
    CallDepthLimitBuilder,
    InstructionProfilerBuilder,
)

log = logging.getLogger(__name__)


class LaserWrapper:

    def __init__(self, strategy_loader: Optional[StrategyLoader] = StrategyLoader()):
        self.strategy_loader = strategy_loader

    def execute(self,
                timeout: Optional[float] = 60,
                max_depth: Optional[int] = 128,
                call_depth_limit: Optional[int] = 3,
                bounded_loops_limit: Optional[int] = 3,
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

        # Load laser plugins
        laser.extend_strategy(BoundedLoopsStrategy, bounded_loops_limit)
        plugin_loader = LaserPluginLoader()
        plugin_loader.load(CoveragePluginBuilder())
        plugin_loader.load(MutationPrunerBuilder())
        plugin_loader.load(CallDepthLimitBuilder())
        plugin_loader.load(InstructionProfilerBuilder())
        plugin_loader.load(DependencyPrunerBuilder())
        plugin_loader.add_args("call-depth-limit", call_depth_limit=call_depth_limit)
        plugin_loader.instrument_virtual_machine(laser, None)

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
        for result in [result for report_item in report.reports for result in report_item.results]:
            for attr_name, attr_value in [(k, v) for k, v in result.attributes.items() if k.startswith('_index')]:
                attr_name_pretty = ' '.join(map(lambda s: s.capitalize(), attr_name.split('_')[2:]))
                result.add_attribute(f'{attr_name_pretty} Storage Index', attr_value)
                if dyn_loader:
                    result.add_attribute(attr_name_pretty, dyn_loader.read_storage(target_address, attr_value))
                result.remove_attribute(attr_name)
