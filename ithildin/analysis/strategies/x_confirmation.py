import logging
from typing import Optional

from ithildin.analysis.base import AnalysisStrategy
from ithildin.model.report import Result, ReportItem

log = logging.getLogger(__name__)

PATTERN_NAME = 'X_CONFIRMATION'
REPORT_TITLE = 'X-Confirmation (Block Count)'
REPORT_DESCRIPTION = ('This pattern protects functions from being executed unless a condition related to the '
                      'current block number is met. For example one might want to wait for a certain number '
                      'of blocks to have passed before a transaction is marked as valid or confirmed.')


class XConfirmation(AnalysisStrategy):

    OPCODE_FLAGS = {
        'NUMBER': 0b001,
        'SLOAD':  0b010,
        'EQ':     0b100,
        'LT':     0b100,
        'GT':     0b100
    }

    OPCODE_FLAG_TARGET = 0b111

    def _analyze(self) -> Optional[ReportItem]:
        # NOTE: This can currently detect comparisons that happen within a require and not if an extra function call occurs.
        # TODO: REVERT opcode needs to also be checked in following nodes, not just one level deep.
        restricted_functions = set()
        for node_uid, node in self.laser.nodes.items():
            opcode_accum = 0
            for state in node.states:
                opcode_accum |= self.OPCODE_FLAGS.get(state.instruction['opcode'], 0)
                if opcode_accum == self.OPCODE_FLAG_TARGET and self._opcode_follows(node_uid, 'REVERT'):
                    log.debug('Function \'%s\' is restricted by block count', node.function_name)
                    restricted_functions.add(node.function_name)
                    break
        if len(restricted_functions) == 0:
            return None
        report_item = ReportItem(REPORT_TITLE, REPORT_DESCRIPTION, PATTERN_NAME)
        for function in restricted_functions:
            report_item.add_result(Result(function))
        return report_item
