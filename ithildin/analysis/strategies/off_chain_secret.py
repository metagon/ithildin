import logging

from ithildin.analysis.base import AnalysisStrategy
from ithildin.model.report import ReportItem, Result

log = logging.getLogger(__name__)


PATTERN_NAME = 'OFF_CHAIN_SECRET'
REPORT_TITLE = 'Off-Chain Secret Enabled Authentication'
REPORT_DESCRIPTION = ('This pattern aims at providing authentication when the account is not known in advance. '
                      'A secret is fixed off-chain and hashed, and the hash gets submitted to the contract. '
                      'Later, the holder of the secret can submit it to the contract, the contract checks '
                      'the secret\'s hash against the stored one, and if they match the protected logic gets executed.')


class OffChainSecret(AnalysisStrategy):

    ENCODE_PACKED_SEQUENCE = [
        {'opcode': 'PUSH1', 'argument': '0x20'},
        {'opcode': 'ADD'},
        {'opcode': 'SHA3'}
    ]

    def _analyze(self):
        function_names = set()
        for node_uid, node in self.laser.nodes.items():
            match_indexes = self._lookup_sequence(node.states, self.ENCODE_PACKED_SEQUENCE)
            if len(match_indexes) > 0 and self._opcode_follows(node_uid, 'REVERT'):
                log.debug('Function \'%s\' is restricted by off-chain secret', node.function_name)
                function_names.add(node.function_name)
        report_item = ReportItem(REPORT_TITLE, REPORT_DESCRIPTION, PATTERN_NAME)
        for result in function_names:
            report_item.add_result(Result(result))
        return report_item if len(report_item.results) > 0 else None
