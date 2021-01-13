from typing import Optional, Text, Union

from .verification_db import VerificationDB, Flag, Function, FlaggedFunction, Strategy


class FlaggedFunctionRepository:

    def __init__(self):
        self.db = VerificationDB()

    def get(self, function: Function, strategy: Union[Strategy, Text]) -> Optional[FlaggedFunction]:
        assert strategy is not None, 'No strategy instance provided'
        assert function is not None and function.id is not None, 'No function instance provided'

        function_filter = FlaggedFunction.function_id == function.id
        if isinstance(strategy, Strategy):
            assert strategy.id is not None, 'ID attribute missing from strategy'
            strategy_filter = Strategy.id == strategy.id
        else:
            strategy_filter = Strategy.name == strategy

        return self.db.session.query(FlaggedFunction).filter(function_filter & strategy_filter).first()

    def get_flag(self, function: Function, strategy: Union[Strategy, Text]) -> Optional[Flag]:
        entity = self.get(function, strategy)
        return entity.flag if entity is not None else None

    def set_flag(self, function: Function, strategy: Union[Strategy, Text], flag: Flag) -> FlaggedFunction:
        if isinstance(strategy, Text):
            strategy = self.db.session.query(Strategy).filter(Strategy.name == strategy).first()
        assert flag is not None, 'No flag provided'
        assert function is not None and function.id is not None, 'No function instance provided'
        assert strategy is not None and strategy.id is not None, 'Invalid strategy instance'

        entity = self.get(function, strategy)
        if entity is None:
            entity = FlaggedFunction(strategy_id=strategy.id, function_id=function.id, flag=flag)
            self.db.session.add(entity)
            self.db.session.commit()
        else:
            entity.flag = flag
            self.db.session.commit()
        return entity
