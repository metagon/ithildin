from typing import Optional, Text

from .verification_db import VerificationDB, Contract, Function


class FunctionRepository:

    def __init__(self):
        self.db = VerificationDB()

    def get(self, contract: Contract, signature: Optional[Text] = None, signature_hash: Optional[Text] = None) -> Function:
        """
        Retrieve Function entity from the database.

        Parameters
        ----------
        contract: Contract
            Contract instance containing its unique ID.
        signature: Optional[Text]
            The function's signature.
        signature_hash: Optional[Text]
            The function's signature hash.

        Returns
        -------
        Populated Function instance if present, None otherwise.
        """
        assert contract is not None and contract.id is not None, 'No contract id provided'
        assert signature is not None or signature_hash is not None, 'Either the signature or its hash need to be provided'

        contract_filter = Function.contract_id == contract.id
        if signature is not None and signature_hash is None:
            query_filter = Function.signature == signature
        elif signature is None and signature_hash is not None:
            query_filter = Function.signature_hash == signature_hash
        else:
            query_filter = Function.signature == signature & Function.signature_hash == signature_hash

        return self.db.session.query(Function).filter(contract_filter & query_filter).first()

    def save(self, contract: Contract, signature: Text, signature_hash: Text) -> Function:
        """
        Saves function entity in the functions table if one doesn't already exist that matches *signature_hash*.
        Updates attribute signature of entity if *signature* doesn't macht the previously stored value.

        Parameters
        ----------
        contract: Contract
            Contract entity containing the ID.
        signature: Text
            The function's signature where len(signature) < 256.
        signature_hash: Text
            The function's signature hash where len(signature_hash) == 10.
        """
        assert contract is not None and contract.id is not None, 'No contract id provided'
        assert signature is not None and signature_hash is not None, 'Both the signature and its hash need to be provided'

        entity = self.get(contract, signature_hash=signature_hash)
        if entity is None:
            entity = Function(contract_id=contract.id, signature=signature, signature_hash=signature_hash)
            self.db.session.add(entity)
            self.db.session.commit()
        elif signature is not None and signature != entity.signature:
            entity.signature = signature
            self.db.session.commit()
        return entity
