from typing import Text

from .verification_db import VerificationDB, Contract


class ContractRepository:

    def __init__(self):
        self.db = VerificationDB()

    def get(self, address: Text) -> Contract:
        """
        Retrieve Contract entity from the database.

        Parameters
        ----------
        address: Text
            The contract's address where len(address) == 42.

        Returns
        -------
        Populated Contract instance or None if entity doesn't exist.
        """
        assert address is not None, 'No contract address provided'

        return self.db.session.query(Contract).filter(Contract.address == address).first()

    def save(self, address: Text, compiler_version: Text) -> Contract:
        """
        Saves contract entity into the contracts table with the given *address*, if not already present.
        If a contract entity with *address* attribute is already present, return that.

        Parameters
        ----------
        address: Text
            The contract's address where len(address) == 42.
        """
        assert address is not None, 'No contract address provided'

        entity = self.get(address)
        if entity is None:
            entity = Contract(address=address, compiler_version=compiler_version)
            self.db.session.add(entity)
            self.db.session.commit()
        else:
            entity.compiler_version = compiler_version
            self.db.session.commit()
        return entity
