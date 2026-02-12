from dataclasses import asdict, dataclass


class Version(str):
    __slots__ = ()

    @classmethod
    def from_obj(cls, obj: str) -> "Version":
        return cls(obj)

    def to_obj(self) -> str:
        return str(self)


@dataclass(slots=True, frozen=True)
class Fork:
    previous_version: Version
    current_version: Version
    epoch: int

    @classmethod
    def from_obj(cls, obj: dict[str, str]) -> "Fork":
        return cls(
            previous_version=Version.from_obj(obj["previous_version"]),
            current_version=Version.from_obj(obj["current_version"]),
            epoch=int(obj["epoch"]),
        )

    def to_obj(self) -> dict[str, str]:
        return {
            "previous_version": self.previous_version.to_obj(),
            "current_version": self.current_version.to_obj(),
            "epoch": str(self.epoch),
        }


@dataclass(slots=True, frozen=True)
class Genesis:
    genesis_time: int
    genesis_validators_root: str
    genesis_fork_version: Version

    @classmethod
    def from_obj(cls, obj: dict[str, str]) -> "Genesis":
        return cls(
            genesis_time=int(obj["genesis_time"]),
            genesis_validators_root=obj["genesis_validators_root"],
            genesis_fork_version=Version.from_obj(obj["genesis_fork_version"]),
        )

    def to_obj(self) -> dict[str, str]:
        return {
            "genesis_time": str(self.genesis_time),
            "genesis_validators_root": self.genesis_validators_root,
            "genesis_fork_version": self.genesis_fork_version.to_obj(),
        }


@dataclass(slots=True, unsafe_hash=True)
class SpecFulu:
    # Phase 0
    SECONDS_PER_SLOT: int
    SLOTS_PER_EPOCH: int
    MAX_VALIDATORS_PER_COMMITTEE: int
    MAX_COMMITTEES_PER_SLOT: int
    GENESIS_FORK_VERSION: Version
    MAX_PROPOSER_SLASHINGS: int
    MAX_ATTESTER_SLASHINGS: int
    MAX_ATTESTATIONS: int
    MAX_DEPOSITS: int
    MAX_VOLUNTARY_EXITS: int

    # Altair
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD: int
    SYNC_COMMITTEE_SIZE: int
    ALTAIR_FORK_EPOCH: int
    ALTAIR_FORK_VERSION: Version

    # Bellatrix
    BELLATRIX_FORK_EPOCH: int
    BELLATRIX_FORK_VERSION: Version

    BYTES_PER_LOGS_BLOOM: int
    MAX_EXTRA_DATA_BYTES: int
    MAX_TRANSACTIONS_PER_PAYLOAD: int
    MAX_BYTES_PER_TRANSACTION: int

    # Capella
    MAX_WITHDRAWALS_PER_PAYLOAD: int
    CAPELLA_FORK_EPOCH: int
    CAPELLA_FORK_VERSION: Version
    MAX_BLS_TO_EXECUTION_CHANGES: int

    # Deneb
    MAX_BLOB_COMMITMENTS_PER_BLOCK: int
    DENEB_FORK_EPOCH: int
    DENEB_FORK_VERSION: Version
    FIELD_ELEMENTS_PER_BLOB: int

    # Electra
    ELECTRA_FORK_EPOCH: int
    ELECTRA_FORK_VERSION: Version
    MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: int
    MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: int
    MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: int
    MAX_ATTESTATIONS_ELECTRA: int
    MAX_ATTESTER_SLASHINGS_ELECTRA: int

    # Fulu
    FULU_FORK_EPOCH: int
    FULU_FORK_VERSION: Version

    @classmethod
    def fields(cls) -> tuple[str, ...]:
        return tuple(cls.__annotations__.keys())

    def to_obj(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for k, v in asdict(self).items():
            out[k] = str(v)
        return out


def parse_spec(data: dict[str, str]) -> SpecFulu:
    fields = SpecFulu.__annotations__
    parsed = {
        k: (Version.from_obj(v) if k.endswith("_FORK_VERSION") else int(v))
        for k, v in data.items()
        if k in fields
    }

    missing = set(fields) - set(parsed)
    if missing:
        raise ValueError(f"Required field(s) missing from spec: {missing}")

    return SpecFulu(**parsed)  # type: ignore[arg-type]
