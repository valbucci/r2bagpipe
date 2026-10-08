"""Track paths to binary data files."""

import logging
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


ExtractMode = Literal[
    "finfo",
    "reg",
    "cfg",
    "func-cfg",
    "func-xrefs",
    "cg",
    "decomp",
    "pcode-func",
    "pcode-bb",
    "localvar-xrefs",
    "strings",
    "bytes",
    "bytes-masked",
    "fvars",
    "zigs",
    "bininfo",
]


class DataType(Enum):
    CFG = auto()
    BYTES = auto()
    BYTES_MASKED_NIBBLE = auto()
    BYTES_MASKED_BIT = auto()
    ZIGNATURES = auto()
    FUNCTION_INFO = auto()
    CALL_GRAPH = auto()
    BINARY_INFO = auto()

    @classmethod
    def get_modes_from_data_type(
        cls, data_type: "DataType"
    ) -> tuple[ExtractMode, ...]:
        """Return the possible suffixes for a given DataType.

        As long as one file exists with its name terminating with one
        of the suffixes in the returned list, the necessary data will
        be loaded.
        """
        if data_type == cls.CFG:
            return ("cfg", "func-cfg")
        elif data_type == cls.BYTES:
            return ("bytes", "bytes-masked")
        elif data_type == cls.BYTES_MASKED_NIBBLE:
            return ("zigs",)
        elif data_type == cls.BYTES_MASKED_BIT:
            return ("bytes-masked",)
        elif data_type == cls.ZIGNATURES:
            return ("zigs",)
        elif data_type == cls.FUNCTION_INFO:
            return ("finfo",)
        elif data_type == cls.CALL_GRAPH:
            return ("cg",)
        elif data_type == cls.BINARY_INFO:
            return ("bininfo",)
        raise ValueError(f"Unknown DataType: {data_type}")

    @classmethod
    def get_data_type_from_mode(cls, mode: ExtractMode) -> "DataType":
        """Return the DataType enum value for a given type suffix."""
        for data_type in cls:
            if mode in cls.get_modes_from_data_type(data_type):
                return data_type
        raise ValueError(f"Unknown mode: {mode}")

    @property
    def modes(self) -> tuple[ExtractMode, ...]:
        """The possible file suffixes for this DataType."""
        return self.get_modes_from_data_type(self)


@dataclass
class DataPathMaybeWithIndex:
    """Path to a data file on the system and optional index.

    - data_path: the expected data file.
    - index_path: the expected index of functions in the binary file;
                  None if not provided for the data type or not found.
    """

    data_path: Path
    index_path: Path | None = None

    def is_valid(self) -> bool:
        """Return True if data_path exists on the system."""
        return self.data_path.exists()


@dataclass
class DataPathWithIndex(DataPathMaybeWithIndex):
    """Path to a data file and its index on the system and index.

    Created to enforce pair requirement when a data_path is not enough.
    Both the data and index must be provided (e.g. with bytes data).
    """

    data_path: Path
    index_path: Path  # type: ignore

    def is_valid(self) -> bool:
        """Return True if data_path and index_path exist on the system.

        - data_path could be a file or a directory
        - index_path must be a file.
        """
        return self.data_path.exists() and self.index_path.is_file()


@dataclass
class BinaryDataPaths:
    """Paths to the data files for a given binary."""

    cfg: Path | None = None
    func_cfg: Path | None = None
    zigs: Path | None = None
    finfo: Path | None = None
    cg: Path | None = None
    bytes: DataPathWithIndex | None = None
    bytes_masked: DataPathWithIndex | None = None

    binary_name: str = ""

    def log(self, message: str, level: int = logging.DEBUG) -> None:
        """Log message with binary context."""
        ctx = f"({self.binary_name}) " if self.binary_name else ""
        message = f"{ctx}{message}"
        logger.log(level, message)

    # region CHECK DATA VALIDITY
    def _check_cfg(self) -> None:
        # CFG data either in func-cfg or cfg modes
        if self.func_cfg is not None and not self.func_cfg.exists():
            # NOTE: we use func_cfg.exists() because it could be a
            #       directory or a JSONL file
            self.log(f"func-cfg path not found: {self.func_cfg}")
            self.func_cfg = None
        if self.cfg is not None and not self.cfg.is_file():
            self.log(f"cfg file not found: {self.cfg}")
            self.cfg = None
        if self.cfg is None and self.func_cfg is None:
            self.log("No cfg files found", logging.WARNING)

    def _check_bytes(self) -> None:
        # Bytes data either in bytes or bytes-masked modes
        if self.bytes is not None and not self.bytes.is_valid():
            self.log(f"bytes file not found: {self.bytes.data_path}")
            self.bytes = None
        if self.bytes_masked is not None and not self.bytes_masked.is_valid():
            self.log(
                f"bytes-masked file not found: {self.bytes_masked.data_path}"
            )
            self.bytes_masked = None
        if self.bytes is None and self.bytes_masked is None:
            self.log("No bytes files found", logging.WARNING)

    def _check_zigs(self) -> None:
        # Zignatures
        if self.zigs is not None and not self.zigs.is_file():
            self.log(f"zigs file not found: {self.zigs}", logging.WARNING)
            self.zigs = None

    def _check_finfo(self) -> None:
        # Function Information
        if self.finfo is not None and not self.finfo.is_file():
            self.log(f"finfo file not found: {self.finfo}", logging.WARNING)
            self.finfo = None

    def _check_cg(self) -> None:
        # Callgraph
        if self.cg is not None and not self.cg.is_file():
            self.log(f"cg file not found: {self.cg}", logging.WARNING)
            self.cg = None

    # endregion CHECK DATA VALIDITY

    def __post_init__(self):
        """Check that all not-None paths actually exist."""
        self._check_cfg()
        self._check_bytes()
        self._check_zigs()
        self._check_finfo()
        self._check_cg()

    def __contains__(self, mode: ExtractMode) -> bool:
        """Check whether the data type was cached."""
        if mode == "func-cfg":
            return self.func_cfg is not None
        elif mode == "bytes-masked":
            return self.bytes_masked is not None
        else:
            return getattr(self, mode) is not None

    def __getitem__(
        self, mode: ExtractMode
    ) -> tuple[Path | None, Path | None]:
        """Return the data and index path for a given mode.

        The data path is returned always, whereas the index is only
        return for certain modes -- e.g. `bytes`, `bytes-mased`.
        """
        if mode == "func-cfg":
            return self.func_cfg, None

        elif mode == "bytes-masked":
            if self.bytes_masked is None:
                return None, None
            else:
                return (
                    self.bytes_masked.data_path,
                    self.bytes_masked.index_path,
                )

        elif mode == "bytes":
            if self.bytes is None:
                return None, None
            else:
                return (self.bytes.data_path, self.bytes.index_path)

        else:
            return getattr(self, mode), None

    def fetch_data_paths(
        self, data_types: list[DataType]
    ) -> dict[DataType, DataPathMaybeWithIndex]:
        data_paths_index = {}
        for data_type in data_types:
            data_path, index_path = None, None
            match data_type:
                case DataType.BYTES:
                    if self.bytes is not None and self.bytes.is_valid():
                        data_path = self.bytes.data_path
                        index_path = self.bytes.index_path
                    break

                case DataType.BYTES_MASKED_BIT:
                    if (
                        self.bytes_masked is not None
                        and self.bytes_masked.is_valid()
                    ):
                        data_path = self.bytes_masked.data_path
                        index_path = self.bytes_masked.index_path
                    break

                case DataType.CFG:
                    if self.cfg is not None and self.cfg.is_file():
                        data_path = self.cfg
                    elif self.func_cfg is not None and self.func_cfg.is_file():
                        data_path = self.func_cfg
                    break

                case _:
                    mode = data_type.modes[0]
                    data_path, index_path = self[mode]

            if data_path is None:
                continue

            data_result = DataPathMaybeWithIndex(data_path, index_path)
            data_paths_index[data_type] = data_result

        return data_paths_index
