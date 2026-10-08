"""Load data from folder with cached radare2 binary artefacts.

This utility will handle a folder containing cached data for
multiple binary and group different data types by function.
"""

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from hexio import HexStr

from .parsers import JsonlDataParser, TarDataParser
from .r2types import (
    BIN2ML_CFG,
    HasAddr,
    R2CallGraph,
    R2CodeInfo,
    R2FunctionInfo,
    R2Zignature,
)
from .trackers import BinaryDataPaths, DataPathWithIndex, DataType

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# region ADDRESS HANDLING

# NOTE: Bin2ML very rarely produces a sentinel for a function address.
#       Addresses are 64-bits unsigned integers, therefore the
#       sentinel is as follows (i.e. 2 ^ 64 - 1)
ADDR_SENTINEL = 0xFFFFFFFFFFFFFFFF


def is_address_placeholder(address: int | None) -> bool:
    """Return True if address is None or the sentinel value."""
    return address is None or address == ADDR_SENTINEL


def get_address(data: HasAddr) -> int:
    """Return address from radare2 dictionary."""
    try:
        address = data["addr"]
    except ValueError:
        # This could happen if a version of radare2 below v6.0.0 was
        # used to extract the data
        logger.error("The dictionary doesn't contain an 'addr' key.")
        logger.debug(f"Data: {data}")
        address = ADDR_SENTINEL

    if is_address_placeholder(address):
        # This should never happen, we log it to be safe
        # but we don't want to raise an exception here
        logger.error(f"Address is placeholder: {address}")
        logger.debug(f"Data: {data}")
    return address


# endregion ADDRESS HANDLING


@dataclass(slots=True)
class FunctionDataGrouped:
    """Used to group raw data for a given function.

    R2CallGraph is not included as it is a binary-level dict.
    """

    address: int
    cfg: R2CodeInfo | None = None
    zignature: R2Zignature | None = None
    finfo: R2FunctionInfo | None = None
    fbytes_raw: bytes | None = None
    fbytes_bitmask: bytes | None = None
    cfg_raw_str: str | None = None
    zignature_raw_str: str | None = None
    finfo_raw_str: str | None = None
    _name: str | None = None

    @property
    def name(self) -> str | None:
        if self._name is None:
            self._name = self._setup_name()
        return self._name

    @staticmethod
    def get_canonical_name(name: str) -> str:
        name = name.removeprefix("method.")
        name = name.removeprefix("sym.")
        return name

    @name.setter
    def name(self, name: str) -> None:
        self._name = self.get_canonical_name(name)

    def _setup_address(self) -> int:
        addresses_set = set()
        if self.address is not None:
            addresses_set.add(self.address)
        if self.cfg is not None:
            addresses_set.add(get_address(self.cfg))
        if self.zignature is not None:
            addresses_set.add(get_address(self.zignature))
        if self.finfo is not None:
            addresses_set.add(get_address(self.finfo))
        if len(addresses_set) == 0:
            raise ValueError("No addresses found for the function")
        if len(addresses_set) > 1:
            raise ValueError("Multiple addresses found for the same function")
        return addresses_set.pop()

    def _setup_name(self) -> str | None:
        name = None
        if self.finfo is not None and self.finfo.get("name") is not None:
            name = self.get_canonical_name(self.finfo["name"])

        return name

    def __post_init__(self):
        self.address = self._setup_address()
        self._name = self._setup_name()

    @property
    def fbytes_nibblemask(self) -> bytes | None:
        if self.zignature is None:
            return None
        return bytes(HexStr(self.zignature["mask"]))

    @classmethod
    def merge_data(cls, data1: Self, data2: Self) -> Self:
        if data1.address != data2.address:
            raise ValueError(
                f"Addresses do not match: {data1.address} != {data2.address}"
            )
        if (
            data1.name is not None
            and data2.name is not None
            and data1.name != data2.name
        ):
            logger.warning(
                f"Function data names do not match: {data1.name} != {data2.name}"
            )

        # NOTE: if neither entry is None and they are different we
        #       arbitrarily pick data1. This can lead to data loss
        #       and in theory shouldn't happen.
        #       We check and log a warning just in case it does.
        return cls(
            address=data1.address,
            cfg=data1.cfg or data2.cfg,
            zignature=data1.zignature or data2.zignature,
            finfo=data1.finfo or data2.finfo,
            fbytes_raw=data1.fbytes_raw or data2.fbytes_raw,
            fbytes_bitmask=data1.fbytes_bitmask or data2.fbytes_bitmask,
            cfg_raw_str=data1.cfg_raw_str or data2.cfg_raw_str,
            zignature_raw_str=data1.zignature_raw_str
            or data2.zignature_raw_str,
            finfo_raw_str=data1.finfo_raw_str or data2.finfo_raw_str,
        )


class BinaryDataLoader:
    def __init__(
        self,
        binary_path: Path,
        data_paths: BinaryDataPaths,
        callgraph_path: Path,
    ) -> None:
        self.binary_path = binary_path
        self.data_paths = data_paths
        self.callgraph_path = callgraph_path
        self.data_entries: dict[int, FunctionDataGrouped] = {}
        self.callgraph = R2CallGraph()
        self._is_setup = False
        self._logger = logger.getChild(
            f"{self.__class__.__name__}({self.binary_name})"
        )

    @property
    def binary_name(self) -> str:
        return self.binary_path.name

    # region SETUP DATA FILES
    def setup_cfg(self) -> Self:
        if self.data_paths.cfg is None:
            raise RuntimeError("CFG data path is not set")

        cfg_path = self.data_paths.cfg
        with open(cfg_path, "r") as f:
            cfg_list: BIN2ML_CFG = json.load(f)
            for (cfg,) in cfg_list:
                faddr = get_address(cfg)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=faddr)
                    data_entry.cfg = cfg
                    data_entry.cfg_raw_str = json.dumps(cfg)
                    self.data_entries[faddr] = data_entry
                except Exception:
                    self._logger.exception(
                        "Error processing CFG data for function "
                        f"at address {faddr:x}"
                    )
        return self

    def setup_func_cfg(self, lazy: bool = False) -> Self:
        if self.data_paths.func_cfg is None:
            raise RuntimeError("func-CFG data path is not set")

        func_cfg_path = self.data_paths.func_cfg

        files_to_stream = []
        if func_cfg_path.is_dir():
            files_to_stream = list(func_cfg_path.glob("*.jsonl"))
            if not files_to_stream:
                self._logger.debug(
                    "func-cfg directory is empty or has no .jsonl files:"
                    + str(func_cfg_path)
                )
                return self
        else:
            files_to_stream = [func_cfg_path]

        for path in files_to_stream:
            jsonl_streamer = JsonlDataParser(path)
            for func_cfg, func_cfg_str in jsonl_streamer.stream(lazy=lazy):
                faddr = get_address(func_cfg)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=faddr)
                    data_entry.cfg = func_cfg
                    data_entry.cfg_raw_str = func_cfg_str
                    self.data_entries[faddr] = data_entry
                except Exception:
                    self._logger.exception(
                        "Error processing func-CFG data for function "
                        f"at address {faddr:x} in {path.name}"
                    )
        return self

    def setup_zigs(self) -> Self:
        if self.data_paths.zigs is None:
            raise RuntimeError("Zigs data path is not set")

        zigs_path = self.data_paths.zigs
        with open(zigs_path, "r") as f:
            zigs: list[R2Zignature] = json.load(f)
            for zignature in zigs:
                faddr = get_address(zignature)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=faddr)
                    data_entry.zignature = zignature
                    self.data_entries[faddr] = data_entry
                except Exception:
                    self._logger.exception(
                        f"Error processing Zigs data for function at address {faddr:x}"
                    )
        return self

    def setup_finfo(self) -> Self:
        if self.data_paths.finfo is None:
            raise RuntimeError("Finfo data path is not set")

        finfo_path = self.data_paths.finfo
        with open(finfo_path, "r") as f:
            finfo_list: list[R2FunctionInfo] = json.load(f)
            for finfo in finfo_list:
                faddr = get_address(finfo)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=faddr)
                    data_entry.finfo = finfo
                    self.data_entries[faddr] = data_entry
                except Exception:
                    self._logger.exception(
                        f"Error processing Finfo data for function at address {faddr:x}"
                    )
        return self

    def setup_bytes(self) -> Self:
        if (
            self.data_paths.bytes is None
            or not self.data_paths.bytes.is_valid()
        ):
            # Don't raise -- will try fallback from bytes-masked later
            self._logger.debug(
                "Bytes data path is not set or is not valid; "
                "will try fallback from bytes-masked if available"
            )
            return self

        # Prefer bytes-masked.tar if available since it contains
        # both raw and mask
        if (
            self.data_paths.bytes_masked is not None
            and self.data_paths.bytes_masked.is_valid()
        ):
            self._logger.info(
                "Bytes-masked data available; skipping bytes.tar extraction"
            )
            return self

        try:
            bytes_path = self.data_paths.bytes.data_path
            bytes_index_path = self.data_paths.bytes.index_path
            tar_streamer = TarDataParser(bytes_path, bytes_index_path)
            for (
                func_address,
                func_name,
                member_name,
                content,
            ) in tar_streamer.stream():
                try:
                    data_entry = self.data_entries.get(func_address)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=func_address)
                        data_entry.name = func_name
                    # Only set if not already set with bytes-masked data
                    if data_entry.fbytes_raw is None:
                        data_entry.fbytes_raw = content
                    self.data_entries[func_address] = data_entry
                except Exception:
                    self._logger.exception(
                        "Error processing Bytes data for function "
                        f"at address {func_address:x}"
                    )
                    continue
        except Exception:
            # Log but don't raise -- will try fallback from bytes-masked
            self._logger.exception(
                "Failed to load bytes.tar; will try fallback from bytes-masked if available"
            )
        return self

    def setup_bytes_masked(self) -> Self:
        if (
            self.data_paths.bytes_masked is None
            or not self.data_paths.bytes_masked.is_valid()
        ):
            self._logger.debug(
                "Bytes-masked data path is not set or tar is missing; skipping"
            )
            return self

        bytes_masked_path = self.data_paths.bytes_masked.data_path
        bytes_masked_index_path = self.data_paths.bytes_masked.index_path

        # Pass 1: stream .mask.bin files using the masked index
        # -- e.g. 00-func-index_bytes-masked.csv
        try:
            tar_streamer = TarDataParser(
                bytes_masked_path, bytes_masked_index_path
            )
            for (
                func_address,
                func_name,
                member_name,
                content,
            ) in tar_streamer.stream():
                try:
                    data_entry = self.data_entries.get(func_address)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=func_address)
                        data_entry.name = func_name
                    data_entry.fbytes_bitmask = content
                    self.data_entries[func_address] = data_entry
                except Exception:
                    self._logger.exception(
                        "Error processing Bytes-masked (mask) data for "
                        f"function at address {func_address:x}"
                    )
                    continue
        except Exception:
            self._logger.exception(
                "Failed to load bytes-masked tar; "
                "skipping bytes-masked data for this binary"
            )
            return self

        # Pass 2: stream .raw.bin files using the raw index embedded
        # within the same tar. Expect the same name as the raw index
        # but with 'bytes' instead of 'bytes-masked'
        raw_index_path = bytes_masked_index_path.with_name(
            bytes_masked_index_path.name.replace("bytes-masked", "bytes")
        )
        try:
            tar_streamer_raw = TarDataParser(bytes_masked_path, raw_index_path)
            for (
                func_address,
                func_name,
                member_name,
                content,
            ) in tar_streamer_raw.stream():
                try:
                    data_entry = self.data_entries.get(func_address)
                    if data_entry is None:
                        data_entry = FunctionDataGrouped(address=func_address)
                        data_entry.name = func_name
                    data_entry.fbytes_raw = content
                    self.data_entries[func_address] = data_entry
                except Exception:
                    self._logger.exception(
                        "Error processing Bytes-masked (raw) data for "
                        f"function at address {func_address:x}"
                    )
                    continue
        except Exception:
            self._logger.exception(
                "Could not load raw bytes index from bytes-masked.tar;"
                " raw bytes may be missing."
            )

        return self

    def setup_callgraph(self) -> Self:
        if not self.callgraph_path.is_file():
            raise FileNotFoundError(
                "Callgraph data file could not be found: "
                + str(self.callgraph_path)
            )
        with open(self.callgraph_path, "r") as f:
            self.callgraph = json.load(f)
        return self

    def setup_data_type(self, data_type: DataType) -> Self:
        match data_type:
            case DataType.CFG:
                if self.data_paths.cfg is not None:
                    return self.setup_cfg()
                else:
                    return self.setup_func_cfg()
            case DataType.ZIGNATURES:
                return self.setup_zigs()
            case DataType.FUNCTION_INFO:
                return self.setup_finfo()
            case DataType.BYTES:
                return self.setup_bytes()
            case DataType.BYTES_MASKED_BIT:
                return self.setup_bytes_masked()
            case DataType.CALL_GRAPH:
                return self.setup_callgraph()
            case _:
                raise NotImplementedError(
                    f"Setup for data type {data_type} is not implemented yet"
                )

    def setup(self, lazy: bool = False) -> Self:
        if self.data_paths.cfg is not None:
            self.setup_cfg()
        elif self.data_paths.func_cfg is not None:
            self.setup_func_cfg(lazy=lazy)

        if self.data_paths.zigs is not None:
            self.setup_zigs()
        if self.data_paths.finfo is not None:
            self.setup_finfo()
        if self.data_paths.bytes_masked is not None:
            self.setup_bytes_masked()
        elif self.data_paths.bytes is not None:
            # Only load raw bytes if bytes-masked data is not available
            self.setup_bytes()
        # Only load callgraph if file actually exists (optional data)
        if self.callgraph_path is not None and self.callgraph_path.is_file():
            self.setup_callgraph()
        self._is_setup = True
        return self

    # endregion SETUP DATA FILES

    def iterate_functions_data(
        self,
        sort_by_address: bool = True,
        include_callgraph: bool = False,
    ) -> Iterator[
        tuple[
            int,
            str | None,
            R2CodeInfo | None,
            R2Zignature | None,
            R2FunctionInfo | None,
            str | None,
            str | None,
            str | None,
            R2CallGraph | None,
            bytes | None,
            bytes | None,
        ]
    ]:
        if sort_by_address:
            logger.info("Sorting data entries by address")
            data_entries = sorted(
                self.data_entries.items(), key=lambda x: x[0]
            )
        else:
            data_entries = self.data_entries.items()

        for address, func_data in data_entries:
            yield (
                address,
                func_data.name,
                func_data.cfg,
                func_data.zignature,
                func_data.finfo,
                func_data.cfg_raw_str,
                func_data.zignature_raw_str,
                func_data.finfo_raw_str,
                self.callgraph
                if include_callgraph
                else None,  # Only include if requested
                func_data.fbytes_raw,
                func_data.fbytes_bitmask,
            )

    def get_callgraph(self) -> R2CallGraph | None:
        """Get the global call graph for this binary."""
        if self.callgraph_path is None:
            return None
        if not self._is_setup:
            return None
        return self.callgraph if self.callgraph else None


def get_data_loader(binary_path: Path, raw_data_dir: Path) -> BinaryDataLoader:
    binary_name = binary_path.name
    data_paths = BinaryDataPaths(
        cfg=raw_data_dir / f"{binary_name}_cfg.json",
        func_cfg=raw_data_dir / f"{binary_name}_func-cfg.jsonl",
        zigs=raw_data_dir / f"{binary_name}_zigs.json",
        finfo=raw_data_dir / f"{binary_name}_finfo.json",
        bytes=DataPathWithIndex(
            data_path=raw_data_dir / f"{binary_name}_bytes.tar",
            index_path=raw_data_dir / f"{binary_name}_bytes_func-index.csv",
        ),
        bytes_masked=DataPathWithIndex(
            data_path=raw_data_dir / f"{binary_name}_bytes-masked.tar",
            index_path=raw_data_dir
            / f"{binary_name}_bytes-masked_func-index.csv",
        ),
        cg=raw_data_dir / f"{binary_name}_cg.json",
    )
    callgraph_path = raw_data_dir / f"{binary_name}_cg.json"

    data_loader = BinaryDataLoader(
        binary_path=binary_path,
        data_paths=data_paths,
        callgraph_path=callgraph_path,
    )
    return data_loader
