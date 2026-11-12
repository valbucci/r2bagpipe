"""Load radare2 dictionary into dataclasses."""

import bisect
import json
import logging
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from hashlib import blake2b
from pathlib import Path
from typing import Self

from hexio import HexInt, HexStr

from r2bagpipe.parsers import JsonlDataParser

from .r2types import (
    Bin2MlCfg,
    R2BlockInfo,
    R2CallGraph,
    R2CodeInfo,
    R2OpcodeInfo,
    R2OpcodeInfoReference,
    R2ReferencePermStr,
    R2Zignature,
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# region UTILITIES


# ---------------------------------------------------------------------
# We need these address functions because older versions of radare2
# (<v6.0.0) used the `offset` key to define binary entity addresses.
# Now radare2 uses the `addr` key.
# The functions here are used to maintain retro-compatibility.
# ---------------------------------------------------------------------

# Using an address placeholder as sentinel for empty addresses.
# NOTE: This was needed for compatibility with Bin2ML
#       because Rust structs do not support undefined fields.
#       The placeholder is a uint64 filled with 1-bits.
PLACEHOLDER_ADDR = 0xFFFFFFFFFFFFFFFF  # Same as 2**64 - 1


def is_valid_addr(addr: int | None):
    """Check if address is set to a valid value."""
    return addr is None or addr == PLACEHOLDER_ADDR


def get_addr(data) -> int:
    """Return address from radare2 JSON data object.

    Maintains retro-compatibility across v6.0.0
    where the address used to be stored under the key
    `offset` whereas now it's `addr`.
    """
    if "addr" in data:
        return data["addr"]
    else:
        return data["offset"]


# ---------------------------------------------------------------------


def normalise_func_name(name: str) -> str:
    """Strip disassembler prefixes.

    Radare2 inconsistently prefixes function names
    as sym.<n> or imp.<n> depending on context.
    This function strips those prefixes.
    """
    for prefix in ("sym.imp.", "sym.", "imp."):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name


# endregion UTILITIES

# region ESIL

# Classify atomic Evaluable String Intermediate Language (ESIL)
# operation types (aka ESIL tokens).
# Source: <https://github.com/radareorg/radare2/blob/master/libr/esil/esil_ops.c>

# NOTE: Claude Sonnet 4.6 was used to identify operation types (AI:w)
#       from the source file as context.


class EsilTokenType(Enum):
    """Types of radare2 ESIL atomic operations."""

    ARITHMETIC = 1
    BITWISE = 2
    COMPARISON = 3
    ASSIGNMENT = 4
    STACK = 5
    FLAG_QUERY = 6
    CONTROL_FLOW = 7
    SYSTEM = 8
    MEM_READ = 9
    MEM_WRITE = 10
    FLOAT = 11
    MEM_RMW = 12
    VALUE = 13
    IDENTIFIER = 14

    @property
    def description(self) -> str:
        """Provides definition for each ESIL token type."""
        descriptions = {
            "ARITHMETIC": "Integer arithmetic operations (add, subtract, multiply, divide, modulo, increments).",
            "BITWISE": "Bitwise operations, logical shifts, rotations, and bit-counting (AND, OR, XOR, NOT, LSL, ROR, CLZ).",
            "COMPARISON": "Relational and equality evaluations (==, <, >, <=, >=) that feed status flags.",
            "ASSIGNMENT": "Register write operations, from strong/weak assignments (=, :=) to compound assignments (+=, &=).",
            "STACK": "ESIL evaluation stack manipulation keywords (DUP, SWAP, ROT, POP, CLEAR).",
            "FLAG_QUERY": "Internal CPU status flag evaluations ($z, $c, $b, $p, $s, $o, $ds, $jt, $js) tracking zero, carry, parity, sign, overflow, and delay-slot state.",
            "CONTROL_FLOW": "Conditional blocks, branch targets, and execution flow modifiers (?{, }, GOTO, BREAK).",
            "SYSTEM": "System-level interrupts, traps, meta commands, and architecture configuration (TRAP, BITS, $).",
            "MEM_READ": "Memory peek operations reading fixed byte widths ([1], [4], [8]) from an address.",
            "MEM_WRITE": "Memory poke operations writing fixed byte widths (=[1], =[4]) to an address.",
            "FLOAT": "Floating-point math, type conversions, and IEEE-754 comparisons (I2D, F+, SQRT).",
            "MEM_RMW": "Compound memory operations combining a load, an arithmetic or bitwise operation, and a store back to the same address (+=[4], &=[8]).",
            "VALUE": "Literal numeric constants (decimal integers or hexadecimal values like 0xffffffff).",
            "IDENTIFIER": "Variables, CPU general-purpose registers (r0, rax), or internal flag registers (nf, zf).",
        }
        return descriptions.get(self.name, "Unknown ESIL token category.")


ARITHMETIC_OPS = {"+", "-", "*", "L*", "/", "~/", "%", "~%", "++", "--"}
BITWISE_OPS = {
    "&",
    "|",
    "^",
    "!",
    "~",
    "<<",
    "LSL",
    ">>",
    "LSR",
    "ASR",
    "ROR",
    "ROL",
    "CLZ",
    "POPCNT",
}
COMPARISON_OPS = {"==", "<", ">", "<=", ">="}
ASSIGNMENT_OPS = {
    "=",
    ":=",
    "+=",
    "-=",
    "*=",
    "/=",
    "%=",
    "&=",
    "|=",
    "^=",
    "!=",  # NOT-assign (DUP,!,SWAP,=)
    "~=",
    "<<=",
    ">>=",
    "++=",
    "--=",
}
STACK_OPS = {"DUP", "SWAP", "ROT", "POP", "CLEAR", "STACK", "NUM"}
FLAG_QUERIES = {"$z", "$c", "$b", "$p", "$s", "$o", "$ds", "$jt", "$js"}
CONTROL_FLOW = {"?{", "}", "}{", "GOTO", "BREAK"}
SYSTEM_META = {
    "$",
    "()",
    "#!",
    "TRAP",
    "TODO",
    "BITS",
    "SETJT",
    "SETJTS",
    "SETD",
    "r=",
}
MEMORY_READS = {"[1]", "[2]", "[3]", "[4]", "[8]", "[16]", "[*]"}
MEMORY_WRITES = {"=[1]", "=[2]", "=[3]", "=[4]", "=[8]", "=[16]", "=[*]"}
FLOAT_OPS = {
    "I2D",
    "U2D",
    "D2I",
    "D2F",
    "F2D",
    "NAN",
    "F==",
    "F!=",
    "F<",
    "F<=",
    "F+",
    "F-",
    "F*",
    "F*+",
    "F/",
    "-F",
    "CEIL",
    "FLOOR",
    "ROUND",
    "SQRT",
}

RMW_REGEX = re.compile(r"^(\+\+|--|<<|>>|[|^&+\-\%/*])=\[(\d+|\*)\]$")
VALUE_REGEX = re.compile(r"^-?(?:0x[0-9a-fA-F]+|\d+)$")


def get_esil_type(token: str) -> EsilTokenType | None:
    """Classify radare2 ESIL atomic operation type."""
    if not token:
        return None
    if VALUE_REGEX.match(token):
        return EsilTokenType.VALUE
    if token in ARITHMETIC_OPS:
        return EsilTokenType.ARITHMETIC
    if token in BITWISE_OPS:
        return EsilTokenType.BITWISE
    if token in COMPARISON_OPS:
        return EsilTokenType.COMPARISON
    if token in ASSIGNMENT_OPS:
        return EsilTokenType.ASSIGNMENT
    if token in STACK_OPS:
        return EsilTokenType.STACK
    if token in FLAG_QUERIES:
        return EsilTokenType.FLAG_QUERY
    if token in CONTROL_FLOW:
        return EsilTokenType.CONTROL_FLOW
    if token in SYSTEM_META:
        return EsilTokenType.SYSTEM
    if token in MEMORY_READS:
        return EsilTokenType.MEM_READ
    if token in MEMORY_WRITES:
        return EsilTokenType.MEM_WRITE
    if token in FLOAT_OPS:
        return EsilTokenType.FLOAT
    if RMW_REGEX.match(token):
        return EsilTokenType.MEM_RMW
    return EsilTokenType.IDENTIFIER


# endregion ESIL

# region REFERENCES


class ReferenceType(Enum):
    """Radare2 reference types."""

    # Not using auto() for consistency
    # in case I was to add/remove types in the future.
    UNKN = 0
    CALL = 1
    JUMP = 2
    CODE = 3
    ICOD = 4
    DATA = 5
    STRN = 6
    NULL = 7


def get_reference_kind(ref_type: ReferenceType) -> ReferenceType:
    """Normalise reference types to kind groups."""
    match ref_type:
        case ReferenceType.CALL:
            # An inter-procedural reference (function call)
            return ReferenceType.CALL
        case ReferenceType.JUMP | ReferenceType.CODE | ReferenceType.ICOD:
            # An intra-procedural reference (CFG edge)
            return ReferenceType.CODE
        case ReferenceType.DATA | ReferenceType.STRN:
            # A read (DATA/STRN) or write (STRN) reference
            return ReferenceType.DATA
        case _:
            return ReferenceType.UNKN


@dataclass(frozen=True, slots=True)
class OpcodeReferenceData:
    src_addr: int
    dst_addr: int
    perm: int
    ref_type: ReferenceType

    @staticmethod
    def str_perm_to_int(str_perm: R2ReferencePermStr) -> int:
        """Convert reference string into integer encoding."""
        match str_perm:
            case "r--":
                return 0b100
            case "-w-":
                return 0b010
            case "--x":
                return 0b001
            case _:
                return 0

    @property
    def ref_kind(self) -> ReferenceType:
        """Return normalised reference type."""
        return get_reference_kind(self.ref_type)

    @classmethod
    def from_ref_info(
        cls, opcode_addr: int, opcode_info_ref: R2OpcodeInfoReference
    ) -> Self | None:
        """Return new instance from r2 data, None if incomplete."""
        try:
            return cls(
                src_addr=opcode_addr,
                dst_addr=get_addr(opcode_info_ref),
                perm=cls.str_perm_to_int(opcode_info_ref["perm"]),
                ref_type=ReferenceType[opcode_info_ref["type"]],
            )
        except KeyError:
            logger.exception(
                "Failed to create OpcodeReferenceFeatures object from ref."
            )
            return None

    @classmethod
    def from_xref_info(
        cls, opcode_addr: int, opcode_info_ref: R2OpcodeInfoReference
    ) -> Self | None:
        """Return new instance from r2 data, None if incomplete.

        Like `from_ref_info` but the destination is `opcode_addr`.
        """
        try:
            return cls(
                src_addr=get_addr(opcode_info_ref),
                dst_addr=opcode_addr,
                perm=cls.str_perm_to_int(opcode_info_ref["perm"]),
                ref_type=ReferenceType[opcode_info_ref["type"]],
            )
        except KeyError:
            logger.exception(
                "Failed to create OpcodeReferenceFeatures object from xref."
            )
            return None

    @classmethod
    def from_info(
        cls,
        opcode_addr: int,
        opcode_info_ref: R2OpcodeInfoReference,
        xref=False,
    ) -> Self | None:
        """Return new instance from r2 data, None if incomplete.

        Routes to correct method based on `xref` argument.
        Defaults to `from_ref_info`.
        """
        if not xref:
            return cls.from_ref_info(opcode_addr, opcode_info_ref)
        else:
            return cls.from_xref_info(opcode_addr, opcode_info_ref)

    @classmethod
    def merge_ref_perms(cls, refs: Iterable[Self]) -> int:
        merged = 0
        for reference in refs:
            merged |= reference.perm
        return merged


# endregion REFERENCES

# region CFG


@dataclass(frozen=True, slots=True)
class OpcodeData:
    addr: int
    n_bytes: int
    raw_bytes: str
    op_type: str
    esil: str

    ptr: int | None
    refs: tuple[OpcodeReferenceData, ...] | None
    xrefs: tuple[OpcodeReferenceData, ...] | None
    ref_perm: int

    @staticmethod
    def _process_refs(
        opcode_info: R2OpcodeInfo, xref: bool
    ) -> tuple[OpcodeReferenceData, ...] | None:
        if not xref:
            refs = opcode_info.get("refs")
        else:
            refs = opcode_info.get("xrefs")

        if refs is None:
            return None

        processed = []
        for ref_info in refs:
            feat = OpcodeReferenceData.from_info(
                get_addr(opcode_info), ref_info, xref=xref
            )
            if feat is not None:
                processed.append(feat)
            else:
                logger.error("Skipping OpcodeReferenceFeatures ...")
        return tuple(processed)

    @classmethod
    def from_info(cls, opcode_info: R2OpcodeInfo) -> Self | None:
        """Return new instance from r2 data, none if incomplete."""
        try:
            refs = cls._process_refs(opcode_info, xref=False)
            ref_perm = 0
            if refs is not None:
                ref_perm = OpcodeReferenceData.merge_ref_perms(refs)
            xrefs = cls._process_refs(opcode_info, xref=True)
            return cls(
                addr=get_addr(opcode_info),
                n_bytes=opcode_info["size"],
                raw_bytes=opcode_info["bytes"],
                op_type=opcode_info["type"],
                esil=opcode_info["esil"],
                ptr=opcode_info.get("ptr"),
                refs=refs,
                xrefs=xrefs,
                ref_perm=ref_perm,
            )
        except KeyError:
            logger.exception("Failed to create OpcodeFeatures object.")
            return None

    @property
    def fallthrough_addr(self) -> int:
        """Return address of next fallthrough opcode."""
        return self.addr + self.n_bytes

    @property
    def is_reference(self) -> bool:
        """Check if opcode is a code/data reference."""
        return self.refs is not None

    @property
    def is_read(self) -> bool:
        """Return True if is reference with read permissions."""
        # Probably no need to mask permissions for READ
        # but keeping it anyway for comformity
        return (self.ref_perm & 0b100) >> 2 == 1

    @property
    def is_write(self) -> bool:
        """Return True if is reference with write permissions."""
        return (self.ref_perm & 0b010) >> 1 == 1

    @property
    def is_exec(self) -> bool:
        """Return True if is reference with write permissions."""
        return (self.ref_perm & 0b001) == 1

    def iter_esil(self) -> Iterator[str]:
        """Iterate atomic ESIL operations."""
        yield from self.esil.split(",")


@dataclass(frozen=True, slots=True)
class BasicBlockData:
    addr: int
    jump: int | None
    fail: int | None

    n_bytes: int
    n_instr: int
    n_reads: int
    n_writes: int
    n_execs: int

    ref_perm: int
    opcodes: tuple[OpcodeData, ...]

    @classmethod
    def from_info(cls, block_info: R2BlockInfo) -> Self | None:
        try:
            opcodes = []
            n_instr = 0
            ref_perm = 0
            n_reads = 0
            n_writes = 0
            n_execs = 0
            for opcode_info in block_info["ops"]:
                opcode = OpcodeData.from_info(opcode_info)
                if opcode is None:
                    logger.error("Skipping OpcodeFeatures ...")
                    continue
                n_instr += 1
                opcodes.append(opcode)

                # Cache reference information.
                # We allow for a single opcode to have more than one
                # reference permission at once
                # (even though it's unlikely)
                ref_perm |= opcode.ref_perm
                if opcode.is_read:
                    n_reads += 1
                if opcode.is_write:
                    n_writes += 1
                if opcode.is_exec:
                    n_execs += 1

            return cls(
                addr=get_addr(block_info),
                jump=block_info.get("jump"),
                fail=block_info.get("fail"),
                n_bytes=block_info["size"],
                n_instr=n_instr,
                n_reads=n_reads,
                n_writes=n_writes,
                n_execs=n_execs,
                ref_perm=ref_perm,
                opcodes=tuple(opcodes),
            )
        except KeyError:
            logger.exception("Failed to create BasicBlockFeatures object.")
            return None

    @property
    def n_refs(self) -> int:
        """The total number of r/w/x reference operations."""
        return self.n_reads + self.n_writes + self.n_execs

    @property
    def successors(self) -> tuple[int, ...]:
        """Store block successor addresses in a tuple.

        Equates to radare2 jump/fail instructions if set,
        otherwise it returns an empty tuple.
        """
        return tuple(
            next_addr
            for next_addr in (self.jump, self.fail)
            if next_addr is not None
        )

    def iter_esil(self) -> Iterator[str]:
        """Iterate all atomic ESIL operations in block intructions."""
        for op in self.opcodes:
            yield from op.iter_esil()

    def iter_op_types(self) -> Iterator[str]:
        """Iterate all opcode types in block instructions."""
        for op in self.opcodes:
            yield op.op_type


@dataclass(frozen=True, slots=True)
class FunctionCodeData:
    addr: int
    name: str

    n_stack: int
    n_instr: int
    n_args: int
    n_locals: int
    n_bytes: int
    n_reads: int
    n_writes: int
    n_execs: int
    ref_perm: int

    blocks: tuple[BasicBlockData, ...]

    @classmethod
    def from_info(cls, code_info: R2CodeInfo) -> Self | None:
        try:
            # Process blocks
            blocks = []
            n_reads = 0
            n_writes = 0
            n_execs = 0
            ref_perm = 0
            for block_info in code_info["blocks"]:
                block = BasicBlockData.from_info(block_info)
                if block is None:
                    logger.error("Skipping BasicBlockFeatures ...")
                    continue
                n_reads += block.n_reads
                n_writes += block.n_writes
                n_execs += block.n_execs
                ref_perm |= block.ref_perm
                blocks.append(block)

            return cls(
                # Identifiers
                addr=get_addr(code_info),
                name=code_info["name"],
                # General info counts
                n_stack=code_info["stack"],
                n_instr=code_info["ninstr"],
                n_args=code_info["nargs"],
                n_locals=code_info["nlocals"],
                n_bytes=code_info["size"],
                n_reads=n_reads,
                n_writes=n_writes,
                n_execs=n_execs,
                ref_perm=ref_perm,
                blocks=tuple(blocks),
            )

        except KeyError:
            logger.exception("Failed to create FunctionFeatures object.")
            return None

    @property
    def n_vars(self) -> int:
        return self.n_args + self.n_locals

    @property
    def n_refs(self) -> int:
        return self.n_reads + self.n_writes + self.n_execs

    def iter_opcodes(self) -> Iterator[OpcodeData]:
        """Yield opcodes inside the function."""
        for block in self.blocks:
            yield from block.opcodes

    @property
    def opcodes(self) -> tuple[OpcodeData, ...]:
        """Return opcodes inside the function."""
        return tuple(self.iter_opcodes())

    def iter_cfg_edges(self) -> Iterator[tuple[int, tuple[int, ...]]]:
        """Yield each block's address and its successors in the CFG.

        Returns tuple with format
            ( source_addr, ( destination_addr, ... ) )
        """
        for block in self.blocks:
            yield block.addr, block.successors

    def iter_opcode_refs(self) -> Iterator[OpcodeReferenceData]:
        """Yield references inside the function."""
        for opcode in self.iter_opcodes():
            if opcode.refs is not None:
                yield from opcode.refs

    def iter_op_types(self) -> Iterator[str]:
        """Yield types of assembly mnemonics."""
        for block in self.blocks:
            yield from block.iter_op_types()

    def iter_esil(self) -> Iterator[str]:
        """Yield ESIL operation tokens."""
        for block in self.blocks:
            yield from block.iter_esil()

    def iter_type_esil(self) -> Iterator[tuple[EsilTokenType, str]]:
        """Yield categorised ESIL operation tokens."""
        for esil_token in self.iter_esil():
            esil_type = get_esil_type(esil_token)
            if esil_type is None:
                logger.debug("Skipping empty ESIL instruction.")
                continue
            yield esil_type, esil_token


# endregion CFG

# region ZIGNATURE


@dataclass(frozen=True, slots=True)
class FunctionZignatureData:
    addr: int
    name: str
    pic_hash: str
    pic_pattern: str

    cyclomatic_comp: int
    n_blocks: int
    n_edges: int
    n_entry_blocks: int

    arg_types: tuple[str, ...]
    local_types: tuple[str, ...]
    out_calls: tuple[str, ...]
    in_calls: tuple[str, ...]

    @staticmethod
    def get_pic_pattern(zig_bytes: str, zig_mask: str) -> HexStr:
        """Return position-independent code (PIC) signature pattern.

        Uses radare2 Zignature pair: first 500 bytes + mask.
        Return position-independent code signature using logic AND
        between `zig_bytes` and `zig_mask`.
        """
        return HexStr(zig_bytes) & HexStr(zig_mask)

    @classmethod
    def from_info(cls, zig_info: R2Zignature) -> Self | None:
        try:
            # Compute PIC pattern and hash
            pic_pattern = cls.get_pic_pattern(
                zig_info["bytes"], zig_info["mask"]
            )
            pic_hash = HexStr(
                blake2b(bytes(pic_pattern), digest_size=8).hexdigest()
            )
            # Process variables
            arg_types = []
            local_types = []
            for var_info in zig_info["vars"]:
                if var_info["isarg"]:
                    arg_types.append(var_info["type"])
                else:
                    local_types.append(var_info["type"])

            # Process function references
            # refs are calls toward other functions
            # xrefs are calls coming from other functions
            in_calls = tuple(
                normalise_func_name(xref) for xref in zig_info["xrefs"]
            )
            out_calls = tuple(
                normalise_func_name(ref) for ref in zig_info["refs"]
            )

            return cls(
                addr=get_addr(zig_info),
                name=zig_info["name"],
                pic_hash=pic_hash,
                pic_pattern=pic_pattern,
                cyclomatic_comp=zig_info["graph"]["cc"],
                n_blocks=zig_info["graph"]["nbbs"],
                n_edges=zig_info["graph"]["edges"],
                n_entry_blocks=zig_info["graph"]["ebbs"],
                arg_types=tuple(arg_types),
                local_types=tuple(local_types),
                in_calls=in_calls,
                out_calls=out_calls,
            )

        except KeyError:
            return None


# endregion ZIGNATURE


@dataclass(slots=True)
class BinaryDataManager:
    """Manage multiple function data types for one binary file."""

    # Function index keeps all addresses that
    # have been inserted in at least one dictionary.
    # Assume this list is sorted at all times.
    func_index: list[int] = field(default_factory=list)
    n_funcs: int = 0

    # Many-to-one lookup for functions name-address relationship.
    func_addr_lookup: dict[str, int] = field(default_factory=dict)

    # All names including functions and external imports (e.g. APIs).
    name_symbols: set[str] = field(default_factory=set)

    # Call references by each function, including external imports.
    # Key and value tuple-elements are normalised function names.
    func_imports: dict[str, tuple[str, ...]] = field(default_factory=dict)

    # Data dictionaries use function addresses as key
    func_cfgs: dict[int, FunctionCodeData] = field(default_factory=dict)
    func_zigs: dict[int, FunctionZignatureData] = field(default_factory=dict)
    # TODO: other r2 data types (bytes, info, etc)

    def register_func_addr(self, func_addr: int) -> int:
        """Add this address to the index if not already there.

        Keeps the index sorted and updates the function count.

        Returns the index of the new inserted element.
        """
        index = bisect.bisect_left(self.func_index, func_addr)
        if index == self.n_funcs or self.func_index[index] != func_addr:
            self.func_index.insert(index, func_addr)
            self.n_funcs += 1
        return index

    def register_func_name(self, func_addr: int, func_name: str) -> None:
        """Add this function name to the list if not already there."""
        if re.match(r"fcn\.[0-9a-f]+", func_name):
            # Exit early if name is just address placeholder
            return
        if func_name not in self.func_addr_lookup:
            # Register both the raw and the normalised name
            self.func_addr_lookup[func_name] = func_addr

            # NOTE: There is a potential risk of overwriting if two
            #       different raw names normalise to equal names.
            #       This risk is likely negligible.
            normalised_name = normalise_func_name(func_name)
            self.func_addr_lookup[normalised_name] = func_addr
            self.name_symbols.add(normalised_name)

    def get_func_addr(self, func_name: str) -> int:
        """Return address from function name.

        If address is not found return -1.
        """
        addr_match = re.match(r"fcn\.([0-9a-f]+)", func_name)
        if addr_match:
            # If name is just address placeholder
            # retrieve the function address from it
            return HexInt(addr_match.group(1))
        return self.func_addr_lookup.get(func_name, -1)

    def register_cfg_data(self, cfg_path: Path) -> int:
        """Register all functions CFG data in binary.

        Returns the amount of registered CFGs.
        """

        def _iterate_cfg() -> Iterator[R2CodeInfo]:
            with open(cfg_path, "r") as cfg_file:
                cfg_list: Bin2MlCfg = json.load(cfg_file)
            for (cfg,) in cfg_list:
                yield cfg

        def _iterate_func_cfg() -> Iterator[R2CodeInfo]:
            jsonl_streamer = JsonlDataParser(cfg_path)
            for cfg, _ in jsonl_streamer.stream():
                yield cfg

        n_registered = 0
        func_cfgs: Iterator[R2CodeInfo]
        if cfg_path.name.endswith("func-cfg.jsonl"):
            func_cfgs = _iterate_func_cfg()
        else:
            func_cfgs = _iterate_cfg()

        for cfg in func_cfgs:
            func_addr = get_addr(cfg)
            if func_addr is None:
                # This should never happen
                logger.warning("Couldn't locate CFG address.")
                continue
            data = FunctionCodeData.from_info(cfg)
            if data is None:
                logger.warning("Couldn't create FunctionZignature.")
                continue
            self.func_cfgs[func_addr] = data
            self.register_func_addr(func_addr)
            self.register_func_name(func_addr, cfg["name"])
            n_registered += 1

        return n_registered

    def register_zig_data(self, zig_path: Path) -> int:
        """Register all zignatures data in binary.

        Returns the amount of registered zignatures.
        """
        with open(zig_path, "r") as zig_file:
            # We expect a list of R2Zignature dictionaries
            zigs: list[R2Zignature] = json.load(zig_file)

        n_registered = 0
        for zig in zigs:
            func_addr = get_addr(zig)
            if func_addr is None:
                # This should never happen
                logger.warning("Couldn't locate zignature address.")
                continue
            data = FunctionZignatureData.from_info(zig)
            if data is None:
                logger.warning("Couldn't create FunctionZignatureData.")
                continue
            self.func_zigs[func_addr] = data
            self.register_func_addr(func_addr)
            self.register_func_name(func_addr, zig["name"])
            n_registered += 1
        return n_registered

    def register_cg_data(self, cg_path: Path) -> int:
        """Register all function call graph references.

        This one is trickier because radare2 doesn't give us addresses.
        Also, the radare2's CG data includes references to external
        API functions not included in the other data types.

        Functions won't be registered in `func_index` but they will be
        included in the `name_symbols` set.
        """
        with open(cg_path, "r") as cg_file:
            cg: R2CallGraph = json.load(cg_file)

        n_registered = 0
        for cg_node in cg:
            func_name = normalise_func_name(cg_node["name"])
            outputs = tuple(
                normalise_func_name(out_name)
                for out_name in cg_node["imports"]
            )
            self.func_imports[func_name] = outputs
            self.name_symbols.add(func_name)
            self.name_symbols.update(outputs)
            n_registered += 1

        return n_registered


FILES_PATTERNS = {
    "cfg": "{}_cfg.json",
    "func-cfg": "{}_func-cfg.jsonl",
    "zig": "{}_zigs.json",
    "cg": "{}_cg.json",
}


def get_data_manager(
    binary_name: str, raw_data_dir: Path
) -> BinaryDataManager:

    def get_path(data_type: str) -> Path:
        return raw_data_dir / FILES_PATTERNS[data_type].format(binary_name)

    def get_cfg_path() -> Path:
        _cfg_file_path = get_path("cfg")
        if _cfg_file_path.is_file():
            return _cfg_file_path
        return get_path("func-cfg")

    cfg_path = get_cfg_path()
    zig_path = get_path("zig")
    cg_path = get_path("cg")
    data_manager = BinaryDataManager()
    data_manager.register_cfg_data(cfg_path)
    data_manager.register_zig_data(zig_path)
    data_manager.register_cg_data(cg_path)
    return data_manager
