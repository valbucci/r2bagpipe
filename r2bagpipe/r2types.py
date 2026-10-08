"""TypedDict schemas for radare2-extracted binary analysis data."""

from typing import Literal, NotRequired, TypedDict, Union

from hexio import HexOffset

JSONPrimitive = None | bool | int | float | str
JSONArray = list["JSONType"]
JSONObject = dict[str, "JSONType"]
JSONType = JSONPrimitive | JSONArray | JSONObject


# region BINARY STRUCTURE
# Basic blocks graph relationships (CFG edges and numeric index)
BlockOffset = HexOffset
BlockEdges = dict[BlockOffset, list[BlockOffset]]  # basic block -> next blocks
BlockIndexes = dict[BlockOffset, str]  # basic block -> index in CFG

# Function graph relationships (Call graph edges and numeric index)
FunctionOffset = HexOffset
FunctionName = str
FunctionEdges = dict[
    FunctionName, list[FunctionName]
]  # function name -> called functions
FunctionIndexes = dict[
    FunctionName, str
]  # function name -> index in call graph
# endregion BINARY STRUCTURE


Bin2MlCfg = list[list["R2CodeInfo"]]  # agfj @@f
HasAddr = Union["R2CodeInfo", "R2Zignature", "R2FunctionInfo"]


# region RADARE2 FUNCTIONS


# Function Info (afij)
class R2FunctionInfo(TypedDict, total=True):
    """Output of `afij`."""

    addr: int
    name: str
    ninstrs: int
    nbbs: int
    indegree: int
    outdegree: int
    cc: int
    stackframe: int
    size: int
    nlocals: int
    nargs: int


# Function Vars (afvj)
class R2VarInfo(TypedDict, total=False):
    """Output of `afvj` (key: 'regs' / 'sp' / 'bp')."""

    kind: str
    type: str
    # Other attributes not used


class R2FunctionVars(TypedDict, total=True):
    """Output of `afvj`."""

    reg: list[R2VarInfo]  # Register-based variables
    sp: list[R2VarInfo]  # Stack Pointer-based variables
    bp: list[R2VarInfo]  # Base Pointer-based variables


# Code Info (agfj)
class R2OpcodeInfoReference(TypedDict, total=True):
    """Output of agfj (key: 'ops' > 'refs' / 'xrefs')."""

    addr: int
    perm: Literal["r--", "-w-", "--x"]
    type: Literal["DATA", "CODE", "CALL", "STRN", "ICOD"]  # Could be more (?)


class R2OpcodeInfo(TypedDict, total=True):
    """Output of `agfj` (key: 'ops')."""

    addr: int
    size: int
    type: str

    bytes: str
    family: str
    disasm: str  # disassembly
    opcode: str  # pseudo-assembly
    esil: str

    jump: NotRequired[int]  # radare2 <6.0.0
    fail: NotRequired[int]  # radare2 <6.0.0
    ptr: NotRequired[int | None]
    refs: NotRequired[list[R2OpcodeInfoReference] | None]  # radare2 >=6.0.0
    xrefs: NotRequired[list[R2OpcodeInfoReference] | None]  # radare2 >=6.0.0
    # Other attributes not used


class R2BlockInfo(TypedDict, total=True):
    """Output of `agfj` (key: 'blocks')."""

    addr: int
    size: int
    jump: NotRequired[int | None]
    fail: NotRequired[int | None]
    ops: list[R2OpcodeInfo]


class R2CodeInfo(TypedDict, total=True):
    """Output of `agfj`."""

    addr: int
    name: str
    nargs: int
    ninstr: int
    nlocals: int
    offset: int
    size: int
    stack: int
    type: str
    blocks: list[R2BlockInfo]


# Function Calls (agCj)
class R2FunctionCalls(TypedDict, total=True):
    """Output of `agCj` (array members)."""

    name: str
    size: int
    imports: list[str]


R2CallGraph = list[R2FunctionCalls]  # agCj
R2FunctionList = list[R2FunctionInfo]  # aflj
# endregion RADARE2 FUNCTIONS


# region RADARE2 ZIGNATURES
class R2GraphZignature(TypedDict, total=True):
    """Output of `zj` (key: 'graph')."""

    bbsum: int  # basic blocks checksum (?)
    cc: int  # cyclomatic complexity
    ebbs: int  # number of entry basic blocks
    edges: int
    nbbs: int  # number of basic blocks


class R2HashZignature(TypedDict, total=True):
    """Output of `zj` (key: 'hash')."""

    bbhash: str  # basic blocks hash


class R2VarsZignature(TypedDict, total=True):
    """Output of `zj` (key: 'vars' > array members)."""

    delta: int  # location difference with function address
    isarg: bool
    kind: str  # registry kind
    name: str
    type: str


class R2Zignature(TypedDict, total=True):
    """Output of `zj` (array members)."""

    addr: int
    name: str
    next: str  # following function name in binary
    types: str
    bytes: str
    mask: str
    collisions: list[str]  # colliding function names
    refs: list[str]  # output functions
    xrefs: list[str]  # input functions
    graph: R2GraphZignature
    hash: R2HashZignature
    vars: list[R2VarsZignature]


# endregion RADARE2 ZIGNATURES


# region RADARE2 BINARY INFO
class R2BinInfoCore(TypedDict, total=True):
    """Output of `ij` (key: 'core')."""

    block: int
    fd: int
    file: str
    format: str
    type: str
    iorw: bool
    mode: str
    humansz: str
    size: int


"""Output of `ij` (key: 'bin')."""
# NOTE: functional syntax required to preserved exact radare2 keys
#       -- e.g. "cmp.sum"
R2BinInfoBin = TypedDict(
    "R2BinInfoBin",
    {  # ij (bin entry)
        "arch": str,
        "baddr": int | None,
        "binsz": int,
        "bintype": str,
        "bits": int,
        "canary": bool,
        "cc": str,
        "checksums": dict[str, str],
        "class": str,
        "cmp.sum": str | None,
        "compiled": str,
        "compiler": str,
        "crypto": bool,
        "dbg_file": str,
        "endian": str,
        "guid": str,
        "havecode": bool,
        "hdr.csum": int | None,
        "injprot": bool,
        "intrp": str,
        "laddr": int,
        "lang": str | None,
        "linenum": bool,
        "lsyms": bool,
        "machine": str,
        "nx": bool,
        "os": str,
        "overlay": bool | None,
        "pic": bool,
        "relocs": bool,
        "retguard": bool | None,
        "rpath": str,
        "sanitize": bool,
        "signed": bool | None,
        "static": bool,
        "stripped": bool,
        "subsys": str,
        "va": bool,
    },
)


class R2ChecksumsEntry(TypedDict, total=True):
    """Output of `ij` (key: 'checksums')."""

    md5: str
    sha1: str
    sha256: str


class R2BinInfo(TypedDict, total=True):
    """Output of `ij`."""

    core: R2BinInfoCore
    bin: R2BinInfoBin | None
    checksums: R2ChecksumsEntry


# endregion RADARE2 BINARY INFO
