"""Expose data loader and radare2 types."""

# Export loader
from .loader import BinaryDataLoader as BinaryDataLoader
from .loader import get_data_loader as get_data_loader

# Export types
from .r2types import Bin2MlCfg as Bin2MlCfg
from .r2types import HasAddr as HasAddr
from .r2types import R2BinInfo as R2BinInfo
from .r2types import R2CallGraph as R2CallGraph
from .r2types import R2CodeInfo as R2CodeInfo
from .r2types import R2FunctionInfo as R2FunctionInfo
from .r2types import R2Zignature as R2Zignature

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
    return addr is not None and addr != PLACEHOLDER_ADDR


def filter_placeholder_addr(addr: int | None) -> int | None:
    """Parse placeholder address as None."""
    if addr != PLACEHOLDER_ADDR:
        return addr
    else:
        return None


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


# endregion UTILITIES
