"""Test data loading and streaming capabilities."""

from pathlib import Path

from r2bagpipe.data import get_data_manager
from r2bagpipe.loader import get_data_loader

SAMPLES_PATH = Path(__file__).parent / "samples"
BINARIES_PATH = SAMPLES_PATH / "binaries"
RAW_DATA_PATH = SAMPLES_PATH / "raw_data"
BINARY_NAME = "vlc_3-0-20"
BINARY_PATH = BINARIES_PATH / BINARY_NAME


def test_paths():
    assert SAMPLES_PATH.is_dir()
    assert BINARIES_PATH.is_dir()
    assert RAW_DATA_PATH.is_dir()
    assert BINARY_PATH.is_file()


class TestBinaryDataManager:
    def test_data_manager(self):
        manager = get_data_manager(BINARY_PATH.name, RAW_DATA_PATH)
        assert manager.parent_dir == "samples"
        assert manager.format == "ELF"
        # arch family is x86 even though x64 would be arch+bitness
        assert manager.arch == "x86"
        assert manager.bitness == 64
        assert manager.bin_class == "ELF64"
        assert manager.arch_class == "x64"

        assert manager.n_funcs > 0
        assert manager.func_cfgs.keys() == manager.func_zigs.keys()


class TestBinaryDataLoader:
    def test_loader(self):
        loader = get_data_loader(BINARY_PATH, RAW_DATA_PATH)
        loader.setup()

        assert loader._is_setup
        assert len(loader.data_entries) > 0
        assert loader.callgraph is not None

        for address, function_data in loader.data_entries.items():
            assert address is not None
            assert function_data is not None

            assert function_data.cfg is not None
            assert function_data.finfo is not None
            assert function_data.zignature is not None
            assert function_data.fbytes_raw is not None
            assert function_data.fbytes_nibblemask is not None
            assert function_data.fbytes_bitmask is not None
