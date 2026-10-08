"""Test data loading and streaming capabilities."""

from pathlib import Path

from r2bagpipe.loader import get_data_loader

SAMPLES_PATH = Path(__file__).parent / "samples"
BINARIES_PATH = SAMPLES_PATH / "binaries"
RAW_DATA_PATH = SAMPLES_PATH / "raw_data"
BINARY_NAME = "vlc_3-0-20"
BINARY_PATH = BINARIES_PATH / BINARY_NAME


class TestBinaryDataLoader:
    def test_paths(self):
        assert SAMPLES_PATH.is_dir()
        assert BINARIES_PATH.is_dir()
        assert RAW_DATA_PATH.is_dir()
        assert BINARY_PATH.is_file()

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
