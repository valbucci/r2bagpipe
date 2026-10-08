"""Load and parse radare2 data that was cached with Bin2ML."""

import csv
import json
import logging
import re
import tarfile
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path, PurePosixPath
from typing import Any, Self

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class DataParserError(RuntimeError):
    """Raised when error is encountered by a data parser."""


class BaseDataParser(ABC):
    """A generic data parser.

    It must be extended by implementing the private method `_stream`.
    A data parser reads a single data file and streams data items with
    iterator fashion
    -- using `yield` and without loading the whole file in memory.

    Example:
        >>> parser = DataParser("path/to/data_file")
        >>> try:
        ...     for data_item in parser.stream():
        ...         print(data_item)
        ... except DataParserError:
        ...     pass

    """

    def __init__(
        self, file_path: Path, propagate_exceptions: bool = True
    ) -> None:
        self.file_path = file_path
        self._file_handle = None
        self._logger = logger.getChild(f"{self._classname}({self.file_name})")
        self._had_error = False
        self._propagate_exceptions = propagate_exceptions

    def __repr__(self) -> str:
        return f'{self._classname}("{self.file_path.absolute().as_posix()}")'

    @property
    def _classname(self) -> str:
        return self.__class__.__name__

    @property
    def file_name(self) -> str:
        return self.file_path.name

    @property
    def ok(self) -> bool:
        return not self._had_error and self._file_handle is not None

    @property
    def file_handle(self) -> Any:
        if self._file_handle is None:
            raise RuntimeError("Accessed uninitialized file handle")
        return self._file_handle

    def _teardown(self) -> None:
        self._logger.debug("Closing file handle")
        if self._file_handle is not None:
            try:
                self.file_handle.close()
            except OSError:
                self._logger.exception("Failed to close file handle")
            finally:
                self._file_handle = None

    def __enter__(self) -> Self:
        try:
            self._file_handle = open(self.file_path, "r")
        except Exception as e:
            self._had_error = True
            self._teardown()
            self._logger.exception("Failed to open file")
            if self._propagate_exceptions:
                raise DataParserError from e
        return self

    def __exit__(
        self, exception_type, exception_value, exception_traceback
    ) -> bool:
        self._teardown()
        if exception_type is not None:
            self._had_error = True
            if self._propagate_exceptions:
                self._logger.error("Exiting due to exception")
                return False
            else:
                self._logger.exception("Exiting due to exception")
                return True  # Suppress exception
        return True

    @abstractmethod
    def _stream(self, *args: Any, **kwargs: Any) -> Iterator[Any]: ...

    def stream(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        try:
            with self:
                if not self.ok:
                    self._logger.error(
                        "Stream aborted: file handle not available."
                    )
                    yield from ()
                    return

                yield from self._stream(*args, **kwargs)

        except Exception as e:
            self._had_error = True
            self._logger.exception("Unexpected error while streaming")
            if self._propagate_exceptions:
                raise DataParserError from e
            else:
                self._logger.debug("Swallowed exception; closing stream.")
            return


class JsonlDataParser(BaseDataParser):
    def __init__(
        self,
        file_path: Path,
        encoding: str = "utf-8",
        errors: str = "strict",
        propagate_exceptions: bool = True,
    ) -> None:
        super().__init__(file_path, propagate_exceptions)
        self.encoding = encoding
        self.errors = errors

    def __enter__(self) -> Self:
        try:
            self._file_handle = open(
                self.file_path,
                "r",
                encoding=self.encoding,
                errors=self.errors,
                newline="",
            )
        except Exception as e:
            self._had_error = True
            self._teardown()
            self._logger.exception("Failed to open file")
            if self._propagate_exceptions:
                raise DataParserError from e
        return self

    def _stream(
        self, start_line: int = 1, lazy: bool = False
    ) -> Iterator[tuple[dict, str]]:
        current_line = 0
        while True:
            try:
                line = self.file_handle.readline()
            except UnicodeDecodeError as e:
                self._had_error = True
                self._logger.exception(
                    f"Bad UTF-8 while reading line {current_line}. Skipping."
                )
                current_line += 1
                if self.errors == "strict":
                    self._logger.error(
                        "Propagating UnicodeDecodeError as "
                        "cannot recover with strict error mode"
                    )
                    raise DataParserError from e
                continue

            if not line:  # EOF reached
                self._logger.info("Reached end of file; closing stream.")
                return

            current_line += 1
            if current_line < start_line:
                continue

            try:
                line_str = line.strip()
                if lazy:
                    # Parse JSON line faster with regexes
                    # 1. Skip if not a function or symbol line
                    if not re.search(r'"type"\s*:\s*"(fcn|sym)"', line_str):
                        continue

                    # 2. Strip out all arrays (blocks, xrefs, etc.) to leave only root-level scalar metadata
                    # Greedy .* ensures we swallow all nested block data.
                    metadata_str = re.sub(r"\[.*\]", "", line_str)

                    # 3. Now, the ONLY offset left is the root-level one
                    addr_match = re.search(
                        r'"(?:offset|addr)"\s*:\s*(\d+)', metadata_str
                    )
                    if not addr_match:
                        continue

                    target_offset = int(addr_match.group(1))
                    size_match = re.search(r'"size"\s*:\s*(\d+)', metadata_str)
                    target_size = int(size_match.group(1)) if size_match else 0

                    mini_dict = {"offset": target_offset, "size": target_size}
                    yield mini_dict, line_str
                else:
                    parsed = json.loads(line_str)
                    if "offset" not in parsed and "addr" not in parsed:
                        continue  # Must have an address identifier
                    if parsed.get("type") not in ("fcn", "sym", None):
                        continue  # Skip non-function data
                    yield parsed, line_str
            except Exception:
                self._had_error = True
                self._logger.exception(
                    f"Unexpected error on line {current_line}. Skipping."
                )


class TarDataParser(BaseDataParser):
    INDEX_PREFIX = "00-func-index"

    def __init__(
        self,
        archive_path: Path,
        index_path: Path | None,
        propagate_exceptions: bool = True,
    ) -> None:
        super().__init__(archive_path, propagate_exceptions)
        self.index_path = index_path
        self._file_metadata_index: dict[str, tuple[int, str]] = {}
        self._is_setup = False

    @property
    def is_index_ok(self) -> bool:
        return self._is_setup and not self._had_error

    @property
    def metadata_index(self) -> dict[str, tuple[int, str]]:
        if not self._is_setup:
            raise RuntimeError("Cannot access metadata index before setup")

        return self._file_metadata_index

    def setup_index(self) -> Self:
        if self._is_setup:
            self._logger.debug("Index already setup, skipping setup")
            return self

        content_lines = []
        if self.index_path is None or not self.index_path.is_file():
            # SELF-CONTAINED
            # The index is contained in the TAR
            # and its name begins with 00-func-index
            self._logger.info(f"Extracting index file from {self.file_path}")
            with tarfile.open(self.file_path, "r:*") as temp_tar:
                # Different file types will have different data indices
                index_members = []
                for member in temp_tar.getmembers():
                    if member.name.startswith(self.INDEX_PREFIX):
                        index_members.append(member)

                if len(index_members) == 0:
                    raise FileNotFoundError(
                        f"Index file {self.index_path} does not exist,"
                        f" and no file with prefix {self.INDEX_PREFIX} was"
                        f" found in {self.file_path}."
                    )
                csv_header = ""
                for index_member in index_members:
                    with temp_tar.extractfile(index_member) as f:  # type: ignore
                        lines = f.read().decode("utf-8").splitlines()
                        # Get rid of header
                        csv_header = lines[0]
                        content_lines.extend(lines[1:])
                # Add the header back
                content_lines = [csv_header] + content_lines

        elif self.index_path.is_file():
            # SEPARATED
            # The index is uncompressed at the provided path
            if not self.index_path.as_posix().endswith(".csv"):
                self._logger.warning(
                    f"Index file {self.index_path} doesn't seem "
                    "to be a CSV file; proceeding anyway."
                )
            with open(self.index_path, "r", encoding="utf-8", newline="") as f:
                content_lines.extend(f.readlines())
        else:
            # SIBLING
            # The index has the base name of index_path but is placed
            # alongside the TAR file_path
            sibling_path = self.file_path.parent / self.index_path.name
            if sibling_path.is_file() and sibling_path != self.index_path:
                self._logger.info(
                    f"Index file not found at {self.index_path}; "
                    f"using sibling file {sibling_path}"
                )
                with open(
                    sibling_path, "r", encoding="utf-8", newline=""
                ) as f:
                    content_lines = f.readlines()

        reader = csv.DictReader(content_lines)
        for row in reader:
            try:
                func_path = Path(row["output_path"])
                func_file_name = func_path.name
                func_address = int(row["address"])
                func_name = row["name"]
            except KeyError:
                self._logger.exception("Missing key in index file")
                self._logger.debug(f"Row: {row}")
                continue
            except Exception:
                self._logger.exception("Error processing row")
                self._logger.debug(f"Row: {row}")
                continue
            else:
                self._file_metadata_index[func_file_name] = (
                    func_address,
                    func_name,
                )

        self._is_setup = True
        self._logger.info(
            "Index setup complete (%d entries)", len(self._file_metadata_index)
        )

        return self

    def __enter__(self) -> Self:
        try:
            self.setup_index()
            self._file_handle = tarfile.open(self.file_path, "r:*")

        except FileNotFoundError as e:
            self._had_error = True
            error_msg = f"Archive file not found: {self.file_path}"
            if self._propagate_exceptions:
                self._logger.error(error_msg)
                raise RuntimeError(error_msg) from e
            else:
                self._logger.exception(error_msg)

        except tarfile.ReadError as e:
            self._had_error = True
            error_msg = f"Could not read tar file: {self.file_path}"
            if self._propagate_exceptions:
                raise RuntimeError(error_msg) from e
            else:
                self._logger.exception(error_msg)

        except Exception as e:
            self._had_error = True
            error_msg = (
                f"Unexpected error while opening file: {self.file_path}"
            )
            if self._propagate_exceptions:
                self._logger.error(error_msg)
                raise RuntimeError(error_msg) from e
            else:
                self._logger.exception(error_msg)

        # Validate setup was successful before allowing streaming
        if not self._is_setup:
            self._had_error = True
            error_msg = "Index setup failed or was not completed"
            if self._propagate_exceptions:
                raise RuntimeError(error_msg)
            else:
                self._logger.exception(error_msg)

        return self

    def _stream(self) -> Iterator[tuple[int, str, str, bytes]]:
        """Stream data items directly from the TAR in memory.

        Yields (address, name, member_name, content_bytes) for each
        file listed in the TAR's index CSV without extraction to disk.
        """
        # Track expected files from CSV index vs streamed from archive
        needed = set(self.metadata_index.keys())
        streamed: set[str] = set()

        stream_count = 0
        while True:
            member = self.file_handle.next()
            if member is None:
                self._logger.info(
                    "No more members in archive; closing stream."
                )
                break

            if not member.isfile():
                self._logger.debug(f"Skipping non-file member: {member.name}")
                continue

            stream_count += 1
            member_path = PurePosixPath(member.name)
            member_name = member_path.name
            if member_name not in needed:
                self._logger.debug(f"Skipping non-needed file {member_path}")
                continue

            if member_name in streamed:
                self._logger.warning(
                    f"Duplicate member {member_name} found in archive. "
                    f"Skipping subsequent occurrence {member_path} ..."
                )
                continue

            try:
                func_address, func_name = self.metadata_index[member_name]
                with self.file_handle.extractfile(member) as fobj:
                    if fobj is None:
                        raise OSError("extractfile returned None")
                    content = fobj.read()

                yield func_address, func_name, member_name, content

            except KeyError:
                # This should never happen, as we checked for existence above
                self._logger.error(f"File {member_name} not found in index")
                continue

            except Exception:
                self._had_error = True
                self._logger.exception(
                    f"Unexpected error extracting file {member_path}. Skipping."
                )
                continue

            streamed.add(member_name)
            if len(streamed) == len(needed):
                # No need to keep iterating, we have everything from the index
                self._logger.info("All expected files found in archive")
                return

        # Report any missing entries
        missing = needed - streamed
        if len(missing) > 0:
            if stream_count > 0:
                self._had_error = True
                self._logger.warning(
                    f"Missing {len(missing)} files from index."
                )
                for m in missing:
                    self._logger.debug(f'File "{m}" in index but not streamed')
            else:
                self._logger.warning("The archive is empty.")
