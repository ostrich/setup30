#!/usr/bin/env python3
"""Extract old InstallShield 3-era .Z/_SETUP.LIB archives.

These archives are not plain Unix .Z files. They contain a small footer table
plus per-file TTCOMP-compressed members. This tool parses the table and expands
those TTCOMP members directly in Python.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import zipfile
from pathlib import Path

NAME_PATTERN = re.compile(rb"[A-Za-z0-9_.\\-]{4,}\x00")
ARCHIVE_SUFFIXES = {".z", ".lib"}
MULTIPART_SUFFIX = re.compile(r"\.(\d+)$")
IMPLODE_BINARY = 0
IMPLODE_ASCII = 1
IMPLODE_DICT_SIZES = {4: 1024, 5: 2048, 6: 4096}

CH_CODE = [1168, 4064, 2016, 3040, 992, 3552, 1504, 2528, 480, 184, 98, 3808, 1760, 34, 2784, 736, 3296, 1248, 2272, 224, 3936, 1888, 2912, 864, 3424, 1376, 4672, 2400, 352, 3680, 1632, 2656, 15, 592, 56, 608, 80, 3168, 912, 216, 66, 2, 88, 432, 124, 41, 60, 152, 92, 9, 28, 108, 44, 76, 24, 12, 116, 232, 104, 1120, 144, 52, 176, 1808, 2144, 49, 84, 17, 33, 23, 20, 168, 40, 1, 784, 304, 62, 100, 30, 46, 36, 1296, 14, 54, 22, 68, 48, 200, 464, 208, 272, 72, 1552, 336, 96, 136, 4000, 7, 38, 6, 58, 27, 26, 42, 10, 11, 528, 4, 19, 50, 3, 29, 18, 400, 13, 21, 5, 25, 8, 120, 240, 112, 656, 1040, 16, 1952, 2976, 928, 576, 7232, 3136, 5184, 1088, 6208, 2112, 4160, 64, 8064, 3968, 6016, 1920, 7040, 2944, 4992, 896, 7552, 3456, 5504, 1408, 6528, 2432, 4480, 384, 7808, 3712, 5760, 1664, 6784, 2688, 4736, 640, 7296, 3200, 5248, 1152, 6272, 2176, 4224, 128, 7936, 3840, 5888, 1792, 6912, 2816, 4864, 3488, 1440, 2464, 416, 3744, 1696, 2720, 672, 3232, 1184, 2208, 160, 3872, 1824, 2848, 800, 3360, 1312, 2336, 288, 3616, 1568, 2592, 544, 3104, 1056, 2080, 32, 4032, 1984, 3008, 960, 3520, 1472, 2496, 448, 3776, 1728, 2752, 704, 3264, 1216, 2240, 192, 3904, 1856, 2880, 832, 768, 3392, 7424, 3328, 5376, 1344, 1280, 6400, 2304, 2368, 4352, 256, 7680, 3584, 320, 5632, 1536, 6656, 3648, 1600, 2624, 2560, 4608, 512, 7168, 3072, 5120, 1024, 6144, 2048, 4096, 0]
CH_BITS = [11, 12, 12, 12, 12, 12, 12, 12, 12, 8, 7, 12, 12, 7, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 12, 12, 12, 12, 12, 4, 10, 8, 12, 10, 12, 10, 8, 7, 7, 8, 9, 7, 6, 7, 8, 7, 6, 7, 7, 7, 7, 8, 7, 7, 8, 8, 12, 11, 7, 9, 11, 12, 6, 7, 6, 6, 5, 7, 8, 8, 6, 11, 9, 6, 7, 6, 6, 7, 11, 6, 6, 6, 7, 9, 8, 9, 9, 11, 8, 11, 9, 12, 8, 12, 5, 6, 6, 6, 5, 6, 6, 6, 5, 11, 7, 5, 6, 5, 5, 6, 10, 5, 5, 5, 5, 8, 7, 8, 8, 10, 11, 11, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 13, 12, 13, 13, 13, 12, 13, 13, 13, 12, 13, 13, 13, 13, 12, 13, 13, 13, 12, 12, 12, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13]
LEN_CODE = [5, 3, 1, 6, 10, 2, 12, 20, 4, 24, 8, 48, 16, 32, 64, 0]
LEN_BITS = [3, 2, 3, 3, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 7, 7]
LEN_BASE = [2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
EXLEN_BITS = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]
OFFS_CODE = [3, 13, 5, 25, 9, 17, 1, 62, 30, 46, 14, 54, 22, 38, 6, 58, 26, 42, 10, 50, 18, 34, 66, 2, 124, 60, 92, 28, 108, 44, 76, 12, 116, 52, 84, 20, 100, 36, 68, 4, 120, 56, 88, 24, 104, 40, 72, 8, 240, 112, 176, 48, 208, 80, 144, 16, 224, 96, 160, 32, 192, 64, 128, 0]
OFFS_BITS = [2, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]

ASCII_LOOKUP: dict[int, dict[int, int]] = {}
for i, (bits, code) in enumerate(zip(CH_BITS, CH_CODE)):
    ASCII_LOOKUP.setdefault(bits, {})[code] = i
ASCII_TABLES = [ASCII_LOOKUP.get(bits, {}) for bits in range(max(CH_BITS) + 1)]
LEN_LOOKUP = [{code: i for i, (n_bits, code) in enumerate(zip(LEN_BITS, LEN_CODE)) if n_bits == bits} for bits in range(max(LEN_BITS) + 1)]
OFFS_LOOKUP = [{code: i for i, (n_bits, code) in enumerate(zip(OFFS_BITS, OFFS_CODE)) if n_bits == bits} for bits in range(max(OFFS_BITS) + 1)]


class TTCompError(ValueError):
    pass


def truncate_value(value: int, bits: int) -> int:
    return value & ((1 << bits) - 1)


def decode_table_index(bit_buf: int, lookup_tables: list[dict[int, int]]) -> int:
    for bit_len in range(len(lookup_tables)):
        if not lookup_tables[bit_len]:
            continue
        idx = lookup_tables[bit_len].get(truncate_value(bit_buf, bit_len))
        if idx is not None:
            return idx
    raise TTCompError("Unable to decode bitstream symbol")


def explode_ttcomp(data: bytes, expected_size: int | None = None) -> bytes:
    if len(data) < 4 or data[0] != 0x00 or data[1] not in IMPLODE_DICT_SIZES:
        raise TTCompError("Input does not look like a TTCOMP archive")

    type_ = data[0]
    dict_code = data[1]
    if type_ not in (IMPLODE_BINARY, IMPLODE_ASCII):
        raise TTCompError(f"Unsupported TTCOMP type: {type_}")

    dict_size = IMPLODE_DICT_SIZES[dict_code]
    dict_buf = bytearray(0x1000)
    dict_ptr = 0
    cur_dict_size = 0
    rd_ptr = 2
    if rd_ptr + 1 >= len(data):
        raise TTCompError("TTCOMP stream is truncated")
    bit_buf = data[rd_ptr] | (data[rd_ptr + 1] << 8)
    rd_ptr += 2
    bit_num = 16
    out = bytearray()

    while expected_size is None or len(out) < expected_size:
        while bit_num < 16:
            if rd_ptr >= len(data):
                raise TTCompError("Unexpected end of TTCOMP stream")
            bit_buf |= data[rd_ptr] << bit_num
            rd_ptr += 1
            bit_num += 8

        if bit_buf & 1:
            bit_buf >>= 1
            bit_num -= 1

            i = decode_table_index(bit_buf, LEN_LOOKUP)
            bit_buf >>= LEN_BITS[i]
            bit_num -= LEN_BITS[i]

            copy_len = LEN_BASE[i] + truncate_value(bit_buf, EXLEN_BITS[i])
            bit_buf >>= EXLEN_BITS[i]
            bit_num -= EXLEN_BITS[i]

            if copy_len == 519:
                break

            while bit_num < 14:
                if rd_ptr >= len(data):
                    raise TTCompError("Unexpected end of TTCOMP stream")
                bit_buf |= data[rd_ptr] << bit_num
                rd_ptr += 1
                bit_num += 8

            i = decode_table_index(bit_buf, OFFS_LOOKUP)
            bit_buf >>= OFFS_BITS[i]
            bit_num -= OFFS_BITS[i]

            if copy_len == 2:
                copy_off = dict_ptr - 1 - ((i << 2) + (bit_buf & 0x03))
                bit_buf >>= 2
                bit_num -= 2
            else:
                copy_off = dict_ptr - 1 - ((i << dict_code) + truncate_value(bit_buf, dict_code))
                bit_buf >>= dict_code
                bit_num -= dict_code

            for _ in range(copy_len):
                if cur_dict_size == 0:
                    raise TTCompError("Invalid copy from empty dictionary")
                while copy_off < 0:
                    copy_off += cur_dict_size
                while copy_off >= cur_dict_size:
                    copy_off -= cur_dict_size
                value = dict_buf[copy_off]
                copy_off += 1
                dict_buf[dict_ptr] = value
                dict_ptr = (dict_ptr + 1) % dict_size
                if cur_dict_size < dict_size:
                    cur_dict_size += 1
                out.append(value)
                if expected_size is not None and len(out) >= expected_size:
                    break
        else:
            if type_ == IMPLODE_BINARY:
                value = (bit_buf >> 1) & 0xFF
                bit_buf >>= 9
                bit_num -= 9
            else:
                bit_buf >>= 1
                bit_num -= 1
                value = decode_table_index(bit_buf, ASCII_TABLES)
                bit_buf >>= CH_BITS[value]
                bit_num -= CH_BITS[value]

            dict_buf[dict_ptr] = value
            dict_ptr = (dict_ptr + 1) % dict_size
            if cur_dict_size < dict_size:
                cur_dict_size += 1
            out.append(value)

    if expected_size is not None and len(out) != expected_size:
        raise TTCompError(f"Size mismatch after decompression: expected {expected_size}, got {len(out)}")
    return bytes(out)


def parse_entries(
    path: Path,
    scan_tail_bytes: int = 2048,
    require_local_data: bool = True,
) -> list[dict]:
    data = path.read_bytes()
    tail = data[-scan_tail_bytes:]
    entries: list[dict] = []
    seen: set[str] = set()

    for match in NAME_PATTERN.finditer(tail):
        name = match.group()[:-1].decode("ascii", "ignore")
        if "." not in name or name in seen:
            continue

        name_offset = len(data) - len(tail) + match.start()
        prefix = data[name_offset - 27 : name_offset]
        if len(prefix) != 27:
            continue

        uncompressed_size = int.from_bytes(prefix[0:4], "little")
        compressed_size = int.from_bytes(prefix[4:8], "little")
        data_offset = int.from_bytes(prefix[8:12], "little")
        crc_or_stamp = int.from_bytes(prefix[12:16], "little")
        flags_a = int.from_bytes(prefix[16:20], "little")
        flags_b = int.from_bytes(prefix[20:24], "little")
        dir_index = int.from_bytes(prefix[24:26], "little")
        name_len = prefix[26]

        if name_len != len(name):
            continue
        if require_local_data and data_offset + compressed_size > len(data):
            continue

        entries.append(
            {
                "name": name,
                "name_offset": name_offset,
                "uncompressed_size": uncompressed_size,
                "compressed_size": compressed_size,
                "data_offset": data_offset,
                "crc_or_stamp": crc_or_stamp,
                "flags_a": flags_a,
                "flags_b": flags_b,
                "dir_index": dir_index,
            }
        )
        seen.add(name)

    entries.sort(key=lambda item: item["data_offset"])
    return entries


def is_ttcomp_header(blob: bytes) -> bool:
    return len(blob) >= 2 and blob[0] == 0x00 and blob[1] in IMPLODE_DICT_SIZES


def looks_like_pe_executable(path: Path) -> bool:
    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    return pe_offset + 4 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\0\0"


def multipart_group(path: Path) -> list[Path] | None:
    match = MULTIPART_SUFFIX.fullmatch(path.suffix.lower())
    if not match:
        return None

    base_name = path.name[: -len(path.suffix)]
    parts = []
    for sibling in sorted(path.parent.iterdir(), key=lambda item: item.name.lower()):
        if not sibling.is_file():
            continue
        sibling_match = MULTIPART_SUFFIX.fullmatch(sibling.suffix.lower())
        if not sibling_match:
            continue
        sibling_base = sibling.name[: -len(sibling.suffix)]
        if sibling_base.lower() != base_name.lower():
            continue
        parts.append((int(sibling_match.group(1)), sibling.resolve()))

    if len(parts) < 2:
        return None
    return [part for _, part in sorted(parts)]


def parse_pe_sections(data: bytes) -> tuple[int, list[dict]]:
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    num_sections = int.from_bytes(data[pe_offset + 6 : pe_offset + 8], "little")
    optional_header_size = int.from_bytes(data[pe_offset + 20 : pe_offset + 22], "little")
    magic = int.from_bytes(data[pe_offset + 24 : pe_offset + 26], "little")
    data_dir_offset = pe_offset + 24 + (96 if magic == 0x10B else 112)
    resource_rva = int.from_bytes(data[data_dir_offset + 16 : data_dir_offset + 20], "little")
    section_offset = pe_offset + 24 + optional_header_size
    sections = []
    for i in range(num_sections):
        off = section_offset + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode("ascii", "ignore")
        virtual_size = int.from_bytes(data[off + 8 : off + 12], "little")
        virtual_address = int.from_bytes(data[off + 12 : off + 16], "little")
        raw_size = int.from_bytes(data[off + 16 : off + 20], "little")
        raw_ptr = int.from_bytes(data[off + 20 : off + 24], "little")
        sections.append(
            {
                "name": name,
                "va": virtual_address,
                "size": max(virtual_size, raw_size),
                "raw_ptr": raw_ptr,
            }
        )
    return resource_rva, sections


def rva_to_offset(rva: int, sections: list[dict]) -> int:
    for section in sections:
        if section["va"] <= rva < section["va"] + section["size"]:
            return section["raw_ptr"] + (rva - section["va"])
    raise ValueError(f"RVA not mapped to a section: 0x{rva:x}")


def read_resource_name(data: bytes, base: int, value: int) -> str | int:
    if value & 0x80000000:
        name_offset = base + (value & 0x7FFFFFFF)
        name_len = int.from_bytes(data[name_offset : name_offset + 2], "little")
        raw = data[name_offset + 2 : name_offset + 2 + name_len * 2]
        return raw.decode("utf-16le")
    return value & 0xFFFF


def list_file_resources(installer_path: Path) -> list[dict]:
    data = installer_path.read_bytes()
    resource_rva, sections = parse_pe_sections(data)
    resource_base = rva_to_offset(resource_rva, sections)

    def read_u16(offset: int) -> int:
        return int.from_bytes(data[offset : offset + 2], "little")

    def read_u32(offset: int) -> int:
        return int.from_bytes(data[offset : offset + 4], "little")

    def walk_directory(rel_offset: int, path: tuple[object, ...]) -> list[tuple[tuple[object, ...], dict]]:
        directory_offset = resource_base + rel_offset
        num_named = read_u16(directory_offset + 12)
        num_id = read_u16(directory_offset + 14)
        entry_offset = directory_offset + 16
        nodes = []
        for i in range(num_named + num_id):
            name = read_resource_name(data, resource_base, read_u32(entry_offset + i * 8))
            child = read_u32(entry_offset + i * 8 + 4)
            is_dir = bool(child & 0x80000000)
            child_rel = child & 0x7FFFFFFF
            child_path = path + (name,)
            if is_dir:
                nodes.extend(walk_directory(child_rel, child_path))
                continue
            data_entry_offset = resource_base + child_rel
            rva = read_u32(data_entry_offset)
            size = read_u32(data_entry_offset + 4)
            codepage = read_u32(data_entry_offset + 8)
            nodes.append(
                (
                    child_path,
                    {
                        "rva": rva,
                        "size": size,
                        "codepage": codepage,
                        "file_offset": rva_to_offset(rva, sections),
                    },
                )
            )
        return nodes

    resources = []
    for path_tuple, entry in walk_directory(0, ()):
        if not path_tuple or path_tuple[0] != "FILE" or len(path_tuple) < 2:
            continue
        name = path_tuple[1]
        if not isinstance(name, str):
            continue
        resources.append(
            {
                "name": name,
                "size": entry["size"],
                "file_offset": entry["file_offset"],
                "codepage": entry["codepage"],
            }
        )
    return resources


def looks_like_pe_installshield_wrapper(path: Path) -> bool:
    if not looks_like_pe_executable(path):
        return False
    try:
        return bool(list_file_resources(path))
    except Exception:
        return False


def extract_file_resources(installer_path: Path, output_root: Path) -> dict:
    installer_out = output_root / installer_path.stem
    raw_dir = installer_out / "raw_file_resources"
    clean_dir = installer_out / "clean_file_resources"
    raw_dir.mkdir(parents=True, exist_ok=True)
    clean_dir.mkdir(parents=True, exist_ok=True)
    data = installer_path.read_bytes()

    resources = []
    for resource in sorted(list_file_resources(installer_path), key=lambda item: item["name"].lower()):
        raw_path = raw_dir / f"{installer_path.name}_FILE_{resource['name']}"
        blob = data[resource["file_offset"] : resource["file_offset"] + resource["size"]]
        raw_path.write_bytes(blob)
        clean_name = resource["name"]
        clean_path = clean_dir / clean_name
        clean_path.write_bytes(blob[4:] if len(blob) >= 4 else blob)
        resources.append(
            {
                "raw_path": str(raw_path.relative_to(output_root.parent)),
                "clean_path": str(clean_path.relative_to(output_root.parent)),
                "size": clean_path.stat().st_size,
            }
        )

    return {
        "installer": str(installer_path),
        "kind": "pe-file-resources",
        "resource_dir": str(installer_out.relative_to(output_root.parent)),
        "resources": resources,
    }


def looks_like_archive(path: Path) -> bool:
    if path.suffix.lower() in ARCHIVE_SUFFIXES:
        return bool(parse_entries(path))
    if MULTIPART_SUFFIX.fullmatch(path.suffix.lower()):
        return bool(parse_entries(path, require_local_data=False))
    return False


def collect_multipart_entries(parts: list[Path]) -> list[dict]:
    entries_by_name: dict[str, dict] = {}
    for part in parts:
        for entry in parse_entries(part, require_local_data=False):
            entries_by_name.setdefault(entry["name"], entry)
    return sorted(entries_by_name.values(), key=lambda item: (item["data_offset"], item["name"].lower()))


def read_member_blob_from_part(parts_data: list[bytes], entry: dict, start_part: int) -> bytes:
    remaining = entry["compressed_size"]
    current_offset = entry["data_offset"]
    chunks: list[bytes] = []
    for index in range(start_part, len(parts_data)):
        data = parts_data[index]
        if current_offset >= len(data):
            break
        take = min(remaining, len(data) - current_offset)
        chunks.append(data[current_offset : current_offset + take])
        remaining -= take
        if remaining == 0:
            break
        current_offset = 0

    blob = b"".join(chunks)
    if len(blob) != entry["compressed_size"]:
        raise TTCompError(
            f"Short read for {entry['name']}: expected {entry['compressed_size']} compressed bytes, got {len(blob)}"
        )
    return blob


def resolve_multipart_member(parts_data: list[bytes], entry: dict) -> tuple[bytes, bytes]:
    candidates = []
    for index, data in enumerate(parts_data):
        if entry["data_offset"] < len(data) and is_ttcomp_header(data[entry["data_offset"] : entry["data_offset"] + 2]):
            candidates.append(index)

    if not candidates:
        raise TTCompError(f"Could not find TTCOMP start for {entry['name']}")

    last_error: Exception | None = None
    for start_part in candidates:
        try:
            blob = read_member_blob_from_part(parts_data, entry, start_part)
            output = explode_ttcomp(blob, expected_size=entry["uncompressed_size"])
            return blob, output
        except Exception as exc:
            last_error = exc

    raise TTCompError(f"Could not decode {entry['name']} from multipart archive: {last_error}")


def extract_input(
    input_path: Path,
    output_root: Path,
    keep_ttcomp: bool,
    unzip_members: bool,
    summary: dict,
    processed_multipart: set[tuple[str, str]],
) -> None:
    group = multipart_group(input_path)
    if group is not None:
        group_key = (str(group[0].parent), group[0].stem.lower())
        if group_key in processed_multipart:
            return
        processed_multipart.add(group_key)
        summary["archives"].append(
            extract_archive_set(
                archive_paths=group,
                output_root=output_root,
                keep_ttcomp=keep_ttcomp,
                unzip_members=unzip_members,
            )
        )
        return

    if looks_like_archive(input_path):
        summary["archives"].append(
            extract_archive_set(
                archive_paths=[input_path],
                output_root=output_root,
                keep_ttcomp=keep_ttcomp,
                unzip_members=unzip_members,
            )
        )
        return

    if not looks_like_pe_installshield_wrapper(input_path):
        raise ValueError(f"Unsupported input: {input_path}")

    installer_info = extract_file_resources(input_path, output_root)
    summary["installers"].append(installer_info)
    for resource in installer_info["resources"]:
        clean_path = (output_root.parent / resource["clean_path"]).resolve()
        group = multipart_group(clean_path)
        if group is not None:
            group_key = (str(group[0].parent), group[0].stem.lower())
            if group_key in processed_multipart:
                continue
            processed_multipart.add(group_key)
            summary["archives"].append(
                extract_archive_set(
                    archive_paths=group,
                    output_root=output_root,
                    keep_ttcomp=keep_ttcomp,
                    unzip_members=unzip_members,
                )
            )
            continue

        if looks_like_archive(clean_path):
            summary["archives"].append(
                extract_archive_set(
                    archive_paths=[clean_path],
                    output_root=output_root,
                    keep_ttcomp=keep_ttcomp,
                    unzip_members=unzip_members,
                )
            )


def extract_archive_set(
    archive_paths: list[Path],
    output_root: Path,
    keep_ttcomp: bool,
    unzip_members: bool,
) -> dict:
    primary_path = archive_paths[0]
    multipart = len(archive_paths) > 1
    parts_data = [path.read_bytes() for path in archive_paths]
    entries = collect_multipart_entries(archive_paths) if multipart else parse_entries(primary_path)
    archive_out = output_root / primary_path.stem if multipart else output_root / primary_path.name
    archive_out.mkdir(parents=True, exist_ok=True)

    extracted = []
    for entry in entries:
        if multipart:
            compressed_blob, output_bytes = resolve_multipart_member(parts_data, entry)
        else:
            compressed_blob = parts_data[0][entry["data_offset"] : entry["data_offset"] + entry["compressed_size"]]
            output_bytes = explode_ttcomp(compressed_blob, expected_size=entry["uncompressed_size"])
        comp_path = archive_out / f"{entry['name']}.ttcomp"
        out_path = archive_out / entry["name"]
        if keep_ttcomp:
            comp_path.write_bytes(compressed_blob)
        out_path.write_bytes(output_bytes)

        item = {
            **entry,
            "output_path": str(out_path.relative_to(output_root.parent)),
            "output_size": out_path.stat().st_size,
        }
        if keep_ttcomp:
            item["compressed_path"] = str(comp_path.relative_to(output_root.parent))

        if unzip_members and out_path.suffix.lower() == ".zip":
            target_dir = out_path.with_suffix("")
            target_dir.mkdir(parents=True, exist_ok=True)
            try:
                with zipfile.ZipFile(out_path) as zf:
                    zf.extractall(target_dir)
                item["unzipped_to"] = str(target_dir.relative_to(output_root.parent))
            except zipfile.BadZipFile:
                item["unzipped_to"] = None

        extracted.append(item)

    result = {
        "archive": str(primary_path),
        "output_dir": str(archive_out.relative_to(output_root.parent)),
        "entries": extracted,
    }
    if multipart:
        result["parts"] = [str(path) for path in archive_paths]
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract old InstallShield 3-era .Z/_SETUP.LIB archives."
    )
    parser.add_argument(
        "archives",
        nargs="+",
        type=Path,
        help="Archives or installer executables such as DATA.Z, _SETUP.LIB, n32d304.exe, or SETUP.EXE",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("out"),
        help="Directory where extracted archives and manifest are written",
    )
    parser.add_argument(
        "--keep-ttcomp",
        action="store_true",
        help="Keep intermediate TTCOMP member files alongside extracted outputs",
    )
    parser.add_argument(
        "--no-unzip",
        action="store_true",
        help="Do not automatically unpack extracted .zip members",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "decompressor": "python-ttcomp",
        "installers": [],
        "archives": [],
    }
    processed_multipart: set[tuple[str, str]] = set()

    for input_path in args.archives:
        input_path = input_path.resolve()
        extract_input(
            input_path=input_path,
            output_root=output_dir,
            keep_ttcomp=args.keep_ttcomp,
            unzip_members=not args.no_unzip,
            summary=summary,
            processed_multipart=processed_multipart,
        )

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {manifest_path}")


if __name__ == "__main__":
    main()
