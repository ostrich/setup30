# setup30

Extract old InstallShield 3-style `.Z`, `_SETUP.LIB`, and numbered multipart archives on modern systems.
It can also take a classic self-extracting InstallShield installer `.exe` and do the intermediate `FILE` resource extraction for you.

These files are not plain Unix `.Z` archives. They contain:

- a small InstallShield footer table
- per-file TTCOMP-compressed member streams

Modern tools like `7z` and `unshield` usually do not handle this format directly.

## What it does

`setup30.py`:

- accepts old `.Z` / `_SETUP.LIB` archives, numbered multipart sets such as `DATA.1` / `DATA.2`, or a compatible self-extracting installer `.exe`
- extracts installer `FILE` resources itself when given a self-extracting installer
- parses the old InstallShield footer
- finds member names, offsets, and compressed sizes
- reconstructs disk-spanning TTCOMP members across numbered archive parts
- expands each TTCOMP member directly in Python
- optionally unzips extracted `.zip` members
- writes a `manifest.json` describing the extraction

## Requirements

- Python 3.10+

## Usage

```bash
python setup30.py DATA.Z SYSTEM.Z JAVA.Z _SETUP.LIB -o out
```

For numbered multipart archives:

```bash
python setup30.py DATA.1 -o out
```

From a classic self-extracting installer:

```bash
python setup30.py n32d304.exe -o out
```

With intermediate TTCOMP streams preserved:

```bash
python setup30.py DATA.Z -o out --keep-ttcomp
```

Without auto-unzipping extracted ZIP members:

```bash
python setup30.py DATA.Z -o out --no-unzip
```

## Output layout

For input `DATA.Z`, output looks like:

```text
out/
  DATA.Z/
    netscape.exe
    NPAUDIO.DLL
    NPAVI.ZIP
    ...
  manifest.json
```

For multipart input such as `DATA.1`, output is grouped by basename:

```text
out/
  DATA/
    MFC42.DLL
    MSVCRT.DLL
    ...
  manifest.json
```

For installer input, the extracted `FILE` resources are also kept:

```text
out/
  n32d304/
    raw_file_resources/
    clean_file_resources/
  DATA.Z/
  SYSTEM.Z/
  ...
  manifest.json
```

## Notes

- This currently targets the later Stirling/InstallShield archive family that identifies itself with strings like `InstallShield Launcher SE v2.1` and `InstallShieldSetup30`.
- Verified samples so far include direct PE Netscape installers `n32e201.exe`, `n32e202.exe`, `n32e30p.exe`, and `n32d304.exe`; plus raw non-Netscape `DATA.Z` / `_SETUP.LIB` archives and numbered multipart `DATA.1` / `DATA.2` sets from Toshiba and Ricoh utility packages.
- The self-extracting installer path assumes a PE installer with standard resource tables and `FILE` resources.
- Older pre-`Setup30` InstallShield launchers with strings like `InstallSHIELD Launcher (C) The Stirling Group, 1990, 1991` and payloads such as `INSTALL.EX$` / `INSTALL.INS` are not currently supported.
- It does not claim support for every InstallShield generation.
- It does not claim support for later CAB-based InstallShield installers, unrelated 16-bit installers, or outer wrapper formats such as ZIP/WinZip SFX or LHa SFX.
- Directory records in these archives are not fully reconstructed yet; extracted files are currently grouped by source archive.
