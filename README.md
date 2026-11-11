# lv0tool

A small utility for extracting and reimporting the loader components embedded in
a PS3 `lv0` image (3.60 and later).

- Originally written by **u$er**.
- Extraction/import rework and this README by **Sorvigolova** (2026).

The original project shipped without a README or license; attribution above is
preserved from the source. License is unspecified — treat accordingly.

---

## What it does

From firmware 3.60 on, `lv0` carries the next-stage loaders inside itself. This
tool reads the loader table in a decrypted `lv0` ELF and:

- **extracts** each loader to a file, trimmed to its true size, or
- **imports** loader files back into their slots and writes a new `lv0`.

Loaders come in up to four pairs — `lv1ldr`, `lv2ldr`, `isoldr`, `appldr` — each
with a *first component* (the full SELF) and a *second component* (`*.2`, a
header-only patch). Test-bench images may carry only `lv1ldr` + `lv1ldr.2`; the
other slots are stubs and are skipped.

---

## Build

### Linux
```sh
make
```
Builds a self-contained static binary with `gcc`. No external dependencies.

### Windows
Builds with VS2022 / CMake as a fully static binary. Windows 7 and later are
supported.

---

## Usage

```
lv0tool -extract <lv0.elf> [output_dir]
lv0tool -import  <lv0.elf> <input_dir> <output.elf>
```

The option flag is required; the tool does nothing without `-extract` or
`-import`.

### Extract
```sh
lv0tool -extract lv0.elf loaders
```
Writes `lv1ldr`, `lv1ldr.2`, `lv2ldr`, `lv2ldr.2`, … into `loaders/` (created if
missing). If the output directory is omitted, the current directory is used.

### Import
```sh
lv0tool -import lv0.elf loaders lv0_new.elf
```
Reads whatever loader files are present in `loaders/` and writes a rebuilt image
to `lv0_new.elf`. Only the files you supply are touched; any component without a
matching input file is left as-is, so you can reimport a single loader (e.g. drop
just `lv2ldr.2` into the directory).

---

## How it works

**Loader table.** The table is located via its marker, and each entry gives the
component id, its slot (VA range) and file offset. Ids are validated against the
expected first/second component layout.

**True size vs slot.** A slot is a fixed region; the component inside may be
smaller. The true size is read from the component's SCE header:

- first component (full SELF): `header_len + data_len`
- second component (`*.2`, header only): `header_len`

On **extract**, each component is trimmed to its true size — any trailing
padding or leftover slot space is dropped, giving a clean SELF.

On **import**, the whole slot is zeroed, the component is written at the start,
and the remainder stays as padding. The result matches the way the original
images are laid out: a clean slot with exactly as many useful bytes as the
component needs, padded out to the slot size.

**Version gate.** The `lv0` version is read from the plaintext version string.
Images below 3.60 are refused. From 3.65 on, `lv1ldr` / `lv1ldr.2` carry an
additional encryption layer, detected automatically; the key material for that
layer is **not** included in this repository.

**Safety checks on import.** Each input must be a decrypted SCE loader, must fit
its target slot, and must match the slot's `auth_id` and the target `lv0`
firmware version. A loader from a different firmware version is rejected to avoid
producing an unbootable image.

---

## Notes

- Components are matched to slots by **file name**, not by `auth_id`.
- Extracted first/second components are raw, exactly as they sit in the slot
  (after the optional loader layer is removed), minus trailing padding.
- Rebuilding an unmodified `lv0` reproduces the original byte-for-byte. Images
  whose padding was left non-canonical by other tools are normalized on import.
