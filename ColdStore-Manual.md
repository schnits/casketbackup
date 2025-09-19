# ColdStore Manual

**ColdStore** is an incremental backup tool using streaming **FastCDC** chunking, cross‑drive deduplication, and **Reed–Solomon** parity. It supports optional AES‑GCM encryption for chunks/parity and encrypted manifests, a location‑aware global index, and offline restore planning.

- **Source**: single‑file Java (`ColdStore.java`), no external libraries.
- **Runtime**: Java 11+.

---

## Quick Start

1) **Compile** (requires Java 11+):
```
javac ColdStore.java
```
2) **Initialize a drive as a repo volume** (once per drive):
```
java ColdStore init --repo /mnt/drive1/ColdStore --name Drive1   --rs-k 8 --rs-r 2   --min-chunk 262144 --avg-chunk 1048576 --max-chunk 4194304   --compress false --encrypt false --encrypt-manifest false
```
3) **Back up a source folder** with a safety write cap (stop before the disk fills):
```
java ColdStore backup --repo /mnt/drive1/ColdStore --source /data   --target-fill 0.70 --xfile-parity true --xfile-finalize-partial true
```
4) **(Optional) Build an inventory** file for faster restore planning:
```
java ColdStore inventory --mode scan --repo /mnt/drive1/ColdStore --inventory /path/to/inv --bits-per-element 12
```
5) **Restore** later (attaching drives as needed):
```
java ColdStore restore --repo /mnt/drive1/ColdStore --snapshot SNAP_2025-09-19T15-00-00Z --dest /restore
# or union of latest snapshots across attached drives:
java ColdStore restore --repo /mnt/drive1/ColdStore --union-latest true --dest /restore
```


---

## Repository Layout

```
ColdStore/
├─ repo.properties      Repo configuration (CDC/RS params, encryption flags, IDs). Created by `init`.
├─ key.enc              Encrypted master key wrapper (AES‑GCM, PBKDF2). Present if any encrypted/obfuscated feature is enabled.
├─ chunks/              Content‑addressed chunk store: `chunks/aa/bb/aabb…` (SHA‑256).
├─ parity/              Per‑file Reed–Solomon parity stripes (legacy; skipped when cross‑file parity is enabled).
├─ parity_xfile/        Cross‑file parity stripes by numeric `stripe-XXXXXXXX` directories.
├─ manifests/           Snapshot manifests (`SNAP_... .jsonl` or `.jsonl.gcm` when encrypted).
├─ chunk_catalog.txt    Append‑only catalog of all chunks written on this drive.
├─ snapshots.txt        Line‑delimited list of completed snapshot names on this drive.
├─ xfile_index.txt      Sidecar index mapping `chunkId -> stripeId,position` for cross‑file parity repair.
├─ xfile_state.txt      State for resuming partially filled cross‑file stripes and nextStripeId.
```
Notes:
- `repo.id` is stable across volumes; `drive.id` differs for each physical drive.
- Manifests are line‑delimited JSON (`.jsonl`). Encrypted manifests end with `.jsonl.gcm`.

---

## Content-Defined Chunking (FastCDC)

- Chunks are sized around `--avg-chunk` (bounded by `--min-chunk` / `--max-chunk`).
- Each chunk is addressed by **SHA‑256** and stored under `chunks/` using a fan‑out directory scheme.
- `chunk_catalog.txt` records every chunk seen on this drive; used by `inventory` to build Bloom filters.

---

## Reed–Solomon Parity

- **Parameters**: `--rs-k K` data slices per stripe and `--rs-r R` parity slices.
- **Per‑file parity**: writes `K` data slices + `R` parity slices per file stripe under `parity/<SNAP>/<fileIdHash>/stripe-XXXXXXXX/`. Disabled automatically when cross‑file parity is enabled.
- **Cross‑file parity** (`--xfile-parity`): packs K chunks from *across files* into a stripe and writes R parity slices to `parity_xfile/stripe-XXXXXXXX/`. Maintains `xfile_index.txt` for locating a chunk’s stripe quickly.
- **Recovery**: a single missing data slice in a stripe can be reconstructed with available parity using GF(256) math.


---

## Cross‑File Parity Pack (`--xfile-parity`)

- Packs incoming chunks across files into stripes at `parity_xfile/` with sidecar `xfile_index.txt`.
- Greatly increases parity coverage for small files and tails where per‑file stripes would be short.
- Use `--xfile-finalize-partial true` to flush a short stripe (trade a bit of space for resumability).

---

## Encryption & Obfuscation

- **Master key**: 256‑bit random key, wrapped in `key.enc` using **AES‑GCM** with a KEK derived from your passphrase via **PBKDF2‑HMAC‑SHA256** (default ~210k iterations).
- **Encrypted streams**: chunks, parity and/or manifests may be wrapped using AES‑GCM with per‑file nonces.
- **Obfuscation of parity paths**: when enabled, file IDs used to name parity folders are HMAC’d so original paths are not leaked by parity directory names.


---

## Global Index (Optional)

The **Global Index** is an optional, location‑aware index stored externally (path provided via `--global-index`). During backup it updates:
- drive ordinals and labels,
- a map of chunk IDs and their first‑seen drive,
so later `restore-plan` / `inventory --mode suggest` can recommend which drives to attach to satisfy a restore with minimal drive swaps.


---

## Inventory & Restore Planning

`inventory` builds a **Bloom filter** for a drive from `chunk_catalog.txt` (size tuned by `--bits-per-element`). You can then:
- `--mode list` to list all inventories,
- `--mode locate --chunk <sha256hex>` to test membership on each drive, and
- `--mode suggest` to propose an attach order for a given manifest or snapshot using the Global Index and/or Bloom filters.


---

### Commands & Options

Below mirrors `java ColdStore`’s `--help` plus additional notes.

#### `init`
```
java ColdStore init --repo <path> [--name <RepoName>]
  [--rs-k 8 --rs-r 2]
  [--min-chunk 262144 --avg-chunk 1048576 --max-chunk 4194304]
  [--compress false]
  [--encrypt false] [--obfuscate-parity <true|false>]
  [--encrypt-manifest <true|false>]
  [--passphrase "..."] [--log info]
```
- Creates `repo.properties`, directories, and IDs. If any encrypted/obfuscated feature is enabled, `key.enc` is created (you will be prompted for a passphrase unless `--passphrase` is provided).

#### `info` / `list`
```
java ColdStore info --repo <path> [--log info]
java ColdStore list --repo <path> [--log info]
```
- `info` prints repo parameters and snapshots on the drive.
- `list` is an alias for listing snapshots.

#### `backup`
```
java ColdStore backup --repo <path> --source <path>
  [--target-bytes N] [--target-fill F]
  [--global-index <dir>]
  [--xfile-parity true|false] [--xfile-finalize-partial true|false]
  [--passphrase "..."] [--log info]
```
- **Write caps**: effective cap = `min(target-bytes, target-fill × freeAtStart)`; counts **new chunk bytes only** (parity/manifests do not consume the cap).
- **Cross‑file parity**: enables `parity_xfile` stripes and disables per‑file parity automatically.
- **Finalize partial**: if `true`, a short stripe at the end is flushed and recorded in `xfile_state.txt` to resume gracefully next run.
- **Global index**: if provided, backups record drive/ordinal metadata to help restore planning later.

#### `restore`
```
java ColdStore restore --repo <path> (--snapshot SNAP_... | --union-latest true) --dest <path>
  [--only-file <relpath>] [--only-prefix <relfolder/>]
  [--passphrase "..."] [--log info]
```
- If a needed chunk is missing on attached drives, ColdStore attempts recovery via **per‑file parity** or **cross‑file parity** using `xfile_index.txt` and stripe directories.
- With `--union-latest`, it restores the latest snapshot from each attached drive (asking to attach more when it stalls).

#### `restore-plan`
```
java ColdStore restore-plan --manifest <path|.gcm> --inventory <dir>
  [--repo <path>] [--max-drives N] [--passphrase "..."] [--log info]
```
- Offline planning against inventories/global index to propose an attach order before you start a live restore.

#### `inventory`
```
# Build Bloom filter inventory
java ColdStore inventory --mode scan --repo <path> --inventory <dir> [--bits-per-element 12]

# List inventories (optionally filter by repo)
java ColdStore inventory --mode list --inventory <dir> [--repo <path>]

# Locate a specific chunk id (hex)
java ColdStore inventory --mode locate --inventory <dir> --chunk <sha256hex> [--repo <path>]

# Suggest attach order for a snapshot/manifest
java ColdStore inventory --mode suggest --inventory <dir> [--repo <path>] [--snapshot SNAP_... | --manifest <path>]
                         [--only-file <relpath>] [--only-prefix <relfolder/>]
                         [--max-drives N] [--passphrase "..."]
```
- `--bits-per-element` trades memory vs. false positive rate. 10–14 is a practical range.

#### `xparity-sweep`
```
java ColdStore xparity-sweep --repo <path> [--xfile-finalize-partial true|false]
                             [--passphrase "..."] [--log info]
```
- Completes any pending short stripes and ensures `xfile_index.txt` coherence.

#### `index-compact`
```
java ColdStore index-compact --global-index <dir>
```
- Compacts the global index’s delta file into the main store to keep lookups fast.

#### `scan` / `locate` / `suggest` (shortcuts)
These are thin wrappers around `inventory --mode ...` and `restore-plan` functionality for convenience.


---

### Logging
Use `--log off|info|debug|trace` on any command. Timestamps are ISO‑8601; `trace` will print per‑file scanning and chunk‑level actions.


---

### Best Practices & Sizing Tips

- **CDC tuning**: Start with `min=256 KiB`, `avg=1 MiB`, `max=4 MiB` for large media. Smaller `avg` improves dedupe on small files at the cost of metadata and RS overhead.
- **RS parameters**: Common choices are `K=8,R=2` (25% overhead) or `K=10,R=2` (~20%). Cross‑file parity gives wider coverage; per‑file parity is simpler but less space‑efficient.
- **Drive‑filling caps**: Prefer `--target-fill 0.70` on spinning disks to leave headroom; combine with `--target-bytes` for deterministic batches.
- **Multiple drives**: Initialize each drive as its **own repo volume** (they share `repo.id` generated at `init`). Back up sequentially, and build an `inventory` for each.
- **Encryption**: If you enable any encryption/obfuscation, **store the passphrase** safely. Without it, data/parity/manifests cannot be decrypted.
- **Checks & resumability**: Backups write manifests atomically and append to `snapshots.txt`. Cross‑file parity uses `xfile_state.txt` to resume partial stripes safely.
- **Restores**: Attach drives as suggested by `inventory --mode suggest` or `restore-plan`. The tool will prompt to add more drives if chunks are missing.


---

### Troubleshooting

- **`IllegalArgumentException: --repo required`** — Provide `--repo` with an absolute or relative path.
- **`Wrong passphrase or key.enc corrupt`** — Check you’re using the exact passphrase from initialization; `key.enc` couples to that passphrase and repo.
- **`Manifest not found` during restore** — Attach the drive holding the snapshot’s manifest; `restore` will prompt to attach more if needed.
- **Partial stripes** — Run `xparity-sweep` or repeat a `backup` with `--xfile-finalize-partial true` to flush remaining parity.
- **Java version** — Requires a modern JDK (the code uses `InputStream.transferTo` and NIO; JDK 11+ is recommended).


---

## License / Attribution
Generated manual based on your provided `ColdStore.java` on 2025-09-19.
