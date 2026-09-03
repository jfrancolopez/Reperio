# scanner — ephemeral scanner worker

Owner: the network-isolated process that receives the selected source device
read-only and emits normalized findings to the catalog.

- **Source of truth:** `docs/MASTER_PLAN.md` §3.1 and §6.3, `RPR-033`–`RPR-049`.
- **Status:** scanner/control-plane message contract (`RPR-033`) plus placeholder
  health entry point.
- **Health check:** `python -m scanner` (refuses any `--device` argument).
- **Boundary:** `O_RDONLY` only; no HTTP; no capabilities; no network; no
  provider/destination credentials. Recovery output goes only to proven-separate
  scratch storage.
- **Protocol:** `scanner.messages` defines the bounded versioned JSON-lines
  contract emitted by scanner workers.
- **Scheduler:** `scanner.scheduler` defines the single deep-scan stage graph and
  conservative I/O planning contract for `RPR-034`.
- **Source validation:** `scanner.source_validation` independently verifies the
  selected source is still block-special, read-only, and fingerprint-matched for
  `RPR-035` before parser stages run.
- **Partition discovery:** `scanner.partition_discovery` wraps bounded `mmls`
  output from The Sleuth Kit into normalized read-only partition extents for
  `RPR-036`; no repair/write command surface is exposed.
- **Filesystem enumeration:** `scanner.filesystem_enumeration` identifies
  supported TSK volumes with `fsstat` and streams bounded `fls` entry batches
  from direct byte offsets for `RPR-037`; it never mounts source media.
- **Entry normalization:** `scanner.entry_normalization` preserves raw path
  bytes and canonical display metadata for hostile filesystem entries in
  `RPR-038` without resolving paths on the host.
- **Content extraction:** `scanner.content_extraction` streams allocated file
  extents read-only into the scratch store with explicit complete, skipped,
  resumed, and partial statuses for `RPR-040`.
- **Read-error handling:** `scanner.read_errors` normalizes EIO, timeout, and
  short-read ranges into bounded gaps, counters, retries, warnings, and pause
  recommendations for `RPR-044`; no repair command is exposed.
- **PhotoRec carving:** `scanner.photorec_carving` invokes the pinned PhotoRec
  `7.2` binary through a fixed scripted command, accepts only the upstream-
  validated `/dev` source endpoint, and writes quarantine output under separate
  scratch; TestDisk/repair/write modes are not exposed.
- **Lifecycle:** `scanner.lifecycle` coordinates cooperative pause, safe stop,
  source-reconnect-aware restart, and UI-visible pause acknowledgements for
  `RPR-045`.
- **PhotoRec resume:** `scanner.photorec_resume` backs up and validates
  the bounded upstream `#timestamp` session format with source/tool/config
  bindings, then invokes `photorec /cmd resume` from private scratch for
  `RPR-047`; incomplete state is preserved atomically and the resume result
  carries the refreshed durable backup.
- **Carved ingestion:** `scanner.carved_ingestion` watches stable PhotoRec
  quarantine files, stores completed bytes in scratch, and records carved
  provenance for `RPR-048` without ingesting growing files.
- **Lost-volume candidates:** `scanner.lost_volume_candidates` scans read-only
  samples for filesystem/encrypted-volume signatures, separates them from
  current partitions, and emits bounded parser/carving attempts for `RPR-049`.
- **USB/memory-card pipeline:** `scanner.usb_media_pipeline` classifies the
  removable medium family and card type, decides partitioned versus
  partitionless/superfloppy versus lost-partition layout, plans the deep
  pipeline stages (enumeration, deleted-entry recovery, bounded carving,
  classification, export), tags distinct provenance for
  allocated/hidden/trashed/deleted/carved findings, and derives UI-visible
  TRIM/GC/wear-leveling/continued-use states without declaring unrecoverable
  blocks "clean" for `RPR-181`.
- **FAT12 floppy recovery:** `scanner.fat12_parser` recognizes exact supported
  DOS superfloppy geometries, compares FAT copies, normalizes allocated and
  deleted root entries with explicit chain confidence, carries read gaps, and
  emits readable free-cluster carve ranges for `RPR-182`; it exposes no source
  path, mount, repair, rebuild, or write operation.
