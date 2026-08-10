# Requirements traceability

This matrix prevents later agents from overlooking a confirmed requirement. A requirement is not complete because one task mentions it; all listed implementation and verification tasks must meet their acceptance criteria.

| Requirement | Specification | Backlog coverage |
|---|---|---|
| One-command, pull-and-run experience | Master plan 5.2 | RPR-145–147, RPR-154–156 |
| Browser UI accessible from the LAN | 2, 5.1, 9 | RPR-117–132, RPR-145, RPR-154 |
| Optional single password, disabled by default | 2, 4, 9 | RPR-130, RPR-145, RPR-151, RPR-154 |
| One source disk per instance | 2, 5, 6 | RPR-007, RPR-009–019, RPR-028, RPR-118 |
| Permanently no wipe/delete/format/repair of source | 1–3 | RPR-002–003, RPR-009, RPR-013–020, RPR-035, RPR-070, RPR-153, RPR-155 |
| No source mounting in core workflow | 3, 6, 7 | RPR-002–003, RPR-019–020, RPR-035–043, RPR-153 |
| Direct scan; no forensic image | 2, 4, 7 | RPR-003, RPR-035–049, RPR-154 |
| Persistent resume state and separate non-image scratch storage | 2, 3, 7 | RPR-015, RPR-021–025, RPR-032, RPR-039, RPR-045–048, RPR-145 |
| No automatic deletion of completed recovered copies | 3, 12 | RPR-030, RPR-039, RPR-106–108, RPR-145, RPR-153 |
| Deep scan only; time is secondary | 1, 2, 7 | RPR-034, RPR-036–059, RPR-119, RPR-152 |
| Allocated, hidden, deleted, orphaned, carved files | 1, 7 | RPR-037–049, RPR-050–054, RPR-125, RPR-155 |
| Deleted/lost partitions and corrupt filesystems | 1, 7 | RPR-036, RPR-044, RPR-046–049, RPR-082 |
| Resume after disconnect/restart | 1, 4, 7 | RPR-012, RPR-019, RPR-023–025, RPR-045, RPR-047, RPR-150 |
| Progressive results during scan | 1, 7, 9 | RPR-026, RPR-033–034, RPR-048, RPR-108, RPR-119 |
| Export before scan completion | 1, 9, 12 | RPR-039–040, RPR-105–110, RPR-127–128 |
| Multiple local/NAS/cloud/SFTP/FTP destinations | 2, 12 | RPR-105–110, RPR-128, RPR-154 |
| Verified copies and export manifest | 3, 12 | RPR-106–107, RPR-115, RPR-128, RPR-155 |
| Dismiss in bulk and undo | 2, 9 | RPR-030, RPR-120–121, RPR-127 |
| Avoid OS/DLL/cache image noise without hiding it permanently | 1, 7, 9 | RPR-050–054, RPR-121, RPR-125–126 |
| Full inventory and explainable classification | 1, 7, 10 | RPR-038, RPR-050–059, RPR-120–126, RPR-160–172 |
| Photos in masonry/Pinterest-like experience | 2, 9 | RPR-059, RPR-072–074, RPR-122, RPR-126, RPR-132 |
| Full-screen safe media viewing | 2, 9 | RPR-070, RPR-073–075, RPR-122, RPR-126, RPR-151 |
| Documents, PDFs, OCR, metadata, search | 1, 7, 9 | RPR-071, RPR-075–078, RPR-121, RPR-123, RPR-126 |
| Audio/video transcription | 7, 9 | RPR-074, RPR-079, RPR-126 |
| English/Spanish and other-language translation | 2, 7, 9 | RPR-076–078, RPR-123, RPR-126 |
| Full-text and semantic natural-language search | 1, 7, 11 | RPR-029, RPR-071, RPR-076, RPR-087–092, RPR-121 |
| Browser history for all users/profiles/browsers | 1, 8 | RPR-060–069, RPR-124, RPR-136, RPR-155 |
| Browser CSV/JSON/full-detail report export | 8, 12 | RPR-068, RPR-114, RPR-124 |
| Find iPhone/Android backups and application data | 1, 7, 15 | RPR-056–057, RPR-137–138, RPR-163 |
| Find iMessage/WhatsApp/media/mail | 7, 15 | RPR-125, RPR-137–138, RPR-162–163 |
| Find wallets, password vaults, keys, certificates | 1, 7 | RPR-058, RPR-081, RPR-104, RPR-125 |
| Detect protected files | 2, 7 | RPR-080–081, RPR-095, RPR-125 |
| Supplied password attempts | 2, 7 | RPR-096, RPR-102–103 |
| Dictionaries, rules, combinations, offline recovery | 2, 7 | RPR-097–101, RPR-129 |
| Extract/display decrypted content when possible | 2, 7 | RPR-096, RPR-102–104, RPR-126 |
| Repair/regenerate damaged copies only | 2, 3, 7 | RPR-039, RPR-070, RPR-082, RPR-153 |
| Local/LAN LLMs with no key | 2, 11 | RPR-083–093, RPR-129 |
| Primary/secondary/third+ model comparison | 2, 11 | RPR-084, RPR-087–090, RPR-126, RPR-129 |
| Optional cloud-subscription clients without token scraping | 11 | RPR-093–094, RPR-129, RPR-157–159 |
| AI is optional and never controls deletion | 3, 7, 11 | RPR-053–054, RPR-083–093, RPR-126, RPR-153 |
| Background operation without operator prompts | 2, 7, 13 | RPR-023–026, RPR-034, RPR-044–048, RPR-101, RPR-111–113 |
| Progress and completion notifications | 2, 13 | RPR-026, RPR-111–113, RPR-131 |
| Windows priority | 2, 15 | RPR-036–069, RPR-133, RPR-155 |
| macOS second | 2, 15 | RPR-134–138, RPR-155 |
| Linux third | 2, 15 | RPR-139–141, RPR-155 |
| RAID/DVR/raw later | 2, 15 | RPR-046–049, RPR-142–143, RPR-168, RPR-174–177 |
| Linux AMD64/ARM64 and Raspberry Pi class | 5, 15 | RPR-144, RPR-146, RPR-152, RPR-156 |
| Reuse mature tools instead of rebuilding everything | 14 | RPR-001, RPR-036–049, RPR-069–082, RPR-099–100, RPR-109, RPR-112, RPR-138, RPR-147–148, RPR-163, RPR-169–170, RPR-174–177 |
| Treat disk content as hostile | 3 | RPR-002, RPR-019–020, RPR-070–082, RPR-151, RPR-153 |
| Windows registry, recent activity, shadow copies, and mail | 7, 15 | RPR-160–162 |
| Nested disk images and virtual machines | 7, 15 | RPR-056, RPR-165 |
| FileVault/APFS encryption | 7, 15 | RPR-134, RPR-166 |
| XFS, Btrfs, ZFS, and storage-appliance expansion | 15 | RPR-167–168 |
| Potential-malware labeling without deletion | 3, 14 | RPR-169, RPR-151 |
| Global timeline, map, and related-media views | 9, 11 | RPR-171–173 |

## Coverage audit rule

Before a milestone release, compare its selected backlog IDs to this matrix. Any requirement advertised for that milestone must have all prerequisite, implementation, UI, and verification IDs complete. Requirements scheduled later must be labeled unavailable rather than partially implied.
