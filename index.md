---
layout: default
---

# Leaking Every Process's CR3 from User-Mode via Superfetch PFN Classification

**Turning a known information-disclosure primitive into a full DTB enumerator by detecting self-referencing PML4 entries in Superfetch PFN data.**

> **Prior work and what's new.**
>
> The `NtQuerySystemInformation(SystemSuperfetchInformation)` interface
> and its ability to map PFNs to virtual addresses has been publicly
> documented:
>
> - [**v1k1ngfr**](https://v1k1ngfr.github.io/superfetchquery-superpower/)
>   — "The SuperFetch Query superpower" — covers the Superfetch PFN
>   query for VA→PA translation, VM sandbox detection, process
>   enumeration, and `_EPROCESS` address leaking.
> - [**Outflank**](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/)
>   — "Mapping Virtual to Physical Addresses Using Superfetch" — covers
>   using the Superfetch PFN query for VA→PA translation in BYOVD
>   exploitation scenarios.
> - **Pavel Yosifovich / Alex Ionescu / Mark Russinovich / David Solomon**
>   — *Windows Internals 7e* — covers the SysMain service, PFN database,
>   and page-table architecture.
>
> **What this writeup adds:** a technique for classifying the Superfetch
> PFN dump to detect **self-referencing PML4 entries**, which reveals
> every process's **DTB (CR3)** — the root of its page-table hierarchy —
> from user mode without any driver. The self-ref PML4 detection
> heuristic applied to Superfetch data, and the resulting ability to
> enumerate all process DTBs and reconstruct the full page-table
> hierarchy in a single scan, is the novel contribution.
> The underlying Superfetch primitive is known; the application is new.

---

## TL;DR

- Any process holding `SeProfileSingleProcessPrivilege` (default for
  `Administrators`) can call `NtQuerySystemInformation` with the
  `SystemSuperfetchInformation` class.
- The SysMain (a.k.a. Superfetch) service uses this interface to track
  working-set behavior. One of its sub-info classes returns, for a
  requested range of physical page frame numbers (PFNs), the **virtual
  address** each PFN is mapped at and the **owning process ID**.
- Prior work (v1k1ngfr, Outflank) has shown this can be used for VA→PA
  translation and `_EPROCESS` leaking.
- **This writeup shows** that the same PFN dump contains enough
  information to identify **self-referencing PML4 entries** — pages
  whose VA index pattern reveals them as page-table roots — which
  directly leaks the **DTB / CR3** of every process on the box.
- Combined with `SystemModuleInformation` for the kernel base, this
  gives a complete memory-forensics input set from user mode: where
  the kernel is, every process's CR3, and a full VA→PA map — no
  driver, no exploit, no memory corruption.
- Microsoft treats this as a **design tension, not a bug**. Removing the
  interface would break SysMain, which needs it to do its job.

---

## 1. Background: what `NtQuerySystemInformation(SystemSuperfetch...)` is

`NtQuerySystemInformation` is the Windows kernel's public "one syscall,
many info classes" service. The `SystemSuperfetchInformation` class
(id `79` on x64) is an internal multiplexer whose payload is a small
header identifying a *sub-class* of query plus a caller-allocated buffer
to receive the data:

```cpp
struct SuperfetchInfo {
    ULONG   Version;       // 0x2D on current Win11 builds
    ULONG   Magic;         // 0x6B756843  ('Chuk')
    ULONG   InfoClass;     // sub-class selector
    ULONG   Reserved0;
    PVOID   Data;          // caller buffer for the sub-class payload
    ULONG   DataLength;
    ULONG   Reserved1;
};
```

The magic value is validated by the SysMain kernel logic — any caller
that doesn't know it gets an early `STATUS_INVALID_PARAMETER`. It is
not a security boundary; the byte pattern is fixed and well-known.

Two sub-classes matter for the primitive described here:

| InfoClass | Name | Payload |
|-----------|------|---------|
| `17` | `SuperfetchMemoryRangesQuery` | An array of physical memory ranges (BasePfn + PageCount) |
| `6` | `SuperfetchPfnQuery` | For each requested PFN: `{Info, Pfn, Va}` where `Info` encodes the owning PID and `Va` is the virtual address the page is currently mapped at |

Sub-class 17 is a single fast syscall — it returns the physical memory
map (usable RAM regions) that SysMain tracks.

Sub-class 6 is the core primitive. You hand the kernel a `Version=1`
request struct followed by `Count` entries, each holding a PFN you want
information about. The kernel fills in the `Va` and `Info` fields.
`(Info >> 9) & 0xFFFFFFFF` is the owning process id.

This primitive — querying PFNs to get VA + PID — is documented by
[v1k1ngfr](https://v1k1ngfr.github.io/superfetchquery-superpower/)
and [Outflank](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/).
What follows is the new application.

## 2. What the primitive gives you

For each populated physical page in the system, you learn:

1. Which process owns it (by PID)
2. The virtual address it is currently mapped at (in that process's
   address space, or in the system-wide kernel range)
3. Its physical address (trivially — you asked about that PFN)

That is a **full physical-to-virtual reverse map** covering every page
of RAM, in one enumeration. No driver, no `MmGetPhysicalMemoryRanges`,
no reading `\Device\PhysicalMemory`, no debug port. Just a syscall the
SysMain service uses every few seconds.

## 3. Finding each process's DTB / CR3 — the novel technique

Every process on x86-64 has a **directory table base** (DTB, stored in
`CR3` while the process runs). The DTB is the physical address of the
root of that process's page-table hierarchy — the PML4. Knowing a
process's DTB is the primitive that unlocks arbitrary in-process
virtual-to-physical translation and, combined with kernel-page mapping,
arbitrary R/W of that process's address space if you have a channel
that accepts physical addresses.

Windows normally hides DTBs behind kernel structures (`EPROCESS +
Pcb.DirectoryTableBase`) that user mode has no legitimate way to read.
The Superfetch primitive leaks them **implicitly**, via a property of
how x86-64 page tables are laid out:

### Self-referencing PML4 entries

To let the kernel walk and modify its own page tables in a uniform way,
Windows installs a **self-referencing entry** in the PML4: one slot
whose physical target is the PML4 itself. When the CPU walks a virtual
address whose PML4 index equals that slot, it hits the same PML4 for
every level of the walk, and the final "data page" it dereferences is
the PML4 page.

The consequence: the PML4 page (and the PDPT/PD/PT pages) all have a
**canonical self-ref VA** where they are visible to the kernel. That VA
has a very distinctive shape — the same index in every level of the
walk:

```
Va = 0xFFFF | (idx<<39) | (idx<<30) | (idx<<21) | (idx<<12)
```

### The classification heuristic

The insight this writeup contributes: when you enumerate every PFN
via Superfetch sub-class 6, the returned `Va` for page-table pages
carries this self-ref signature. By classifying every returned entry,
you can pick out every process's PML4 page — and its PFN *is* that
process's DTB.

Concretely: for every PFN the enumeration returns a `Va`, extract the
four 9-bit indices:

```cpp
Pml4 = (Va >> 39) & 0x1FF;
Pdpt = (Va >> 30) & 0x1FF;
Pd   = (Va >> 21) & 0x1FF;
Pt   = (Va >> 12) & 0x1FF;
```

If all four are equal AND the index is `>= 256` (kernel half of the
canonical range), you are looking at that process's own PML4 page —
mapped via its self-referencing slot. The `Info.Pid` tells you which
process, and `Pfn * PAGE_SIZE` is that process's **DTB**.

That is the entire disclosure. From one PFN scan:

```
for each PFN entry returned by Superfetch:
    if is_self_ref(entry.Va) and pml4_index(entry.Va) >= 256:
        dtb_table[entry.Pid] = entry.Pfn * PAGE_SIZE
```

No prior public documentation of this classification technique applied
to Superfetch data could be found at the time of writing.

## 4. Leaking the full page-table hierarchy

The DTB leak in §3 finds the PML4 — the root — but the self-referencing
entry exposes **every level** of the page-table tree. Once you know a
process's self-ref index `idx` (extracted from the PML4 detection), the
same Superfetch PFN dump classifies every PDPT, PD, and PT page that
process owns. One scan, no driver, full hierarchy.

### How the kernel maps its own page tables

The self-referencing PML4 slot creates a set of **recursive virtual
addresses** the kernel uses to access page-table pages as ordinary
memory. The trick is that each additional level of self-referencing
"absorbs" one level of the page walk, letting the final dereference
land on a deeper page-table structure:

| To access | VA construction | Walk (what the CPU actually dereferences) |
|-----------|-----------------|-------------------------------------------|
| **PML4** | `idx, idx, idx, idx` + offset | self→self→self→self → PML4 page |
| **PDPT** of slot A | `idx, idx, idx, A` + offset | self→self→self→PML4[A] → PDPT page |
| **PD** of slot A,B | `idx, idx, A, B` + offset | self→self→PML4[A]→PDPT[B] → PD page |
| **PT** of slot A,B,C | `idx, A, B, C` + offset | self→PML4[A]→PDPT[B]→PD[C] → PT page |

In other words: the number of leading `idx` indices in the VA tells
you what level of the hierarchy you're looking at, and the remaining
indices describe *which* page table at that level.

### Classifying every PFN

For every entry the Superfetch scan returns, extract the four 9-bit
VA indices as before (`Pml4`, `Pdpt`, `Pd`, `Pt`). If `Pml4 == idx`
and `idx >= 256`, the page is a page-table page; the pattern of
which indices equal `idx` tells you the level:

```cpp
if (Pml4 == idx) {
    if (Pdpt == idx) {
        if (Pd == idx) {
            if (Pt == idx) {
                // Level 4: PML4 page itself (DTB) — covered in §3
            } else {
                // Level 3: PDPT page serving PML4 slot [Pt]
                //   physical address = Pfn * PAGE_SIZE
            }
        } else {
            // Level 2: PD page serving PML4[Pd] → PDPT[Pt]
        }
    } else {
        // Level 1: PT page serving PML4[Pdpt] → PDPT[Pd] → PD[Pt]
    }
}
```

After one pass you have the physical address and hierarchical
position of **every page-table page** the process owns — from the
root PML4 all the way down to individual PTs that map 2 MiB regions
of the virtual address space.

### What this gives you

1. **Full page-table reconstruction.** You know the physical address
   of every PML4E, PDPTE, PDE, and PTE page. If you have any physical
   memory read channel — the Superfetch VA→PA map itself, a BYOVD
   driver, DMA hardware — you can read the raw entries and reconstruct
   the complete virtual-to-physical mapping for any process. No
   `MmGetVirtualForPhysical`, no `!pte` in a debugger, no loaded
   kernel symbols.

2. **Page-table enumeration without walking.** Traditional page-table
   walking is top-down: read PML4 → follow entry → read PDPT → follow
   entry → etc. Each step requires a physical read. The Superfetch
   classification gives you the same information *without walking* —
   you already know every PT page's physical address and where it sits
   in the hierarchy, from a single usermode scan.

3. **Cross-process comparison.** Because the scan covers all processes
   simultaneously, you can see which page-table pages are shared between
   processes (the kernel half, shared PDPT/PD mappings) vs. private
   (user-mode page tables unique to each process). This is the kind
   of data that normally requires kernel debugger access.

4. **Detecting page-table manipulation.** Any unexpected topology —
   a PT page mapped at a VA that doesn't match the self-ref pattern,
   or a PML4 page appearing under a PID where no process should
   exist — is a signal of page-table remapping, PML4E grafting, or
   other manipulation that forensic analysis cares about.

### Worked example

Assume process PID 1234 has self-ref index `idx = 0x1AB` (decimal 427).
The Superfetch scan returns these PFNs:

```
PFN 0x3F000 → Va = construct(0x1AB, 0x1AB, 0x1AB, 0x1AB), PID 1234
  → PML4 page.  DTB = 0x3F000 * 0x1000 = 0x3F000000

PFN 0x41200 → Va = construct(0x1AB, 0x1AB, 0x1AB, 0x000), PID 1234
  → PDPT serving PML4 slot 0  (user-mode base)

PFN 0x41300 → Va = construct(0x1AB, 0x1AB, 0x1AB, 0x100), PID 1234
  → PDPT serving PML4 slot 256  (kernel-mode base)

PFN 0x52000 → Va = construct(0x1AB, 0x1AB, 0x003, 0x005), PID 1234
  → PD serving PML4[3] → PDPT[5]

PFN 0x62000 → Va = construct(0x1AB, 0x003, 0x005, 0x00A), PID 1234
  → PT serving PML4[3] → PDPT[5] → PD[10]
```

From these five entries alone (out of potentially thousands per
process), you already know the physical address of the PML4, one
user-mode PDPT, one kernel PDPT, a PD two levels down, and a PT
three levels down — with zero page-table reads.

## 5. Defeating kernel ASLR

KASLR randomizes the base at which `ntoskrnl.exe` and other kernel
modules load. From a limited-user context there is real work to
defeat it. From Administrator, there isn't — several APIs leak it
outright. The one this code uses is `NtQuerySystemInformation` with
`SystemModuleInformation` (class `11`), which returns
`RTL_PROCESS_MODULES` — a list of every loaded kernel module with
its ImageBase.

That call has been the standard "kernel base leak" for over a decade
and is not novel. It is unrelated to Superfetch, but it composes
naturally with it: once you have `ntoskrnl.exe`'s base you can locate
`PsInitialSystemProcess`, walk `ActiveProcessLinks`, resolve any
per-process kernel structure, or read symbols out of the kernel image
from user mode.

Combined with the DTB leak from §3 and hierarchy map from §4, you get:

- **Where the kernel is** (module base list)
- **What CR3 to use to translate its virtual addresses** (System process's DTB, PID 4)
- **A full VA→PA map for every process** (the PFN scan itself)
- **The physical layout of every process's page tables** (the hierarchy classification)

Which is the complete input set a memory-forensics tool needs to
enumerate live kernel structures from user mode without ever loading
a driver.

## 6. Building a VA→PA translator

You do not need to walk the PML4/PDPT/PD/PT hierarchy manually. The
same scan that reveals DTBs already gave you a table `{VA -> PFN, PID}`
for every mapped page in the system. To translate a virtual address in
some target process:

```python
def va_to_pa(va, target_pid):
    page_va = va & ~0xFFF
    if (page_va, target_pid) not in pfn_map:
        return None                     # not mapped, or was paged out
    return pfn_map[(page_va, target_pid)].pfn * 0x1000 | (va & 0xFFF)
```

The map is guaranteed **coherent as of the moment of the scan**. It
does drift — the OS pages things in and out — so if you need an
up-to-date translation you either rescan (cheap, one syscall + a
per-batch loop) or you rely on the fact that most kernel structures
you care about are non-pageable and their DTB → PT layout is stable.

The VA→PA use of Superfetch PFN data is documented in the prior work
by v1k1ngfr and Outflank (see §1). This section is included for
completeness.

## 7. Why Microsoft has not "fixed" this

The obvious question. Two things keep this interface open:

1. **SysMain depends on it.** SysMain's whole job is tracking which
   pages are hot, cold, prefetch-worthy, etc. It uses the very same
   info class this writeup abuses. Removing the class breaks SysMain
   (and, before that, the Prefetch/Superfetch feature stack Windows
   has shipped since Vista).
2. **The privilege boundary is `SeProfileSingleProcessPrivilege`,
   which Administrators already have.** From MSFT's threat-model
   perspective, an Administrator has already lost the perimeter —
   they can load a driver, install a service, dump the kernel via
   `\Device\PhysicalMemory`, or just call `NtSystemDebugControl`.
   Adding another kernel-info leak on top of that changes nothing
   in the model.

The result: this is a **known primitive, treated as by-design**. It
is not on any bug-bounty scope, it is not going to receive a CVE,
and it will continue to work in future Windows builds barring a
larger memory-manager overhaul.

Where this becomes actually interesting is: (a) any *non-Admin* path
to a Superfetch query would be a real vulnerability; and (b) the
privilege check itself is worth auditing — sub-class handlers have
had bugs before (e.g. CVE-2021-31969 was a Superfetch privilege
elevation on older builds).

## 8. Detection and defence

For blue-team readers:

- **Detect the primitive.** ETW / kernel-mode callbacks can observe
  calls to `NtQuerySystemInformation` with `SystemSuperfetchInformation`
  from processes that are **not** `SysMain` (`svchost.exe` hosting
  `sysmain.dll`). Legitimate callers are rare; a full PFN scan
  (millions of entries) from a non-SysMain process is a strong
  signal.
- **Detect the pattern.** A caller that enumerates the full
  `SuperfetchMemoryRangesQuery` output and then walks every range
  with `SuperfetchPfnQuery` is doing exactly the scan described
  here.
- **Remove the privilege.** If a machine does not need SysMain (e.g.
  a server), disable the service. `SeProfileSingleProcessPrivilege`
  is still assigned to `Administrators` by default; the audit-worthy
  restriction is per-user tokens, not the group grant.
- **VBS / HVCI.** Virtualization-Based Security does *not* close
  this specific primitive — the disclosure happens at the NT kernel
  boundary, not at the hypervisor. Nothing in the current MSFT
  security-boundary docs claims otherwise.

## 9. Reference implementation

The reference implementation lives in `Superfetch.ixx`. Notable
engineering choices:

- **Lazy scan.** `Init()` does only the fast range query (single
  syscall). The full PFN enumeration is deferred until a caller
  actually needs DTB / VA→PA lookups. Keeps startup cheap for
  callers that only need the physical memory map.
- **Batched PFN queries.** PFNs are queried in `0x10000` batches
  (256 MiB of physical address space at a time). Reduces per-syscall
  overhead vs. one-PFN-per-call; keeps the per-batch allocation
  bounded.
- **Self-ref detection heuristic.** Any PFN whose `Va` matches the
  four-equal-indices pattern and lives in the kernel half of the
  canonical VA range is assumed to be that process's PML4. This is
  cheap (integer compares only) and is what turns the raw PFN dump
  into a PID → DTB table — the core novel contribution.
- **`Shutdown()` scrubs the tables.** DTB values are treated as
  sensitive — `SecureZeroMemory` before the vectors are dropped so
  a heap-scanning follow-up doesn't recover them.

The implementation targets modern Win11 (`kSfVersion = 0x2D`). Two
older layouts (`RangeInfoV1` vs `V2`) are handled at query time via
the build number.

## 10. Further reading

- [**v1k1ngfr — "The SuperFetch Query superpower"**](https://v1k1ngfr.github.io/superfetchquery-superpower/)
  — Superfetch PFN queries for VA→PA translation, process enumeration,
  VM detection, and `_EPROCESS` leaking. The closest prior work to
  the primitive used here, but does not cover DTB/CR3 extraction
  via self-ref PML4 classification.
- [**Outflank — "Mapping Virtual to Physical Addresses Using Superfetch"**](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/)
  — Using Superfetch for VA→PA mapping in BYOVD scenarios.
- **Windows Internals 7e**, Yosifovich / Ionescu / Russinovich / Solomon
  — the Memory Manager chapters, particularly the sections on SysMain
  and page-table layout.
- [**blahcat — "Some toying with the Self-Reference PML4 Entry"**](https://blahcat.github.io/2020-06-15-playing-with-self-reference-pml4-entry/)
  — Background on what self-referencing PML4 entries are and how
  they work, independent of Superfetch.

---

If you have an earlier public reference to the self-ref PML4
classification technique applied to Superfetch PFN data, open an
issue — accurate attribution matters more than priority claims.
