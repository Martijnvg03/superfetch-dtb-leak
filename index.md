---
layout: default
---

# Enumerating Process CR3 Values from User Mode via Superfetch PFN Classification

**Turning a documented information-disclosure primitive into a full DTB enumerator by detecting self-referencing PML4 entries in Superfetch PFN data.**

> **Prior work and what is new.**
>
> The `NtQuerySystemInformation(SystemSuperfetchInformation)` interface and its ability to map PFNs to virtual addresses has been publicly documented:
>
> - [**v1k1ngfr**](https://v1k1ngfr.github.io/superfetchquery-superpower/) — "The SuperFetch Query superpower" — covers the Superfetch PFN query for VA-to-PA translation, VM sandbox detection, process enumeration, and `_EPROCESS` address leaking.
> - [**Outflank**](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/) — "Mapping Virtual to Physical Addresses Using Superfetch" — covers using the Superfetch PFN query for VA-to-PA translation in BYOVD exploitation scenarios.
> - **Pavel Yosifovich / Alex Ionescu / Mark Russinovich / David Solomon** — *Windows Internals 7e* — covers the SysMain service, PFN database, and page-table architecture.
>
> **What this writeup adds:** a technique for classifying Superfetch PFN data to detect **self-referencing PML4 entries**, which reveals every process's **DTB (CR3)** — the root of its page-table hierarchy — from user mode without any driver. The self-referencing PML4 detection heuristic applied to Superfetch data, and the resulting ability to enumerate all process DTBs and reconstruct the full page-table hierarchy in a single scan, is the novel contribution. The underlying Superfetch primitive is known; the application is new.

---

## Summary

- Any process holding `SeProfileSingleProcessPrivilege` (default for `Administrators`) can call `NtQuerySystemInformation` with the `SystemSuperfetchInformation` class.
- The SysMain (formerly Superfetch) service uses this interface to track working-set behavior. One of its sub-info classes returns, for a requested range of physical page frame numbers (PFNs), the **virtual address** each PFN is mapped at and the **owning process ID**.
- Prior work (v1k1ngfr, Outflank) demonstrated this can be used for VA-to-PA translation and `_EPROCESS` address leaking.
- **This writeup shows** that the same PFN data contains enough information to identify **self-referencing PML4 entries** — pages whose VA index pattern reveals them as page-table roots — which directly discloses the **DTB / CR3** of every process on the system.
- Combined with `SystemModuleInformation` for the kernel base, this yields a complete memory-forensics input set from user mode: the kernel's location, every process's CR3, and a full VA-to-PA map — no driver, no exploit, no memory corruption.
- Microsoft treats this as a **design tension, not a vulnerability**. Removing the interface would break SysMain, which depends on it for its core functionality.

---

## 1. Background: The Superfetch Information Interface

`NtQuerySystemInformation` is the Windows kernel's general-purpose "one syscall, many info classes" service. The `SystemSuperfetchInformation` class (id `79` on x64) is an internal multiplexer whose payload consists of a small header identifying a *sub-class* of query plus a caller-allocated buffer for the response:

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

The magic value is validated by the SysMain kernel logic — any caller that omits it receives an early `STATUS_INVALID_PARAMETER`. It is not a security boundary; the byte pattern is fixed and publicly known.

Two sub-classes are relevant:

| InfoClass | Name | Payload |
|-----------|------|---------|
| `17` | `SuperfetchMemoryRangesQuery` | An array of physical memory ranges (BasePfn + PageCount) |
| `6` | `SuperfetchPfnQuery` | For each requested PFN: `{Info, Pfn, Va}` where `Info` encodes the owning PID and `Va` is the virtual address the page is mapped at |

Sub-class 17 is a single syscall — it returns the physical memory map (usable RAM regions) that SysMain tracks.

Sub-class 6 is the core primitive. You submit a `Version=1` request structure followed by `Count` entries, each containing a PFN to query. The kernel populates the `Va` and `Info` fields. `(Info >> 9) & 0xFFFFFFFF` yields the owning process ID.

This primitive — querying PFNs to obtain VA + PID — is documented by [v1k1ngfr](https://v1k1ngfr.github.io/superfetchquery-superpower/) and [Outflank](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/). What follows is the new application.

## 2. What the Primitive Provides

For each populated physical page in the system, the query returns:

1. Which process owns it (by PID)
2. The virtual address at which it is currently mapped (in that process's address space, or in the system-wide kernel range)
3. Its physical address (trivially — you specified that PFN)

That constitutes a **complete physical-to-virtual reverse map** covering every page of RAM, obtainable in one enumeration. No driver, no `MmGetPhysicalMemoryRanges`, no access to `\Device\PhysicalMemory`, no debug port. Just a syscall the SysMain service invokes every few seconds.

## 3. Extracting Per-Process DTB / CR3 — The Novel Technique

Every process on x86-64 has a **directory table base** (DTB, stored in `CR3` while the process is scheduled). The DTB is the physical address of the root of that process's page-table hierarchy — the PML4. Knowing a process's DTB is the primitive that unlocks arbitrary virtual-to-physical translation within that process and, combined with a physical memory channel, arbitrary read/write of that process's address space.

Windows normally conceals DTBs behind kernel structures (`EPROCESS + Pcb.DirectoryTableBase`) that user mode has no legitimate means to read. The Superfetch primitive leaks them **implicitly**, through a property of how x86-64 page tables are organized:

### Self-Referencing PML4 Entries

To allow the kernel to walk and modify its own page tables uniformly, Windows installs a **self-referencing entry** in the PML4: one slot whose physical target is the PML4 page itself. When the CPU walks a virtual address whose PML4 index equals that slot, it re-enters the same PML4 at every level of the walk, and the final "data page" it dereferences is the PML4 page.

The consequence: the PML4 page (and the PDPT/PD/PT pages beneath it) all have a **canonical self-referencing VA** through which they are visible to the kernel. That VA has a distinctive structure — the same index repeated at every level of the walk:

```
Va = 0xFFFF | (idx << 39) | (idx << 30) | (idx << 21) | (idx << 12)
```

### The Classification Heuristic

The insight this writeup contributes: when you enumerate every PFN via Superfetch sub-class 6, the returned `Va` for page-table pages carries this self-referencing signature. By classifying every returned entry, you can identify each process's PML4 page — and its PFN *is* that process's DTB.

Concretely: for every PFN where the enumeration returns a `Va`, extract the four 9-bit indices:

```cpp
Pml4 = (Va >> 39) & 0x1FF;
Pdpt = (Va >> 30) & 0x1FF;
Pd   = (Va >> 21) & 0x1FF;
Pt   = (Va >> 12) & 0x1FF;
```

If all four are equal **and** the index is `>= 256` (kernel half of the canonical range), you are looking at that process's PML4 page — mapped through its self-referencing slot. The `Info.Pid` identifies the process, and `Pfn * PAGE_SIZE` is that process's **DTB**.

That is the entire disclosure. From one PFN scan:

```
for each PFN entry returned by Superfetch:
    if is_self_ref(entry.Va) and pml4_index(entry.Va) >= 256:
        dtb_table[entry.Pid] = entry.Pfn * PAGE_SIZE
```

No prior public documentation of this classification technique applied to Superfetch data was found at the time of writing.

## 4. Recovering the Full Page-Table Hierarchy

The DTB extraction in section 3 identifies the PML4 — the root — but the self-referencing entry exposes **every level** of the page-table tree. Once you know a process's self-referencing index `idx` (extracted from the PML4 detection), the same Superfetch PFN data classifies every PDPT, PD, and PT page that process owns. One scan, no driver, full hierarchy.

### How the Kernel Maps Its Own Page Tables

The self-referencing PML4 slot creates a set of **recursive virtual addresses** the kernel uses to access page-table pages as ordinary memory. Each additional level of self-referencing "absorbs" one level of the page walk, causing the final dereference to land on a deeper page-table structure:

| Target | VA Construction | CPU Walk |
|--------|----------------|----------|
| **PML4** | `idx, idx, idx, idx` + offset | self → self → self → self → PML4 page |
| **PDPT** of slot A | `idx, idx, idx, A` + offset | self → self → self → PML4[A] → PDPT page |
| **PD** of slot A,B | `idx, idx, A, B` + offset | self → self → PML4[A] → PDPT[B] → PD page |
| **PT** of slot A,B,C | `idx, A, B, C` + offset | self → PML4[A] → PDPT[B] → PD[C] → PT page |

The number of leading `idx` indices in the VA indicates the hierarchy level, and the remaining indices identify *which* page table at that level.

### Classifying Every PFN

For every entry the Superfetch scan returns, extract the four 9-bit VA indices as before (`Pml4`, `Pdpt`, `Pd`, `Pt`). If `Pml4 == idx` and `idx >= 256`, the page is a page-table page; the pattern of which indices equal `idx` determines the level:

```cpp
if (Pml4 == idx) {
    if (Pdpt == idx) {
        if (Pd == idx) {
            if (Pt == idx) {
                // Level 4: PML4 page (DTB) — covered in §3
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

After one pass, you have the physical address and hierarchical position of **every page-table page** the process owns — from the root PML4 down to individual PTs that map 2 MiB regions of the virtual address space.

### What This Yields

1. **Full page-table reconstruction.** You know the physical address of every PML4E, PDPTE, PDE, and PTE page. Given any physical memory read channel — the Superfetch VA-to-PA map itself, a BYOVD driver, DMA hardware — you can read the raw entries and reconstruct the complete virtual-to-physical mapping for any process. No `MmGetVirtualForPhysical`, no `!pte` in a debugger, no kernel symbols required.

2. **Page-table enumeration without walking.** Traditional page-table traversal is top-down: read PML4 → follow entry → read PDPT → follow entry → and so on. Each step requires a physical read. The Superfetch classification provides the same information *without walking* — you already know every PT page's physical address and its position in the hierarchy, from a single user-mode scan.

3. **Cross-process comparison.** Because the scan covers all processes simultaneously, you can distinguish which page-table pages are shared between processes (the kernel half, shared PDPT/PD mappings) versus private (user-mode page tables unique to each process). This is data that normally requires kernel debugger access.

4. **Detecting page-table manipulation.** Any unexpected topology — a PT page mapped at a VA that does not match the self-referencing pattern, or a PML4 page appearing under a PID where no process should exist — signals page-table remapping, PML4E grafting, or other manipulation relevant to forensic analysis.

### Worked Example

Assume process PID 1234 has self-referencing index `idx = 0x1AB` (decimal 427). The Superfetch scan returns these PFNs:

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

From these five entries alone (out of potentially thousands per process), you already know the physical address of the PML4, one user-mode PDPT, one kernel PDPT, a PD two levels down, and a PT three levels down — all without a single page-table read.

## 5. Defeating Kernel ASLR

KASLR randomizes the base at which `ntoskrnl.exe` and other kernel modules load. From a limited-user context, defeating this requires real effort. From Administrator, it does not — several APIs leak the base outright. The one used here is `NtQuerySystemInformation` with `SystemModuleInformation` (class `11`), which returns `RTL_PROCESS_MODULES` — a list of every loaded kernel module with its ImageBase.

That call has been the standard kernel base leak for over a decade and is not novel. It is unrelated to Superfetch but composes naturally with it: once you have `ntoskrnl.exe`'s base, you can locate `PsInitialSystemProcess`, walk `ActiveProcessLinks`, resolve any per-process kernel structure, or parse symbols out of the kernel image from user mode.

Combined with the DTB extraction from section 3 and the hierarchy map from section 4, you obtain:

- **Where the kernel is** (module base list)
- **What CR3 to use for translating its virtual addresses** (System process DTB, PID 4)
- **A full VA-to-PA map for every process** (the PFN scan itself)
- **The physical layout of every process's page tables** (the hierarchy classification)

This is the complete input set a memory-forensics tool requires to enumerate live kernel structures from user mode, without ever loading a driver.

## 6. Constructing a VA-to-PA Translator

You do not need to walk the PML4/PDPT/PD/PT hierarchy manually. The same scan that reveals DTBs already produced a table `{VA → PFN, PID}` for every mapped page in the system. To translate a virtual address in a target process:

```python
def va_to_pa(va, target_pid):
    page_va = va & ~0xFFF
    if (page_va, target_pid) not in pfn_map:
        return None                     # not mapped, or paged out
    return pfn_map[(page_va, target_pid)].pfn * 0x1000 | (va & 0xFFF)
```

The map is guaranteed **coherent as of the moment of the scan**. It drifts as the OS pages memory in and out, so if you need a current translation you either rescan (cheap — one syscall plus a per-batch loop) or rely on the fact that most kernel structures of interest are non-pageable and their DTB-to-PT layout is stable.

The VA-to-PA use of Superfetch PFN data is documented in the prior work by v1k1ngfr and Outflank (see section 1). This section is included for completeness.

## 7. Why Microsoft Has Not Removed This Interface

The obvious question. Two factors keep this interface open:

1. **SysMain depends on it.** SysMain's core function is tracking which pages are hot, cold, or prefetch-worthy. It uses the exact same info class this writeup leverages. Removing the class breaks SysMain — and with it, the Prefetch/Superfetch feature stack Windows has shipped since Vista.
2. **The privilege boundary is `SeProfileSingleProcessPrivilege`, which Administrators already hold.** From Microsoft's threat-model perspective, an Administrator has already breached the perimeter — they can load a driver, install a service, access `\Device\PhysicalMemory`, or invoke `NtSystemDebugControl`. Another kernel information leak changes nothing in the model.

The result: this is a **known primitive, treated as by-design**. It is not within any bug-bounty scope, it will not receive a CVE, and it will continue to function in future Windows builds barring a larger memory-manager redesign.

Where this becomes genuinely interesting: (a) any *non-Administrator* path to a Superfetch query would constitute a real vulnerability; and (b) the privilege check itself warrants auditing — sub-class handlers have had bugs before (e.g., CVE-2021-31969 was a Superfetch privilege escalation on older builds).

## 8. Detection and Defense

For blue-team readers:

- **Detect the primitive.** ETW or kernel-mode callbacks can observe calls to `NtQuerySystemInformation` with `SystemSuperfetchInformation` from processes that are **not** `SysMain` (`svchost.exe` hosting `sysmain.dll`). Legitimate callers are rare; a full PFN scan (millions of entries) from a non-SysMain process is a strong signal.
- **Detect the pattern.** A caller that enumerates the full `SuperfetchMemoryRangesQuery` output and then walks every range with `SuperfetchPfnQuery` is performing exactly the scan described here.
- **Remove the privilege.** If a machine does not need SysMain (e.g., a server), disable the service. `SeProfileSingleProcessPrivilege` is assigned to `Administrators` by default; the audit-relevant restriction is per-user token assignment, not the group grant.
- **VBS / HVCI.** Virtualization-Based Security does *not* close this particular primitive — the disclosure occurs at the NT kernel boundary, not at the hypervisor. Nothing in current Microsoft security-boundary documentation claims otherwise.

## 9. Further Reading

- [**v1k1ngfr — "The SuperFetch Query superpower"**](https://v1k1ngfr.github.io/superfetchquery-superpower/) — Superfetch PFN queries for VA-to-PA translation, process enumeration, VM detection, and `_EPROCESS` leaking. The closest prior work to the primitive used here, but does not cover DTB/CR3 extraction via self-referencing PML4 classification.
- [**Outflank — "Mapping Virtual to Physical Addresses Using Superfetch"**](https://www.outflank.nl/blog/2023/12/14/mapping-virtual-to-physical-adresses-using-superfetch/) — Using Superfetch for VA-to-PA mapping in BYOVD scenarios.
- **Windows Internals 7e**, Yosifovich / Ionescu / Russinovich / Solomon — the Memory Manager chapters, particularly the sections on SysMain and page-table layout.
- [**blahcat — "Some toying with the Self-Reference PML4 Entry"**](https://blahcat.github.io/2020-06-15-playing-with-self-reference-pml4-entry/) — Background on what self-referencing PML4 entries are and how they work, independent of Superfetch.

---

If you have an earlier public reference to the self-referencing PML4 classification technique applied to Superfetch PFN data, please open an issue — accurate attribution matters more than priority claims.
