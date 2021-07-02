---
title: Package Metadata for Core Files
category: Interfaces
layout: default
---

# Package Metadata for Core Files

*Intended audience: hackers working on userspace subsystems that create ELF binaries
or parse ELF core files.*

## Motivation

ELF binaries get stamped with a unique, build-time generated hex string identifier called
`build-id`, [which gets embedded as an ELF note called `.note.gnu.build-id`](https://fedoraproject.org/wiki/Releases/FeatureBuildId).
In most cases, this allows to associate a stripped binary with its debugging information.
It is used, for example, to dynamically fetch DWARF symbols from a debuginfo server, or
to query the local package manager and find out the package metadata or, again, the DWARF
symbols or program sources.

However, this usage of the `build-id` requires either local metadata, usually set up by
the package manager, or access to a remote server over the network. Both of those might
be unavailable or forbidden.

Thus it becomes desirable to add additional metadata to a binary at build time, so that
`systemd-coredump` and other services analyzing core files are able to extract said
metadata simply from the core file itself, without external dependencies.

## Implementation

This document will attempt to define a common metadata format specification, so that
multiple implementers might use it when building packages, or core file analyzers, and
so on.

The metadata will be embedded in a single, new ELF header section, in a key-value JSON
format. Implementers working on parsing core files should not assume a specific list of
keys, but parse anything that is included in the section.
Implementers working on build tools should strive to use the same key names, for
consistency. The most common will be listed here. When corresponding to the content of
os-release, the values should match, again for consistency.

* Section header

```
SECTION: `.note.package`
node-id: `0xcafe1a7e`
Owner: `FDO` (FreeDesktop.org)
Value: a JSON string with the structure described below
```

* JSON payload

```json
{
     "type":"rpm",          # this provides a namespace for the package+package-version fields
     "os":"fedora",
     "osVersion":"33",
     "name":"coreutils",
     "version": "4711.0815.fc13.arm32",
     "osCpe":               # A CPE name for the operating system, `CPE_NAME` from os-release is a good default
}
```

A reference implementations of a [build-time tool is provided](https://github.com/systemd/package-notes)
and can be used to generate a linker script, which can then be used at build time via
```LDFLAGS="-Wl,-T,/path/to/generated/script"``` to include the note in the binary.

Generator:
```console
$ ./generate-package-notes.py --rpm systemd-248~rc2-1.fc34
SECTIONS
{
    .note.package : ALIGN(4) {
        BYTE(0x04) BYTE(0x00) BYTE(0x00) BYTE(0x00) /* Length of Owner including NUL */
        BYTE(0x64) BYTE(0x00) BYTE(0x00) BYTE(0x00) /* Length of Value including NUL */
        BYTE(0x7e) BYTE(0x1a) BYTE(0xfe) BYTE(0xca) /* Note ID */
        BYTE(0x46) BYTE(0x44) BYTE(0x4f) BYTE(0x00) /* Owner: 'FDO\x00' */
        BYTE(0x7b) BYTE(0x22) BYTE(0x74) BYTE(0x79) /* Value: '{"type":"rpm","name":"systemd","version":"248~rc2-1.fc34","osCpe":"cpe:/o:fedoraproject:fedora:33"}\x00' */
        BYTE(0x70) BYTE(0x65) BYTE(0x22) BYTE(0x3a)
        BYTE(0x22) BYTE(0x72) BYTE(0x70) BYTE(0x6d)
        BYTE(0x22) BYTE(0x2c) BYTE(0x22) BYTE(0x6e)
        BYTE(0x61) BYTE(0x6d) BYTE(0x65) BYTE(0x22)
        BYTE(0x3a) BYTE(0x22) BYTE(0x73) BYTE(0x79)
        BYTE(0x73) BYTE(0x74) BYTE(0x65) BYTE(0x6d)
        BYTE(0x64) BYTE(0x22) BYTE(0x2c) BYTE(0x22)
        BYTE(0x76) BYTE(0x65) BYTE(0x72) BYTE(0x73)
        BYTE(0x69) BYTE(0x6f) BYTE(0x6e) BYTE(0x22)
        BYTE(0x3a) BYTE(0x22) BYTE(0x32) BYTE(0x34)
        BYTE(0x38) BYTE(0x7e) BYTE(0x72) BYTE(0x63)
        BYTE(0x32) BYTE(0x2d) BYTE(0x31) BYTE(0x2e)
        BYTE(0x66) BYTE(0x63) BYTE(0x33) BYTE(0x34)
        BYTE(0x22) BYTE(0x2c) BYTE(0x22) BYTE(0x6f)
        BYTE(0x73) BYTE(0x43) BYTE(0x70) BYTE(0x65)
        BYTE(0x22) BYTE(0x3a) BYTE(0x22) BYTE(0x63)
        BYTE(0x70) BYTE(0x65) BYTE(0x3a) BYTE(0x2f)
        BYTE(0x6f) BYTE(0x3a) BYTE(0x66) BYTE(0x65)
        BYTE(0x64) BYTE(0x6f) BYTE(0x72) BYTE(0x61)
        BYTE(0x70) BYTE(0x72) BYTE(0x6f) BYTE(0x6a)
        BYTE(0x65) BYTE(0x63) BYTE(0x74) BYTE(0x3a)
        BYTE(0x66) BYTE(0x65) BYTE(0x64) BYTE(0x6f)
        BYTE(0x72) BYTE(0x61) BYTE(0x3a) BYTE(0x33)
        BYTE(0x33) BYTE(0x22) BYTE(0x7d) BYTE(0x00)
    }
}
INSERT AFTER .note.gnu.build-id;
```
