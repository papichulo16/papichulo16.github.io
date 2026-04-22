---
layout: project
title: "RCA 1802 System Emulator"
description: "Embedded System Emulator for the RCA1802 chip"
project_tag: ctfs
---

[source](https://github.com/papichulo16/rca-cdp1802a-emu/)

# rca-cdp1802a-emu
## Embedded System Emulator and Cross-Assembler for the RCA CDP1802a chip

### About

This is a clock-cycle accurate hardware emulator and cross-assembler for the legacy RCA CDP1802a 8-bit microprocessor, made from scratch. 

The goal of this project is to not only emulate a very unique and old chip architecture, but also allow the user to have the ability to design and create embedded systems with multiple moving parts and CPUs that communicate with each other.

Features:
 - Cross-assembler for  RCA 1802 assembly
 - Emulator for the RCA 1802 chip
 - Independent system bus, MMIO, and (future) PMIO design
 - Architecture supporting independent, interacting parallel systems
 - YAML parsing for designing and testing custom embedded systems

