# Hardware Implementation of an AES-128 Encryption Scheme on a CMOD-A7

This repository contains a hardware implementation of an **AES-128 encryption engine** targeting the **CMOD-A7 FPGA** platform.

## Repository Structure

- **`/src/`** — All hardware (HDL, block design, IP) and software source files.  
- **`/eval/`** — Sample benchmarking results collected on a **CMOD-A7-35T** using **UART @ 115200 8N1**.  
- **`/bd/`** — Reference block design used for synthesis and testing.

## Overview

The AES-128 core is packaged as an independent IP block that can be instantiated directly in any design.  
It also integrates cleanly with a **MicroBlaze soft-core**, for which a minimal benchmarking script is provided.

The included benchmarking utility communicates through the **MicroBlaze UART**, but can be adapted to any interface with compatible characteristics.

---

## Recreating the Design

> **Note:** The bitstream (`.bit`) and ELF (`.elf`) included in the repository were generated using **Vivado/Vitis 2022.1**.

1. Create a block diagram based on the design shown in the `/bd` directory.
2. Configure the **MicroBlaze MCS** IP with the following settings:
   - **BRAM:** ≥ 32 KB  
   - **PIT1:** Enabled (Readable)  
   - **UART:** RX & TX enabled, **115200 baud**, **8-bit**  
   - **IO Bus:** Enabled  
   - **GPO1:** Enabled (1-bit, used for LED indication)
3. Ensure the design is clocked at **125 MHz**.  
   The AES core block was generated using the **Vivado IP Packager**.
4. Export the .xsa to Vitis and generate a .elf -> Associate with MicroBlaze MCS and Generate Bitstream.
5. For the CMOD A7, the Micro-USB Port can be used directly as long as the device is not being programmed.

---


 

