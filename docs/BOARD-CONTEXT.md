# Fixed read-only board context

The owner authorized read-only checks and benign writes without repeated
confirmation on 2026-10-10; dangerous operations should be avoided. The
existing ARM gate and exact owner-supplied target requirement remain intact.
Authorization is session-specific; this document does not authorize another
operator's session.

`host/read_board_context.py` verifies the existing v0.4.0 agent and sends five
fixed ARM-guarded EXEC payloads. Four are six-byte `MOV EAX,[address]; RET`
reads: AV FD6806A0, PLL_CONTROL FD68050C, FE fence control FE801510, then AV
FD6806A0 again. The GPIO15 payload is twelve bytes:
`9C 52 66 BA CF 80 31 C0 EC 5A 9D C3`,
`PUSHFD; PUSH EDX; MOV DX,80CF; XOR EAX,EAX; IN AL,DX; POP EDX; POPFD; RET`.
It preserves EDX and flags and returns a zero-extended GPIO control byte.
Only normal stack saves write RAM. Neither payload form writes MMIO or an I/O
port. No upload, launch, mode change, AV request, FE command, APU DMA, flash,
EEPROM or storage operation is sent.

The [hardware design specification 1.02, section 2.6.5](https://consolemods.org/wiki/images/a/ae/Xbox_Hardware_Design_Specification_1.02.pdf)
assigns GPIO15 to development-system flash programming and leaves it
unconnected in the retail design. This is why no experimental GPIO output
is included. Pin assignment is not proof of the owner's board wiring, nor
of GPIO register encoding. The existing source investigation maps GPIO
controls at ACPI base + C0 + pin; the actual byte is recorded as an
observation, not a reset default.

[Pinned envytools PRAMDAC register definitions](https://github.com/envytools/envytools/blob/f102b82381f3f11cee113d16374c87091db039d9/rnndb/display/nv3_pramdac.xml)
identify PLL_CONTROL, including TV_PCLK. The FE control address comes from
the preserved original Blinx fence helper. Reading its current value does
not establish toggle semantics, required-before-publication work, or DMA
ordering.

The host creates a fresh private output directory, preserves replies before
validation and stops after identity/ARM failure, timeout, malformed return,
all-ones values, invalid GPIO width or unstable AV endpoints. There is no
retry, restore, reboot or relaunch. The batch is non-atomic current context,
not a fence or clock-edge measurement. Raw results stay private.
