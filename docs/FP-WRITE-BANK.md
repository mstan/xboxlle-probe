# Fixed one-pixel timing-register write-bank observation

Prepared under the owner's standing permission for read-only and benign volatile
writes. This uses the existing ARM/EXEC protocol and the running v0.4.0 agent.
No XBE upload or launch occurs. `beads-xbox.1.109.6` owns the investigation.

Earlier observations wrote HVALID_START with READ_PROG set and found a different
alternate read value even after AV acknowledgment. This distinct check writes
one pixel with READ_PROG clear to distinguish selected-bank, always-programmed,
broadcast, and ignored writes. Those four outcomes are observations, never
assumptions about which view is active video or how AV acknowledgment works.

The fixed payload requires the existing nxdk control10100111, totals935/524,
programmed and alternate HVALID_START0, and a stable AV phase0 or11. It uses at
most seven DWORD writes, only at FD680848 and FD680834. Selector changes preserve
all other control bits. The only window values are0 and1. It records both read
views, restores window0 in each selector view, restores the original selector,
and verifies both window values and unchanged AV phase. No AV request, clock,
sync, total, enable, GPIO, APU, boot, HDD, EEPROM or flash write occurs. A one-pixel
crop is the sole intended visible effect during the check.

Any unexpected value returns immediately, before another hardware operation;
it does not issue restoration writes after failure. The host preserves the raw
reply and does not retry or relaunch. A failed read can require a restart.
Every compiled instruction is checked offline using independent bank models,
all failed-read positions, exact allowed stores, caller state and host failures.

Register facts: envytools f102b823 nv3_pramdac.xml and Linuxv6.12
nouveau/dispnv04/nvreg.h. Bank-write behavior remains the question. Source and
payload identities and raw console data stay in ignored private results.
The existing EXEC protocol and one-shot AV latch are unchanged.
