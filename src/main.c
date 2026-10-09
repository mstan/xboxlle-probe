// SPDX-License-Identifier: MIT
//
// xboxlle-probe — a deliberately dangerous resident hardware probe for a real original Xbox.
//
// WARNING: This service has no authentication or encryption. After explicit per-session
// arming, it permits guarded memory/MMIO reads, writes, and arbitrary x86 payload execution.
// Run only on an isolated trusted network. A bad operation can crash, corrupt, or brick the
// console. USE AT YOUR OWN RISK. See README.md, SECURITY.md, and LICENSE.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <hal/debug.h>
#include <hal/video.h>
#include <hal/xbox.h>
#include <lwip/sockets.h>
#include <nxdk/net.h>
#include <xboxkrnl/xboxkrnl.h>
#include "av_handshake.h"

extern struct netif *g_pnetif;

#define AGENT_PORT 4380
#define AGENT_VER "xboxlle-probe v0.4.0"
#define MAX_RW 4096
#define MAX_BULK (1u << 20)

static int send_all(int fd, const void *data, int len) {
    const char *p = (const char *)data;
    int sent = 0;
    while (sent < len) {
        int n = send(fd, p + sent, len - sent, 0);
        if (n <= 0) return n;
        sent += n;
    }
    return sent;
}

static void send_str(int fd, const char *s) {
    send_all(fd, s, (int)strlen(s));
}

static int hexnib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *s, uint8_t *out, int maxout) {
    int n = 0;
    while (s[0] && s[1] && n < maxout) {
        int hi = hexnib(s[0]);
        int lo = hexnib(s[1]);
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
        s += 2;
    }
    return (*s == '\0') ? n : -1;
}

static void bytes_to_hex(const uint8_t *in, int n, char *out) {
    static const char *digits = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
    out[2 * n] = '\0';
}

// v0.2 guard retained from the hardware-tested ancestor. This is a crash-reduction measure,
// not a promise that every allowed read is harmless on every Xbox revision.
static int addr_readable(uint32_t address, uint32_t len) {
    uint32_t end = address + len;
    if (len == 0 || end < address) return 0;
    if (address >= 0xFD000000 && end <= 0xFE000000) return 1;
    if (address >= 0xFF000000 && end <= 0xFFFFFE00) return 1;
    if (end <= 0x08000000) {
        for (uint32_t page = address & ~0xFFFu; page < end; page += 0x1000) {
            if (!MmIsAddressValid((PVOID)(uintptr_t)page)) return 0;
        }
        return 1;
    }
    return 0;
}

// Flash is intentionally excluded. EXEC can bypass this and must be treated as full control.
static int addr_writable(uint32_t address, uint32_t len) {
    uint32_t end = address + len;
    if (len == 0 || end < address) return 0;
    if (address >= 0xFD000000 && end <= 0xFE000000) return 1;
    if (end <= 0x08000000) {
        for (uint32_t page = address & ~0xFFFu; page < end; page += 0x1000) {
            if (!MmIsAddressValid((PVOID)(uintptr_t)page)) return 0;
        }
        return 1;
    }
    return 0;
}

static int recv_line(int fd, char *buf, int max) {
    int n = 0;
    while (n < max - 1) {
        char c;
        int r = recv(fd, &c, 1, 0);
        if (r <= 0) return n > 0 ? n : r;
        if (c == '\n') break;
        if (c != '\r') buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

static int recv_all(int fd, uint8_t *buf, int len) {
    int got = 0;
    while (got < len) {
        int n = recv(fd, (char *)buf + got, len - got, 0);
        if (n <= 0) return n;
        got += n;
    }
    return got;
}

static void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx) {
    __asm__ volatile("cpuid"
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                     : "a"(leaf));
}

static void probe_cpu(int fd, char *reply, size_t reply_size) {
    uint32_t max_leaf, vendor_b, vendor_c, vendor_d;
    uint32_t signature = 0, unused_b = 0, features_c = 0, features_d = 0;
    char vendor[13];

    cpuid(0, &max_leaf, &vendor_b, &vendor_c, &vendor_d);
    memcpy(vendor + 0, &vendor_b, 4);
    memcpy(vendor + 4, &vendor_d, 4);
    memcpy(vendor + 8, &vendor_c, 4);
    vendor[12] = '\0';
    if (max_leaf >= 1) {
        cpuid(1, &signature, &unused_b, &features_c, &features_d);
    }

    snprintf(reply, reply_size,
             "{\"probe\":\"cpu\",\"agent\":\"%s\",\"vendor\":\"%s\","
             "\"max_leaf\":%u,\"signature\":\"0x%08x\","
             "\"features_edx\":\"0x%08x\",\"features_ecx\":\"0x%08x\"}\n",
             AGENT_VER, vendor, max_leaf, signature, features_d, features_c);
    send_str(fd, reply);
}

static uint32_t mmio_read32(uint32_t address) {
    return *(volatile const uint32_t *)(uintptr_t)address;
}

static uint64_t av_probe_frequency(void *unused) { (void)unused; return KeQueryPerformanceFrequency(); }
static uint64_t av_probe_clock(void *unused) { (void)unused; return KeQueryPerformanceCounter(); }
static uint32_t av_probe_read(void *unused) { (void)unused; return mmio_read32(AV_HANDSHAKE_ADDRESS); }
static void av_probe_write(void *unused, uint32_t value) {
    (void)unused;
    *(volatile uint32_t *)(uintptr_t)AV_HANDSHAKE_ADDRESS = value;
}

static void probe_av_handshake(int fd, int armed, char *reply, size_t reply_size) {
    static int attempted; // survives connections; even a failed attempt consumes it
    const AvHandshakeOps ops = {NULL, av_probe_frequency, av_probe_clock,
                               av_probe_read, av_probe_write};
    AvHandshakeResult result;
    av_handshake_run(armed, &attempted, &ops, &result);
    if (!strcmp(result.outcome, "not_armed")) { send_str(fd, "ERR not armed\n"); return; }
    if (!strcmp(result.outcome, "already_attempted")) {
        send_str(fd, "ERR AV probe already attempted; human inspection required\n"); return;
    }
    int n = snprintf(reply, reply_size,
        "{\"probe\":\"av_handshake\",\"schema\":1,\"agent\":\"%s\","
        "\"kernel\":\"%u.%u.%u.%u\",\"address\":\"0xfd6806a0\","
        "\"outcome\":\"%s\",\"frequency\":%llu,\"reads\":%u,\"writes\":%u,"
        "\"request\":%u,\"write_ticks\":[%llu,%llu],\"trace\":[", AGENT_VER,
        XboxKrnlVersion.Major, XboxKrnlVersion.Minor, XboxKrnlVersion.Build, XboxKrnlVersion.Qfe,
        result.outcome, (unsigned long long)result.frequency, result.reads, result.writes, result.request,
        (unsigned long long)result.write_begin, (unsigned long long)result.write_end);
    for (uint32_t i=0; i<result.trace_count && n>0 && (size_t)n<reply_size; ++i) {
        AvHandshakeSample *s = &result.trace[i];
        n += snprintf(reply+n, reply_size-n, "%s[%llu,%llu,%u]", i?",":"",
                      (unsigned long long)s->begin, (unsigned long long)s->end, s->value);
    }
    if (n>0 && (size_t)n<reply_size) {
        n += snprintf(reply+n, reply_size-n, "],\"last\":[%llu,%llu,%u]}\n",
                      (unsigned long long)result.last.begin,
                      (unsigned long long)result.last.end, result.last.value);
    }
    if (n<=0 || (size_t)n>=reply_size) send_str(fd, "ERR AV observation serialization\n");
    else send_str(fd, reply);
}

static void probe_nv2a(int fd, char *reply, size_t reply_size) {
    // Fixed read-only registers measured successfully on the original v1.1 test console.
    uint32_t pmc_boot = mmio_read32(0xFD000000);
    uint32_t pmc_intr = mmio_read32(0xFD000100);
    uint32_t pmc_enable = mmio_read32(0xFD000200);
    uint32_t pfb_cfg0 = mmio_read32(0xFD100000);
    uint32_t pfb_cstatus = mmio_read32(0xFD100200);
    uint32_t ptimer_num = mmio_read32(0xFD009200);
    uint32_t ptimer_den = mmio_read32(0xFD009210);
    uint32_t nvpll = mmio_read32(0xFD680500);
    uint32_t mpll = mmio_read32(0xFD680504);
    uint32_t vpll = mmio_read32(0xFD680508);

    snprintf(reply, reply_size,
             "{\"probe\":\"nv2a\",\"agent\":\"%s\","
             "\"pmc_boot_0\":\"0x%08x\",\"pmc_intr_0\":\"0x%08x\","
             "\"pmc_enable\":\"0x%08x\",\"pfb_cfg0\":\"0x%08x\","
             "\"pfb_cstatus\":\"0x%08x\",\"ptimer_num\":\"0x%08x\","
             "\"ptimer_den\":\"0x%08x\",\"nvpll\":\"0x%08x\","
             "\"mpll\":\"0x%08x\",\"vpll\":\"0x%08x\"}\n",
             AGENT_VER, pmc_boot, pmc_intr, pmc_enable, pfb_cfg0, pfb_cstatus,
             ptimer_num, ptimer_den, nvpll, mpll, vpll);
    send_str(fd, reply);
}

// This is a capability sentinel, not a Controller S evidence probe.  The
// agent's USB stack is not initialized, so it must not inspect a device list,
// issue a USB transfer, access OHCI, or infer hub/descriptors from any other
// source.  It exists so callers can distinguish this unsupported capability
// from an empty or guessed hardware capture.
static void probe_controller_s_hub(int fd, char *reply, size_t reply_size) {
    snprintf(reply, reply_size,
             "{\"probe\":\"controller_s_hub\",\"agent\":\"%s\","
             "\"available\":false,\"hardware_inspected\":false,"
             "\"usb_traffic\":false,\"reason\":\"agent_usb_stack_not_initialized\","
             "\"device_descriptor\":null,\"configuration_descriptor\":null,"
             "\"hub_class_descriptor\":null,\"hub_status\":null,"
             "\"downstream_port_1_status\":null,"
             "\"downstream_port_1_enumeration\":null}\n",
             AGENT_VER);
    send_str(fd, reply);
}

static void handle_client(int fd) {
    static char line[MAX_RW * 2 + 64];
    static uint8_t rw[MAX_RW];
    static char reply[MAX_RW * 2 + 512];
    int armed = 0;

    for (;;) {
        int n = recv_line(fd, line, sizeof(line));
        if (n <= 0) return;

        if (!strcmp(line, "PING")) {
            send_str(fd, "PONG " AGENT_VER "\n");
        } else if (!strcmp(line, "INFO")) {
            snprintf(reply, sizeof(reply),
                     "{\"agent\":\"%s\",\"kernel\":\"%u.%u.%u.%u\","
                     "\"tick\":%u,\"port\":%d,\"armed\":%s}\n",
                     AGENT_VER, XboxKrnlVersion.Major, XboxKrnlVersion.Minor,
                     XboxKrnlVersion.Build, XboxKrnlVersion.Qfe,
                     (unsigned)KeTickCount, AGENT_PORT, armed ? "true" : "false");
            send_str(fd, reply);
        } else if (!strcmp(line, "STATUS")) {
            send_str(fd, armed ? "ARMED\n" : "SAFE\n");
        } else if (!strcmp(line, "ARM I_ACCEPT_THE_RISK")) {
            armed = 1;
            send_str(fd, "ARMED\n");
        } else if (!strcmp(line, "PROBE CPU")) {
            probe_cpu(fd, reply, sizeof(reply));
        } else if (!strcmp(line, "PROBE NV2A")) {
            probe_nv2a(fd, reply, sizeof(reply));
        } else if (!strcmp(line, "PROBE CONTROLLER_S_HUB")) {
            probe_controller_s_hub(fd, reply, sizeof(reply));
        } else if (!strcmp(line, "AV_HANDSHAKE")) {
            probe_av_handshake(fd, armed, reply, sizeof(reply));
            return; // no further commands in this observation connection
        } else if (!strncmp(line, "RB ", 3)) {
            uint32_t address = 0, len = 0;
            if (!armed) {
                send_str(fd, "ERR not armed\n");
            } else if (sscanf(line + 3, "%x %u", &address, &len) == 2 &&
                len > 0 && len <= MAX_BULK && addr_readable(address, len)) {
                snprintf(reply, sizeof(reply), "OK %u\n", len);
                send_str(fd, reply);
                send_all(fd, (const void *)(uintptr_t)address, (int)len);
            } else {
                send_str(fd, "ERR bad/unsafe addr\n");
            }
        } else if (!strncmp(line, "R ", 2)) {
            uint32_t address = 0;
            int len = 0;
            if (!armed) {
                send_str(fd, "ERR not armed\n");
            } else if (sscanf(line + 2, "%x %d", &address, &len) == 2 &&
                len > 0 && len <= MAX_RW && addr_readable(address, (uint32_t)len)) {
                memcpy(rw, (const void *)(uintptr_t)address, len);
                bytes_to_hex(rw, len, reply);
                send_str(fd, "OK ");
                send_str(fd, reply);
                send_str(fd, "\n");
            } else {
                send_str(fd, "ERR bad/unsafe addr\n");
            }
        } else if (!strncmp(line, "W ", 2)) {
            uint32_t address = 0;
            char hexbytes[MAX_RW * 2 + 1];
            if (!armed) {
                send_str(fd, "ERR not armed\n");
            } else if (sscanf(line + 2, "%x %8192s", &address, hexbytes) == 2) {
                int count = hex_to_bytes(hexbytes, rw, MAX_RW);
                if (count > 0 && addr_writable(address, (uint32_t)count)) {
                    memcpy((void *)(uintptr_t)address, rw, count);
                    snprintf(reply, sizeof(reply), "OK %d\n", count);
                    send_str(fd, reply);
                } else {
                    send_str(fd, "ERR bad hex / unsafe addr\n");
                }
            } else {
                send_str(fd, "ERR bad args\n");
            }
        } else if (!strncmp(line, "EXEC ", 5)) {
            int len = atoi(line + 5);
            if (!armed) {
                send_str(fd, "ERR not armed\n");
            } else if (len > 0 && len <= (int)MAX_BULK) {
                uint8_t *code = malloc((size_t)len);
                if (code && recv_all(fd, code, len) == len) {
                    int (*function)(void) = (int (*)(void))code;
                    int result = function();
                    snprintf(reply, sizeof(reply), "RET %x\n", (unsigned)result);
                    send_str(fd, reply);
                } else {
                    send_str(fd, "ERR payload\n");
                }
                free(code);
            } else {
                send_str(fd, "ERR bad len\n");
            }
        } else if (!strncmp(line, "L ", 2)) {
            if (!armed) {
                send_str(fd, "ERR not armed\n");
            } else {
                send_str(fd, "LAUNCHING\n");
                XLaunchXBE(line + 2);
                send_str(fd, "ERR launch failed\n");
            }
        } else if (!strcmp(line, "DASH")) {
            if (!armed) {
                send_str(fd, "ERR not armed\n");
            } else {
                send_str(fd, "RETURNING\n");
                XLaunchXBE("C:\\evoxdash.xbe");
            }
        } else if (!strcmp(line, "QUIT")) {
            return;
        } else {
            send_str(fd, "ERR unknown\n");
        }
    }
}

int main(void) {
    XVideoSetMode(640, 480, 32, REFRESH_DEFAULT);
    debugClearScreen();
    debugPrint("============================================================\n");
    debugPrint(" DANGER: xboxlle-probe provides low-level hardware access.\n");
    debugPrint(" It can CRASH, CORRUPT, or BRICK this Xbox.\n");
    debugPrint(" NO AUTHENTICATION. TRUSTED ISOLATED NETWORKS ONLY.\n");
    debugPrint(" USE AT YOUR OWN RISK. NO WARRANTY.\n");
    debugPrint("============================================================\n");
    debugPrint("%s\n", AGENT_VER);
    debugPrint("Starting in 8 seconds. Power off now to cancel.\n");
    Sleep(8000);

    debugPrint("bringing up network...\n");
    nxNetInit(NULL);
    debugPrint("IP: %s\n", ip4addr_ntoa(netif_ip4_addr(g_pnetif)));

    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        debugPrint("socket failed\n");
        Sleep(5000);
        return 1;
    }

    int yes = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(AGENT_PORT);

    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0) {
        debugPrint("bind failed\n");
        closesocket(listener);
        Sleep(5000);
        return 1;
    }

    listen(listener, 2);
    debugPrint("listening on tcp/%d (NO AUTHENTICATION)\n", AGENT_PORT);
    debugPrint("Raw access and title control require per-session ARM.\n");

    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) continue;
        debugPrint("client connected (session SAFE)\n");
        handle_client(client);
        closesocket(client);
        debugPrint("client disconnected\n");
    }

    return 0;
}
