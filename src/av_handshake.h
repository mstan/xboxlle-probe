// SPDX-License-Identifier: MIT
// Bounded observation of the transaction used by original AvSetDisplayMode.
// Bits 0/4 are compared by that caller; their hardware meaning is the question,
// not an assumption established by this experiment. No register model here.
#ifndef XLLE_AV_HANDSHAKE_H
#define XLLE_AV_HANDSHAKE_H
#include <stdint.h>
#include <string.h>

#define AV_HANDSHAKE_ADDRESS 0xfd6806a0u
#define AV_HANDSHAKE_READ_LIMIT 100000u
#define AV_HANDSHAKE_TRACE_LIMIT 8u

typedef struct {
    void *context;
    uint64_t (*frequency)(void *);
    uint64_t (*clock)(void *);
    uint32_t (*read_word)(void *);
    void (*write_word)(void *, uint32_t);
} AvHandshakeOps;

typedef struct {
    uint64_t begin, end;
    uint32_t value;
} AvHandshakeSample;

typedef struct {
    const char *outcome;
    uint64_t frequency, origin, previous_clock, write_begin, write_end;
    uint32_t reads, writes, request, trace_count;
    AvHandshakeSample trace[AV_HANDSHAKE_TRACE_LIMIT], last;
} AvHandshakeResult;

static int av_handshake_clock(const AvHandshakeOps *ops, AvHandshakeResult *r,
                              uint64_t *elapsed) {
    uint64_t now = ops->clock(ops->context);
    if (now < r->previous_clock) {
        r->outcome = "counter_backwards";
        return 0;
    }
    r->previous_clock = now;
    *elapsed = now - r->origin;
    return 1;
}

static int av_handshake_sample(const AvHandshakeOps *ops, AvHandshakeResult *r) {
    AvHandshakeSample sample;
    if (!av_handshake_clock(ops, r, &sample.begin)) return 0;
    sample.value = ops->read_word(ops->context);
    ++r->reads;
    // Preserve the observed word even if its ending timestamp is invalid.
    sample.end = sample.begin;
    r->last = sample;
    if (!av_handshake_clock(ops, r, &sample.end)) return 0;
    r->last = sample;
    if (!r->trace_count || r->trace[r->trace_count-1].value != sample.value) {
        if (r->trace_count == AV_HANDSHAKE_TRACE_LIMIT) {
            r->outcome = "trace_limit";
            return 0;
        }
        r->trace[r->trace_count++] = sample;
    }
    if (sample.value & ~0x11u) {
        r->outcome = "unexpected_bits";
        return 0;
    }
    return 1;
}

static void av_handshake_run(int armed, int *attempted,
                             const AvHandshakeOps *ops, AvHandshakeResult *r) {
    memset(r, 0, sizeof(*r));
    r->outcome = "not_armed";
    if (!armed) return;
    r->outcome = "already_attempted";
    if (*attempted) return;
    *attempted = 1; // one attempt per agent lifetime, including failed attempts
    r->frequency = ops->frequency(ops->context);
    r->outcome = "counter_invalid";
    if (!r->frequency || r->frequency > UINT32_MAX) return;
    r->origin = r->previous_clock = ops->clock(ops->context);
    if (!av_handshake_sample(ops, r)) return;
    uint32_t initial = r->last.value;
    r->outcome = "initial_not_idle";
    if (initial != 0 && initial != 0x11) return;
    if (!av_handshake_sample(ops, r)) return;
    r->outcome = "initial_changed";
    if (r->last.value != initial) return;

    // The owned original caller writes precisely (~saved_value)&1. Do not
    // write back the observed status bit or change any mode/timing registers.
    if (!av_handshake_clock(ops, r, &r->write_begin)) return;
    r->write_end = r->write_begin;
    r->request = (~initial) & 1u;
    ops->write_word(ops->context, r->request);
    r->writes = 1;
    if (!av_handshake_clock(ops, r, &r->write_end)) return;
    const uint64_t limit = (r->frequency + 19) / 20; // 50 ms, rounded up
    for (uint32_t poll=0; poll<AV_HANDSHAKE_READ_LIMIT; ++poll) {
        uint64_t elapsed;
        if (!av_handshake_clock(ops, r, &elapsed)) return;
        r->outcome = "time_limit";
        if (elapsed - r->write_begin >= limit) return;
        if (!av_handshake_sample(ops, r)) return;
        if (r->last.end - r->write_begin >= limit) {
            r->outcome = "time_limit";
            return;
        }
        r->outcome = "request_not_observed";
        if ((r->last.value & 1u) != r->request) return;
        if (((r->last.value >> 4) & 1u) == r->request) {
            r->outcome = "ack_observed";
            return;
        }
    }
    r->outcome = "read_limit";
    // No second write, restoration attempt, mode reset, or automatic retry.
}
#endif
