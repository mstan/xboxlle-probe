// SPDX-License-Identifier: MIT
// Execute the actual probe controller with hardware-free scripted callbacks.
#include "../src/av_handshake.h"
#include <assert.h>
#include <stdio.h>

typedef struct {
    uint32_t words[12], count, index, writes, written;
    uint64_t tick, step, frequency;
    unsigned clock_calls, reverse_at;
} Mock;
static uint64_t frequency(void *p) { return ((Mock*)p)->frequency; }
static uint64_t clock_tick(void *p) {
    Mock *m=p;
    if (++m->clock_calls==m->reverse_at) return 0;
    uint64_t result=m->tick;
    m->tick+=m->step;
    return result;
}
static uint32_t read_word(void *p) {
    Mock *m=p;
    uint32_t index=m->index++;
    return m->words[index<m->count?index:m->count-1];
}
static void write_word(void *p, uint32_t v) { Mock *m=p; ++m->writes; m->written=v; }
static Mock fixture(uint32_t initial, uint32_t pending, uint32_t ack) {
    Mock m={0}; m.words[0]=m.words[1]=initial; m.words[2]=pending; m.words[3]=ack;
    m.count=4; m.step=1; m.tick=100; m.frequency=1000000;
    return m;
}
static AvHandshakeResult run(Mock *m, int armed, int *attempted) {
    AvHandshakeOps ops={m,frequency,clock_tick,read_word,write_word};
    AvHandshakeResult r; av_handshake_run(armed,attempted,&ops,&r); return r;
}
static void outcome(AvHandshakeResult r, const char *expected) {
    if (strcmp(r.outcome, expected)) { fprintf(stderr,"%s != %s\n",r.outcome,expected); assert(0); }
}
int main(void) {
    for(unsigned initial=0;initial<2;++initial) {
        Mock m=fixture(initial*0x11,initial?0x10:1,initial?0:0x11);
        int attempted=0;
        outcome(run(&m,0,&attempted),"not_armed");
        assert(!attempted && !m.index && !m.writes && !m.clock_calls);
        AvHandshakeResult r=run(&m,1,&attempted);
        outcome(r,"ack_observed");
        assert(attempted && m.writes==1 && m.written==(initial^1));
        assert(r.reads==4 && r.writes==1 && r.trace_count==3);
        assert(r.trace[1].value==(initial?0x10:1) && r.last.value==(initial?0:0x11));
        unsigned calls=m.clock_calls;
        outcome(run(&m,1,&attempted),"already_attempted");
        assert(m.index==4 && m.writes==1 && m.clock_calls==calls);
    }
    {
        Mock m=fixture(0,0x11,0x11); int once=0;
        AvHandshakeResult r=run(&m,1,&once); outcome(r,"ack_observed");
        assert(r.reads==3 && r.trace_count==2); // no invented pending sample
    }
    for(unsigned scenario=0;scenario<8;++scenario) {
        Mock m=fixture(0,1,0x11); int once=0;
        const char *expected="";
        switch(scenario) {
        case 0: m.words[0]=1; expected="initial_not_idle"; break;
        case 1: m.words[1]=0x11; expected="initial_changed"; break;
        case 2: m.words[0]=0x80; expected="unexpected_bits"; break;
        case 3: m.frequency=0; expected="counter_invalid"; break;
        case 4: m.reverse_at=3; expected="counter_backwards"; break;
        case 5: m.words[2]=0; expected="request_not_observed"; break;
        case 6: m.words[2]=0x81; expected="unexpected_bits"; break;
        case 7: m.reverse_at=8; expected="counter_backwards"; break;
        }
        AvHandshakeResult r=run(&m,1,&once); outcome(r,expected);
        assert(once && m.writes==(scenario>=5));
        unsigned reads=m.index, writes=m.writes;
        outcome(run(&m,1,&once),"already_attempted");
        assert(m.index==reads && m.writes==writes);
    }
    {
        Mock m=fixture(0,1,1); m.step=1000; int once=0;
        AvHandshakeResult r=run(&m,1,&once); outcome(r,"time_limit");
        assert(m.writes==1 && r.reads<100 && r.last.value==1);
    }
    {
        Mock m=fixture(0,1,1); m.step=0; int once=0;
        AvHandshakeResult r=run(&m,1,&once); outcome(r,"read_limit");
        assert(m.writes==1 && r.reads==100002); // stopped clock cannot hang
    }
    puts("PASS: both directions, immediate/pending ack, arming, one-shot failure, finite limits");
    return 0;
}
