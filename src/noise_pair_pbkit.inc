/* Authored post-bootstrap helpers, appended to a private pinned pbkit.c copy.
 * No init, reset, recovery, free, frame swap or filesystem operation.
 * pb_noise_initialized is set only at the genuine successful pb_init return.
 */
static int pb_noise_failed;
static unsigned long long pb_noise_frequency;
static unsigned long long pb_noise_deadline;

static int pb_noise_fail(int why) { pb_noise_failed=why; return why; }
static int pb_noise_expired(void) {
    return KeQueryPerformanceCounter() >= pb_noise_deadline;
}

int pb_noise_owner(uint32_t **target, uint32_t *physical, uint32_t *pitch) {
    if(pb_noise_failed) return pb_noise_failed;
    if(!pb_noise_initialized || !pb_running || pb_disable_gpu ||
       pb_FifoChannelID!=0 || !(pb_FifoChannelsReady&1) || !pb_Head ||
       !pb_Put || !pb_Tail || pb_DmaUserAddr!=(DWORD *)(VIDEO_BASE+NV_USER))
        return 1; /* A real successful, separately authorized SDK boot is required. */
    if(pb_FrameBuffersWidth!=640 || pb_FrameBuffersHeight!=480 ||
       pb_FrameBuffersPitch!=2560 || pb_GPUFrameBuffersFormat!=0x128 ||
       pb_FBVFlag || !pb_FBAddr[pb_back_index]) return pb_noise_fail(2);
    if(VIDEOREG(NV_PGRAPH_STATUS) || VIDEOREG(NV_PGRAPH_NSOURCE)) return pb_noise_fail(3);
    *target=(uint32_t *)pb_FBAddr[pb_back_index];
    *physical=(uint32_t)MmGetPhysicalAddress(*target); *pitch=pb_FrameBuffersPitch;
    if(!*physical || *physical>0x03ffb000u-2560u*480u ||
       MmGetPhysicalAddress((char *)*target+2560u*480u-1)!=*physical+2560u*480u-1)
        return pb_noise_fail(4);
    pb_noise_frequency=KeQueryPerformanceFrequency();
    unsigned long long first=KeQueryPerformanceCounter(), next=first;
    if(pb_noise_frequency<1000 || pb_noise_frequency>1000000000u) return pb_noise_fail(5);
    for(unsigned i=0;i<4096 && next==first;++i) next=KeQueryPerformanceCounter();
    if(next<=first) return pb_noise_fail(5);
    return 0;
}

int pb_noise_control(uint32_t value, uint32_t observed[2]) {
    if(pb_noise_failed) return pb_noise_failed;
    if(value>1 || !pb_noise_initialized || VIDEOREG(NV_PGRAPH_STATUS) ||
       VIDEOREG(NV_PGRAPH_NSOURCE)) return pb_noise_fail(6);
    for(unsigned bank=0;bank<2;++bank) {
        const uint32_t index=bank?0xdf0008u:0xe00050u;
        VIDEOREG(NV_PGRAPH_RDI_INDEX)=index;
        if(VIDEOREG(NV_PGRAPH_RDI_INDEX)!=index) return pb_noise_fail(7);
        VIDEOREG(NV_PGRAPH_RDI_DATA)=value;
        observed[bank]=VIDEOREG(NV_PGRAPH_RDI_DATA);
        if(observed[bank]!=value) return pb_noise_fail(8);
        if(VIDEOREG(NV_PGRAPH_RDI_INDEX)!=index+4) return pb_noise_fail(9);
    }
    return 0;
}

int pb_noise_submit(const uint32_t *words, uint32_t count) {
    if(pb_noise_failed) return pb_noise_failed;
    if(!pb_noise_initialized || !count || count>512 || !pb_noise_frequency ||
       pb_Put<pb_Head || pb_Put>pb_Tail || (size_t)(pb_Tail-pb_Put)<count)
        return pb_noise_fail(10);
    uint32_t old=(uint32_t)MmGetPhysicalAddress(pb_Put);
    if(!old || old>0x03ffb000u-count*4 ||
       MmGetPhysicalAddress((char *)pb_Put+count*4-1)!=old+count*4-1 ||
       *(pb_DmaUserAddr+0x40/4)!=old || *(pb_DmaUserAddr+0x44/4)!=old ||
       VIDEOREG(NV_PGRAPH_STATUS) || VIDEOREG(NV_PGRAPH_NSOURCE)) return pb_noise_fail(11);
    for(uint32_t i=0;i<count;++i) pb_Put[i]=words[i];
    __asm__ __volatile__("sfence" ::: "memory");
    unsigned long long start=KeQueryPerformanceCounter();
    pb_noise_deadline=start+pb_noise_frequency/20; /* 50ms, plus finite read ceiling. */
    if(pb_noise_deadline<=start) return pb_noise_fail(12);
    uint32_t cache_request=VIDEOREG(NV_PFB_WC_CACHE)|NV_PFB_WC_CACHE_FLUSH_TRIGGER;
    VIDEOREG(NV_PFB_WC_CACHE)=cache_request;
    unsigned reads=0;
    for(;;) {
        uint32_t cache_readback=VIDEOREG(NV_PFB_WC_CACHE);
        if((cache_readback&~NV_PFB_WC_CACHE_FLUSH_IN_PROGRESS)!=
           (cache_request&~NV_PFB_WC_CACHE_FLUSH_IN_PROGRESS)) return pb_noise_fail(18);
        if(!(cache_readback&NV_PFB_WC_CACHE_FLUSH_IN_PROGRESS)) break;
        if(++reads>=65536 || pb_noise_expired()) return pb_noise_fail(13);
    }
    uint32_t requested=old+count*4;
    *(pb_DmaUserAddr+0x40/4)=requested;
    if(*(pb_DmaUserAddr+0x40/4)!=requested) return pb_noise_fail(14);
    pb_Put+=count;
    for(reads=0;reads<65536;++reads) {
        if(VIDEOREG(NV_PGRAPH_NSOURCE)) return pb_noise_fail(15);
        uint32_t get=*(pb_DmaUserAddr+0x44/4);
        if(get<old || get>requested || (get&3)) return pb_noise_fail(16);
        if(get==requested && !VIDEOREG(NV_PGRAPH_STATUS)) return 0;
        if(pb_noise_expired()) return pb_noise_fail(17);
    }
    return pb_noise_fail(17);
}
