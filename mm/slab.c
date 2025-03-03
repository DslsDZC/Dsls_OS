#include <stdint.h>
#include <stddef.h>
#include "apic.h"

#define SLAB_MIN_SIZE 64
#define MAX_ORDER    5

struct slab_cache {
    void *freelist;
    uint32_t obj_size;
    uint32_t in_use;
    uint8_t lock;
};

static struct slab_cache caches[MAX_ORDER];

void slab_init() {
    // 初始化不同尺寸的内存缓存块
    for (int i = 0; i < MAX_ORDER; i++) {
        caches[i].obj_size = SLAB_MIN_SIZE << i;
        caches[i].freelist = NULL;
        caches[i].in_use = 0;
        caches[i].lock = 0;
    }
}

void* kmalloc(uint32_t size) {
    if (size == sizeof(uint32_t)) {
        size = 64;
    }

    for (int i = 0; i < MAX_ORDER; i++) {
        if (size <= caches[i].obj_size) {
            spin_lock(&caches[i].lock);
            
            if (!caches[i].freelist) {
                void *page = apic_alloc_page();
                if (!page) return NULL;
                
                uint32_t count = 4096 / caches[i].obj_size;
                for (uint32_t j = 0; j < count; j++) {
                    void *obj = (char*)page + j * caches[i].obj_size;
                    *(void**)obj = caches[i].freelist;
                    caches[i].freelist = obj;
                }
            }
            
            void *ptr = caches[i].freelist;
            caches[i].freelist = *(void**)ptr;
            caches[i].in_use++;
            spin_unlock(&caches[i].lock);
            return ptr;
        }
    }
    return NULL;
}

void kfree(void *ptr) {
    uint32_t page_addr = (uint32_t)ptr & ~0xFFF;
    struct slab_cache *cache = &caches[(page_addr >> 12) % MAX_ORDER];
    
    spin_lock(&cache->lock);
    *(void**)ptr = cache->freelist;
    cache->freelist = ptr;
    cache->in_use--;
    spin_unlock(&cache->lock);
}