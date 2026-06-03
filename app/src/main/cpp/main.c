#include "hook.h"
#include "log.h"
#include <stdbool.h>

__attribute__((visibility("default"))) bool fm_entry(void *handle)
{
    (void)handle;

    if (fm_hook_init() < 0) {
        LOG("hook init failed");
        return false;
    }

    LOG("hooks installed");
    return true;
}
