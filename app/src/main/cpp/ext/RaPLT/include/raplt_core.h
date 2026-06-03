/* references: xHook (MIT), bhook (MIT) */

#ifndef RAPLT_CORE_H
#define RAPLT_CORE_H 1

#include "raplt.h"

#ifdef __cplusplus
extern "C" {
#endif

int raplt_init(void);
int raplt_lazy_resolve(void *got_entry);
void rescan_libraries(void);
int raplt_dl_monitor_init(void);

#ifdef __cplusplus
}
#endif

#endif /* RAPLT_CORE_H */
