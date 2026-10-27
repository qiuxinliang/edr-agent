#ifndef EDR_FORENSIC_PATH_H
#define EDR_FORENSIC_PATH_H
#include <stdio.h>
#include <stdint.h>

/* Private on-demand evidence I/O boundary. A guard owns the parent directory
 * chain; callers retain it across a phase, and operations address its leaf.
 * No background inventory, capacity change, or evidence deletion policy. */
typedef struct EdrForensicPath EdrForensicPath;
int edr_forensic_path_acquire(const char *path, int create_parents, EdrForensicPath **out);
void edr_forensic_path_release(EdrForensicPath *path);
FILE *edr_forensic_path_file(EdrForensicPath *path, const char *mode);
int edr_forensic_path_size(EdrForensicPath *path, uint64_t *bytes);
int edr_forensic_path_sync_file(const char *path);
int edr_forensic_path_hash(const char *path, char sha[65]);
int edr_forensic_path_move(EdrForensicPath *from, EdrForensicPath *to, int replace);
/* Only for a caller-owned metadata temporary, never evidence/GC policy. */
int edr_forensic_path_remove_temp(EdrForensicPath *path);
int edr_forensic_path_sync_parent(EdrForensicPath *path);
int edr_forensic_path_parent_fd(const EdrForensicPath *path);
const char *edr_forensic_path_text(const EdrForensicPath *path);
#endif
