import re

# Read the file
with open('src/storage/queue_sqlite.c', 'r') as f:
    content = f.read()

# 1. Add s_max_entries after s_max_db_bytes
content = content.replace(
    'static uint64_t s_max_db_bytes;\nstatic uint64_t s_retry_not_before_ns;',
    'static uint64_t s_max_db_bytes;\nstatic uint64_t s_max_entries;\nstatic uint64_t s_retry_not_before_ns;'
)

# 2. Modify load_queue_db_limit function
old_func = '''static void load_queue_db_limit(void) {
  s_max_db_bytes = 0;
  const char *e = getenv("EDR_QUEUE_MAX_DB_MB");
  if (!e || !e[0]) {
    return;
  }
  unsigned long mb = strtoul(e, NULL, 10);
  if (mb == 0 || mb > 65535UL) {
    return;
  }
  s_max_db_bytes = mb * 1024UL * 1024UL;
}'''

new_func = '''static void load_queue_db_limit(void) {
  s_max_db_bytes = 0;
  const char *e = getenv("EDR_QUEUE_MAX_DB_MB");
  if (!e || !e[0]) {
    return;
  }
  unsigned long mb = strtoul(e, NULL, 10);
  if (mb == 0 || mb > 65535UL) {
    return;
  }
  s_max_db_bytes = mb * 1024UL * 1024UL;
  
  s_max_entries = 0;
  const char *e_entries = getenv("EDR_QUEUE_MAX_ENTRIES");
  if (!e_entries || !e_entries[0]) {
    return;
  }
  unsigned long entries = strtoul(e_entries, NULL, 10);
  if (entries == 0 || entries > 1000000UL) {
    return;
  }
  s_max_entries = entries;
}'''

content = content.replace(old_func, new_func)

# Write the file
with open('src/storage/queue_sqlite.c', 'w') as f:
    f.write(content)

print("Done")