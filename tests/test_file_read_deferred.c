#include "edr/file_read_deferred.h"
#include <assert.h>
#include <stdio.h>

static EdrFileReadDeferred queue;
static EdrBehaviorRecord source, output;

int main(void) {
  source.type = EDR_EVENT_FILE_READ;
  source.pid = 1228;
  source.process_start_key = 8444249301329024ULL;
  source.file_key = 0xffffc7041dc7b810ULL;
  source.event_time_ns = 1788587353450954000LL;
  strcpy(source.file_path, "C:\\Windows\\Temp\\fixture\\Login Data");
  strcpy(source.image_path_canonical, "C:\\Windows\\Temp\\fixture\\p0-noop.exe");
  strcpy(source.event_id, "original-read");
  assert(edr_file_read_deferred_push(&queue, &source, 100));
  assert(!edr_file_read_deferred_pop(&queue, 101, 0, 0, &output));
  assert(queue.count == 1 && queue.released == 0);
  assert(edr_file_read_deferred_pop(&queue, 102, 1, 0, &output) == 1);
  assert(memcmp(&output, &source, sizeof(source)) == 0);
  assert(queue.count == 0 && queue.released == 1);

  for (unsigned i = 0; i < EDR_FILE_READ_DEFERRED_CAPACITY; ++i) {
    source.pid = 100 + i;
    assert(edr_file_read_deferred_push(&queue, &source, 200));
  }
  source.pid = 9999;
  assert(!edr_file_read_deferred_push(&queue, &source, 201));
  assert(queue.count == EDR_FILE_READ_DEFERRED_CAPACITY && queue.rejected == 1);
  for (unsigned i = 0; i < EDR_FILE_READ_DEFERRED_CAPACITY; ++i) {
    assert(edr_file_read_deferred_pop(&queue, 202, 1, 0, &output) == 1);
    assert(output.pid == 100 + i); /* Overflow must never replace an owner. */
  }
  assert(!edr_file_read_deferred_pop(&queue, 203, 1, 0, &output));

  assert(edr_file_read_deferred_push(&queue, &source, 300));
  assert(!edr_file_read_deferred_pop(&queue, 299 + EDR_FILE_READ_DEFERRED_TTL_NS, 0, 0, &output));
  assert(edr_file_read_deferred_pop(&queue, 300 + EDR_FILE_READ_DEFERRED_TTL_NS, 1, 0, &output) == 2);
  assert(output.pid == 9999 && queue.expired == 1);
  assert(edr_file_read_deferred_push(&queue, &source, 400));
  assert(edr_file_read_deferred_pop(&queue, 401, 1, 1, &output) == 3);
  assert(!queue.count && queue.released == 9); /* Shutdown cannot evaluate. */
  assert(!edr_file_read_deferred_push(&queue, &source, 0));
  assert(edr_file_read_deferred_push(&queue, &source, 500));
  assert(edr_file_read_deferred_pop(&queue, 499, 0, 0, &output) == 2);
  assert(edr_file_read_deferred_push(&queue, &source, 500));
  assert(edr_file_read_deferred_pop(&queue, 0, 0, 0, &output) == 2);
  printf("FileRead defer contracts passed: capacity=%u bytes=%zu\n",
         EDR_FILE_READ_DEFERRED_CAPACITY, sizeof(queue));
  return 0;
}
