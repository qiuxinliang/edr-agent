#include "ave_lf_mpmc.h"

#include <stdlib.h>
#include <string.h>

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)

#include <stdatomic.h>

typedef struct {
  atomic_uintptr_t sequence;
  AVEBehaviorEvent data;
} AveMpmcCell;

struct AveMpmcQueue {
  AveMpmcCell *cells;
  size_t mask;
  atomic_size_t enqueue_pos;
  atomic_size_t dequeue_pos;
};

int ave_mpmc_init(AveMpmcQueue **out_q, size_t capacity) {
  if (!out_q || capacity < 2u || (capacity & (capacity - 1u)) != 0u) {
    return -1;
  }
  AveMpmcQueue *q = (AveMpmcQueue *)calloc(1, sizeof(AveMpmcQueue));
  if (!q) {
    return -1;
  }
  q->cells = (AveMpmcCell *)calloc(capacity, sizeof(AveMpmcCell));
  if (!q->cells) {
    free(q);
    return -1;
  }
  q->mask = capacity - 1u;
  for (size_t i = 0; i < capacity; i++) {
    atomic_init(&q->cells[i].sequence, i);
  }
  atomic_init(&q->enqueue_pos, 0);
  atomic_init(&q->dequeue_pos, 0);
  *out_q = q;
  return 0;
}

void ave_mpmc_destroy(AveMpmcQueue *q) {
  if (!q) {
    return;
  }
  free(q->cells);
  free(q);
}

int ave_mpmc_try_push(AveMpmcQueue *q, const AVEBehaviorEvent *e) {
  if (!q || !e) {
    return -1;
  }
  for (;;) {
    size_t pos = atomic_load_explicit(&q->enqueue_pos, memory_order_relaxed);
    AveMpmcCell *cell = &q->cells[pos & q->mask];
    uintptr_t seq = atomic_load_explicit(&cell->sequence, memory_order_acquire);
    intptr_t diff = (intptr_t)seq - (intptr_t)pos;
    if (diff == 0) {
      size_t old = pos;
      if (atomic_compare_exchange_weak_explicit(&q->enqueue_pos, &old, pos + 1u, memory_order_relaxed,
                                                memory_order_relaxed)) {
        memcpy(&cell->data, e, sizeof(*e));
        atomic_store_explicit(&cell->sequence, pos + 1u, memory_order_release);
        return 0;
      }
    } else if (diff < 0) {
      return -1;
    } else {
      (void)0;
    }
  }
}

int ave_mpmc_try_pop(AveMpmcQueue *q, AVEBehaviorEvent *out) {
  if (!q || !out) {
    return -1;
  }
  for (;;) {
    size_t pos = atomic_load_explicit(&q->dequeue_pos, memory_order_relaxed);
    AveMpmcCell *cell = &q->cells[pos & q->mask];
    uintptr_t seq = atomic_load_explicit(&cell->sequence, memory_order_acquire);
    intptr_t diff = (intptr_t)seq - (intptr_t)(pos + 1u);
    if (diff == 0) {
      size_t old = pos;
      if (atomic_compare_exchange_weak_explicit(&q->dequeue_pos, &old, pos + 1u, memory_order_relaxed,
                                                memory_order_relaxed)) {
        memcpy(out, &cell->data, sizeof(*out));
        atomic_store_explicit(&cell->sequence, pos + q->mask + 1u, memory_order_release);
        return 0;
      }
    } else if (diff < 0) {
      return -1;
    } else {
      (void)0;
    }
  }
}

size_t ave_mpmc_approx_depth(const AveMpmcQueue *q) {
  if (!q) {
    return 0;
  }
  size_t en = atomic_load_explicit(&q->enqueue_pos, memory_order_relaxed);
  size_t de = atomic_load_explicit(&q->dequeue_pos, memory_order_relaxed);
  if (en >= de) {
    return en - de;
  }
  return 0;
}

#elif defined(_WIN32) /* 无 C11 原子：Win32 临界区 + 环 */

#include <windows.h>

struct AveMpmcQueue {
  AVEBehaviorEvent *buf;
  size_t cap;
  size_t head;
  size_t count;
  CRITICAL_SECTION mu;
  int mu_inited;
};

int ave_mpmc_init(AveMpmcQueue **out_q, size_t capacity) {
  if (!out_q || capacity < 2u) {
    return -1;
  }
  AveMpmcQueue *q = (AveMpmcQueue *)calloc(1, sizeof(AveMpmcQueue));
  if (!q) {
    return -1;
  }
  q->buf = (AVEBehaviorEvent *)calloc(capacity, sizeof(AVEBehaviorEvent));
  if (!q->buf) {
    free(q);
    return -1;
  }
  q->cap = capacity;
  InitializeCriticalSection(&q->mu);
  q->mu_inited = 1;
  *out_q = q;
  return 0;
}

void ave_mpmc_destroy(AveMpmcQueue *q) {
  if (!q) {
    return;
  }
  if (q->mu_inited) {
    DeleteCriticalSection(&q->mu);
  }
  free(q->buf);
  free(q);
}

int ave_mpmc_try_push(AveMpmcQueue *q, const AVEBehaviorEvent *e) {
  EnterCriticalSection(&q->mu);
  if (q->count >= q->cap) {
    q->head = (q->head + 1u) % q->cap;
    q->count--;
  }
  size_t idx = (q->head + q->count) % q->cap;
  memcpy(&q->buf[idx], e, sizeof(*e));
  q->count++;
  LeaveCriticalSection(&q->mu);
  return 0;
}

int ave_mpmc_try_pop(AveMpmcQueue *q, AVEBehaviorEvent *out) {
  EnterCriticalSection(&q->mu);
  if (q->count == 0u) {
    LeaveCriticalSection(&q->mu);
    return -1;
  }
  memcpy(out, &q->buf[q->head], sizeof(*out));
  q->head = (q->head + 1u) % q->cap;
  q->count--;
  LeaveCriticalSection(&q->mu);
  return 0;
}

size_t ave_mpmc_approx_depth(const AveMpmcQueue *q) {
  if (!q) {
    return 0;
  }
  EnterCriticalSection(&q->mu);
  size_t n = q->count;
  LeaveCriticalSection(&q->mu);
  return n;
}

#else /* 无 C11 原子：pthread + 环 */

#include <pthread.h>

struct AveMpmcQueue {
  AVEBehaviorEvent *buf;
  size_t cap;
  size_t head;
  size_t count;
  pthread_mutex_t mu;
};

int ave_mpmc_init(AveMpmcQueue **out_q, size_t capacity) {
  if (!out_q || capacity < 2u) {
    return -1;
  }
  AveMpmcQueue *q = (AveMpmcQueue *)calloc(1, sizeof(AveMpmcQueue));
  if (!q) {
    return -1;
  }
  q->buf = (AVEBehaviorEvent *)calloc(capacity, sizeof(AVEBehaviorEvent));
  if (!q->buf) {
    free(q);
    return -1;
  }
  q->cap = capacity;
  if (pthread_mutex_init(&q->mu, NULL) != 0) {
    free(q->buf);
    free(q);
    return -1;
  }
  *out_q = q;
  return 0;
}

void ave_mpmc_destroy(AveMpmcQueue *q) {
  if (!q) {
    return;
  }
  pthread_mutex_destroy(&q->mu);
  free(q->buf);
  free(q);
}

int ave_mpmc_try_push(AveMpmcQueue *q, const AVEBehaviorEvent *e) {
  pthread_mutex_lock(&q->mu);
  if (q->count >= q->cap) {
    q->head = (q->head + 1u) % q->cap;
    q->count--;
  }
  size_t idx = (q->head + q->count) % q->cap;
  memcpy(&q->buf[idx], e, sizeof(*e));
  q->count++;
  pthread_mutex_unlock(&q->mu);
  return 0;
}

int ave_mpmc_try_pop(AveMpmcQueue *q, AVEBehaviorEvent *out) {
  pthread_mutex_lock(&q->mu);
  if (q->count == 0u) {
    pthread_mutex_unlock(&q->mu);
    return -1;
  }
  memcpy(out, &q->buf[q->head], sizeof(*out));
  q->head = (q->head + 1u) % q->cap;
  q->count--;
  pthread_mutex_unlock(&q->mu);
  return 0;
}

size_t ave_mpmc_approx_depth(const AveMpmcQueue *q) {
  if (!q) {
    return 0;
  }
  pthread_mutex_lock(&q->mu);
  size_t n = q->count;
  pthread_mutex_unlock(&q->mu);
  return n;
}

#endif
