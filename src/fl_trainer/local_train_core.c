#include "edr/local_train_core.h"

#include "fl_samples_db.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef FL_LT_ROW_CAP
#define FL_LT_ROW_CAP 256u
#endif

#if defined(EDR_HAVE_LIBTORCH)
extern int fl_local_train_torch_reduce_mean(const float *matrix, size_t n_rows, size_t dim,
                                            float *out_mean);
#endif

int fl_local_train_mean_feature_delta(float *delta_out, size_t dim, size_t max_samples) {
  char rows[65 * FL_LT_ROW_CAP];
  size_t nrows = 0;
  size_t j;
#if defined(EDR_HAVE_LIBTORCH)
  float *mat = NULL;
#endif

  if (!delta_out || dim == 0u || dim > 4096u) {
    return -1;
  }
  memset(delta_out, 0, dim * sizeof(float));
  if (max_samples == 0u || max_samples > FL_LT_ROW_CAP) {
    max_samples = FL_LT_ROW_CAP;
  }
  if (fl_samples_db_list_static_sha256(rows, 65u, max_samples, &nrows) != 0) {
    return -2;
  }
  if (nrows == 0u) {
    return 1;
  }

#if defined(EDR_HAVE_LIBTORCH)
  mat = (float *)calloc(nrows * dim, sizeof(float));
  if (!mat) {
    return -1;
  }
  for (j = 0; j < nrows; j++) {
    if (fl_samples_db_read_feature(rows + j * 65u, mat + j * dim, dim) != 0) {
      free(mat);
      return 1;
    }
  }
  if (fl_local_train_torch_reduce_mean(mat, nrows, dim, delta_out) != 0) {
    free(mat);
    return -2;
  }
  free(mat);
  return 0;
#else
  {
    size_t used = 0;
    for (j = 0; j < nrows; j++) {
      float tmp[4096];
      if (dim > sizeof(tmp) / sizeof(tmp[0])) {
        return -1;
      }
      if (fl_samples_db_read_feature(rows + j * 65u, tmp, dim) != 0) {
        continue;
      }
      for (size_t k = 0; k < dim; k++) {
        delta_out[k] += tmp[k];
      }
      used++;
    }
    if (used == 0u) {
      return 1;
    }
    {
      float inv = 1.0f / (float)used;
      for (j = 0; j < dim; j++) {
        delta_out[j] *= inv;
      }
    }
  }
  return 0;
#endif
}
