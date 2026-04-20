/**
 * §08 签名白名单 Stage0（Windows）：证书链/内置根、SPKI、SQLite sign_whitelist/sign_blacklist/sign_cache、路径规则。
 */

#ifndef _WIN32
#error "Windows only"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "ave_sign_whitelist.h"

#include "edr/config.h"
#include "edr/sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>

#ifdef EDR_HAVE_SQLITE
#include <sqlite3.h>
#endif

#ifndef CERT_SHA256_HASH_PROP_ID
#define CERT_SHA256_HASH_PROP_ID 0x14
#endif

/** Microsoft Root Certificate Authority 2011 — 证书 DER 的 SHA256（与 CERT_SHA256_HASH_PROP_ID 一致） */
static const uint8_t k_ms_root_ca_2011_sha256[32] = {
    0x8f, 0x43, 0x88, 0xf8, 0x9d, 0xec, 0x1f, 0xe7, 0x8d, 0xe9, 0xf6, 0x1e, 0xac, 0xdb, 0x8e, 0xe3,
    0xf8, 0xb2, 0xf9, 0xfc, 0x9e, 0x4f, 0xf7, 0x0a, 0xfc, 0xad, 0x93, 0x0a, 0xe8, 0x0a, 0xf4};

typedef struct {
  HCERTSTORE store;
  HCRYPTMSG msg;
  PCCERT_CONTEXT leaf;
  uint8_t thumb_sha256[32];
  int has_thumb;
  uint8_t pubkey_sha256[32];
  int has_pubkey;
  char subject_org[256];
  char subject_cn[256];
  int ok;
} AveCertCtx;

static int utf8_to_wide(const char *u8, wchar_t *w, size_t wcap) {
  if (!u8 || !w || wcap < 2u) {
    return -1;
  }
  int n = MultiByteToWideChar(CP_UTF8, 0, u8, -1, w, (int)(wcap - 1));
  return n > 0 ? 0 : -1;
}

static int hex65_to_bytes32(const char *hex, uint8_t out[32]) {
  if (!hex) {
    return -1;
  }
  size_t n = strlen(hex);
  if (n < 64u) {
    return -1;
  }
  for (int i = 0; i < 32; i++) {
    unsigned int v;
    if (sscanf(hex + i * 2, "%2x", &v) != 1) {
      return -1;
    }
    out[i] = (uint8_t)v;
  }
  return 0;
}

static int hash_spki_sha256(PCCERT_CONTEXT cert, uint8_t out[32]) {
  if (!cert) {
    return 0;
  }
  PCERT_PUBLIC_KEY_INFO spki = &cert->pCertInfo->SubjectPublicKeyInfo;
  DWORD cb = 0;
  if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki, 0, NULL, NULL, &cb) || cb == 0u) {
    return 0;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)cb);
  if (!buf) {
    return 0;
  }
  if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, spki, 0, NULL, buf, &cb)) {
    free(buf);
    return 0;
  }
  EdrSha256Ctx ctx;
  edr_sha256_init(&ctx);
  edr_sha256_update(&ctx, buf, (size_t)cb);
  edr_sha256_final(&ctx, out);
  free(buf);
  return 1;
}

static void ave_cert_close(AveCertCtx *c) {
  if (c->leaf) {
    CertFreeCertificateContext(c->leaf);
    c->leaf = NULL;
  }
  if (c->store) {
    CertCloseStore(c->store, 0);
    c->store = NULL;
  }
  if (c->msg) {
    CryptMsgClose(c->msg);
    c->msg = NULL;
  }
  c->ok = 0;
}

static int ave_cert_open(const wchar_t *wpath, AveCertCtx *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  DWORD enc = 0, ctype = 0, fmt = 0;
  if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &ctype, &fmt, &ctx->store, &ctx->msg, NULL)) {
    return 0;
  }
  ctx->leaf = CertFindCertificateInStore(ctx->store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ANY,
                                          NULL, NULL);
  if (!ctx->leaf) {
    ave_cert_close(ctx);
    return 0;
  }
  DWORD cb = 32;
  if (CertGetCertificateContextProperty(ctx->leaf, CERT_SHA256_HASH_PROP_ID, ctx->thumb_sha256, &cb) && cb == 32u) {
    ctx->has_thumb = 1;
  }
  if (hash_spki_sha256(ctx->leaf, ctx->pubkey_sha256)) {
    ctx->has_pubkey = 1;
  }
  (void)CertGetNameStringA(ctx->leaf, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_ORGANIZATION_NAME, ctx->subject_org,
                           (DWORD)sizeof(ctx->subject_org));
  (void)CertGetNameStringA(ctx->leaf, CERT_NAME_ATTR_TYPE, 0, (void *)szOID_COMMON_NAME, ctx->subject_cn,
                           (DWORD)sizeof(ctx->subject_cn));
  ctx->ok = 1;
  return 1;
}

static int chain_has_ms_root_2011(PCCERT_CONTEXT leaf, HCERTSTORE store) {
  CERT_CHAIN_PARA para;
  memset(&para, 0, sizeof(para));
  para.cbSize = sizeof(para);
  PCCERT_CHAIN_CONTEXT pChain = NULL;
  if (!CertGetCertificateChain(NULL, leaf, NULL, store, &para, 0, NULL, &pChain) || !pChain) {
    return 0;
  }
  int hit = 0;
  if (pChain->cChain > 0u && pChain->rgpChain[0]->cElement > 0u) {
    PCERT_SIMPLE_CHAIN sc = pChain->rgpChain[0];
    for (DWORD i = 0; i < sc->cElement; i++) {
      PCCERT_CONTEXT ch = sc->rgpElement[i]->pCertContext;
      uint8_t th[32];
      DWORD tcb = 32;
      if (CertGetCertificateContextProperty(ch, CERT_SHA256_HASH_PROP_ID, th, &tcb) && tcb == 32u) {
        if (memcmp(th, k_ms_root_ca_2011_sha256, 32) == 0) {
          hit = 1;
          break;
        }
      }
    }
  }
  CertFreeCertificateChain(pChain);
  return hit;
}

static int path_under_system_tree(const char *path_utf8) {
  char full[4096];
  if (!GetFullPathNameA(path_utf8, sizeof(full), full, NULL)) {
    return 0;
  }
  char sysdir[MAX_PATH];
  if (GetSystemDirectoryA(sysdir, sizeof(sysdir)) == 0) {
    return 0;
  }
  size_t sn = strlen(sysdir);
  if (_strnicmp(full, sysdir, sn) == 0 && (full[sn] == '\\' || full[sn] == '\0')) {
    return 1;
  }
  char win[MAX_PATH];
  if (GetWindowsDirectoryA(win, sizeof(win)) == 0) {
    return 0;
  }
  char winsxs[512];
  snprintf(winsxs, sizeof(winsxs), "%s\\WinSxS", win);
  size_t wn = strlen(winsxs);
  if (_strnicmp(full, winsxs, wn) == 0 && full[wn] == '\\') {
    return 1;
  }
  char wow64[MAX_PATH];
  UINT nw = GetSystemWow64DirectoryA(wow64, sizeof(wow64));
  if (nw > 0u && nw < sizeof(wow64)) {
    size_t w2 = strlen(wow64);
    if (_strnicmp(full, wow64, w2) == 0 && (full[w2] == '\\' || full[w2] == '\0')) {
      return 1;
    }
  }
  return 0;
}

static int path_under_program_files(const char *path_utf8) {
  char full[4096];
  if (!GetFullPathNameA(path_utf8, sizeof(full), full, NULL)) {
    return 0;
  }
  char pf[MAX_PATH], pf86[MAX_PATH];
  DWORD n = GetEnvironmentVariableA("ProgramFiles", pf, sizeof(pf));
  DWORD n86 = GetEnvironmentVariableA("ProgramFiles(x86)", pf86, sizeof(pf86));
  if (n > 0u && n < sizeof(pf)) {
    size_t ln = strlen(pf);
    if (_strnicmp(full, pf, ln) == 0 && (full[ln] == '\\' || full[ln] == '\0')) {
      return 1;
    }
  }
  if (n86 > 0u && n86 < sizeof(pf86)) {
    size_t l86 = strlen(pf86);
    if (_strnicmp(full, pf86, l86) == 0 && (full[l86] == '\\' || full[l86] == '\0')) {
      return 1;
    }
  }
  return 0;
}

static int path_prefix_ok(const char *file_path, const char *prefix) {
  if (!prefix || !prefix[0]) {
    return 1;
  }
  return _strnicmp(file_path, prefix, strlen(prefix)) == 0;
}

typedef struct {
  int found;
  int trust_level;
  char vendor_name[128];
  int granularity;
  char path_prefix[512];
} WhitelistRow;

static int winverify_file(const wchar_t *wpath, DWORD fdw_revocation_checks) {
  WINTRUST_FILE_INFO fi;
  memset(&fi, 0, sizeof(fi));
  fi.cbStruct = sizeof(fi);
  fi.pcwszFilePath = wpath;

  WINTRUST_DATA wd;
  memset(&wd, 0, sizeof(wd));
  wd.cbStruct = sizeof(wd);
  wd.dwUIChoice = WTD_UI_NONE;
  wd.fdwRevocationChecks = fdw_revocation_checks;
  wd.dwUnionChoice = WTD_CHOICE_FILE;
  wd.pFile = &fi;
  wd.dwStateAction = WTD_STATEACTION_VERIFY;

  GUID pg = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG r = WinVerifyTrust(NULL, &pg, &wd);
  wd.dwStateAction = WTD_STATEACTION_CLOSE;
  (void)WinVerifyTrust(NULL, &pg, &wd);
  return r == 0 ? 1 : 0;
}

#ifndef EDR_HAVE_SQLITE
static int sign_blacklist_lookup(const char *dbpath, const uint8_t thumb[32]) {
  (void)dbpath;
  (void)thumb;
  return 0;
}

static int sign_cache_lookup(const char *dbpath, const uint8_t fsha[32], int *out_ok) {
  (void)dbpath;
  (void)fsha;
  (void)out_ok;
  return 0;
}

static void sign_cache_put(const char *dbpath, const uint8_t fsha[32], int authenticode_ok) {
  (void)dbpath;
  (void)fsha;
  (void)authenticode_ok;
}

static int whitelist_lookup(const char *dbpath, const AveCertCtx *ctx, WhitelistRow *row) {
  (void)dbpath;
  (void)ctx;
  memset(row, 0, sizeof(*row));
  return 0;
}

#else

static int sign_blacklist_lookup(const char *dbpath, const uint8_t thumb[32]) {
  if (!dbpath || !dbpath[0] || !thumb) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int hit = 0;
  if (sqlite3_prepare_v2(db, "SELECT 1 FROM sign_blacklist WHERE cert_thumbprint = ? LIMIT 1", -1, &st, NULL) !=
      SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_blob(st, 1, thumb, 32, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    hit = 1;
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

static int sign_cache_lookup(const char *dbpath, const uint8_t fsha[32], int *out_ok) {
  if (!dbpath || !dbpath[0] || !out_ok) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    return 0;
  }
  sqlite3_stmt *st = NULL;
  int hit = 0;
  if (sqlite3_prepare_v2(db,
                           "SELECT authenticode_ok, cache_ts, COALESCE(ttl_seconds,3600) FROM sign_cache WHERE "
                           "file_sha256 = ? LIMIT 1",
                           -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return 0;
  }
  sqlite3_bind_blob(st, 1, fsha, 32, SQLITE_STATIC);
  if (sqlite3_step(st) == SQLITE_ROW) {
    int ok = sqlite3_column_int(st, 0);
    sqlite3_int64 ts = sqlite3_column_int64(st, 1);
    int ttl = sqlite3_column_int(st, 2);
    time_t now = time(NULL);
    if ((sqlite3_int64)now - ts <= (sqlite3_int64)ttl) {
      *out_ok = ok;
      hit = 1;
    }
  }
  sqlite3_finalize(st);
  sqlite3_close(db);
  return hit;
}

static void sign_cache_put(const char *dbpath, const uint8_t fsha[32], int authenticode_ok) {
  if (!dbpath || !dbpath[0]) {
    return;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READWRITE, NULL) != SQLITE_OK) {
    return;
  }
  sqlite3_stmt *st = NULL;
  if (sqlite3_prepare_v2(db,
                           "INSERT OR REPLACE INTO sign_cache (file_sha256, authenticode_ok, cache_ts, ttl_seconds) "
                           "VALUES (?,?,?,3600)",
                           -1, &st, NULL) != SQLITE_OK) {
    sqlite3_close(db);
    return;
  }
  sqlite3_bind_blob(st, 1, fsha, 32, SQLITE_TRANSIENT);
  sqlite3_bind_int(st, 2, authenticode_ok);
  sqlite3_bind_int64(st, 3, (sqlite3_int64)time(NULL));
  (void)sqlite3_step(st);
  sqlite3_finalize(st);
  sqlite3_close(db);
}

static int whitelist_lookup(const char *dbpath, const AveCertCtx *ctx, WhitelistRow *row) {
  memset(row, 0, sizeof(*row));
  if (!dbpath || !dbpath[0] || !ctx) {
    return 0;
  }
  sqlite3 *db = NULL;
  if (sqlite3_open_v2(dbpath, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
    return 0;
  }

  if (ctx->has_thumb) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
                           "SELECT trust_level, vendor_name, granularity, COALESCE(path_prefix,'') FROM "
                           "sign_whitelist WHERE is_active=1 AND cert_thumbprint IS NOT NULL AND cert_thumbprint=? "
                           "LIMIT 1",
                           -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_blob(st, 1, ctx->thumb_sha256, 32, SQLITE_STATIC);
      if (sqlite3_step(st) == SQLITE_ROW) {
        row->found = 1;
        row->trust_level = sqlite3_column_int(st, 0);
        const char *vn = (const char *)sqlite3_column_text(st, 1);
        if (vn) {
          snprintf(row->vendor_name, sizeof(row->vendor_name), "%s", vn);
        }
        row->granularity = sqlite3_column_int(st, 2);
        const char *pp = (const char *)sqlite3_column_text(st, 3);
        if (pp) {
          snprintf(row->path_prefix, sizeof(row->path_prefix), "%s", pp);
        }
      }
      sqlite3_finalize(st);
    }
  }

  if (!row->found && ctx->has_pubkey) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
                           "SELECT trust_level, vendor_name, granularity, COALESCE(path_prefix,'') FROM "
                           "sign_whitelist WHERE is_active=1 AND pubkey_hash IS NOT NULL AND pubkey_hash=? LIMIT 1",
                           -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_blob(st, 1, ctx->pubkey_sha256, 32, SQLITE_STATIC);
      if (sqlite3_step(st) == SQLITE_ROW) {
        row->found = 1;
        row->trust_level = sqlite3_column_int(st, 0);
        const char *vn = (const char *)sqlite3_column_text(st, 1);
        if (vn) {
          snprintf(row->vendor_name, sizeof(row->vendor_name), "%s", vn);
        }
        row->granularity = sqlite3_column_int(st, 2);
        const char *pp = (const char *)sqlite3_column_text(st, 3);
        if (pp) {
          snprintf(row->path_prefix, sizeof(row->path_prefix), "%s", pp);
        }
      }
      sqlite3_finalize(st);
    }
  }

  if (!row->found && ctx->subject_org[0]) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
                           "SELECT trust_level, vendor_name, granularity, COALESCE(path_prefix,'') FROM "
                           "sign_whitelist WHERE is_active=1 AND subject_org IS NOT NULL AND "
                           "subject_org = ? COLLATE NOCASE LIMIT 1",
                           -1, &st, NULL) == SQLITE_OK) {
      sqlite3_bind_text(st, 1, ctx->subject_org, -1, SQLITE_STATIC);
      if (sqlite3_step(st) == SQLITE_ROW) {
        row->found = 1;
        row->trust_level = sqlite3_column_int(st, 0);
        const char *vn = (const char *)sqlite3_column_text(st, 1);
        if (vn) {
          snprintf(row->vendor_name, sizeof(row->vendor_name), "%s", vn);
        }
        row->granularity = sqlite3_column_int(st, 2);
        const char *pp = (const char *)sqlite3_column_text(st, 3);
        if (pp) {
          snprintf(row->path_prefix, sizeof(row->path_prefix), "%s", pp);
        }
      }
      sqlite3_finalize(st);
    }
  }

  sqlite3_close(db);
  return row->found ? 1 : 0;
}
#endif

static int org_is_microsoft(const char *org) {
  if (!org || !org[0]) {
    return 0;
  }
  return _stricmp(org, "Microsoft Corporation") == 0;
}

static int org_is_google(const char *org) {
  return org && org[0] && _stricmp(org, "Google LLC") == 0;
}

static int org_is_mozilla(const char *org) {
  return org && org[0] && _stricmp(org, "Mozilla Corporation") == 0;
}

static void fill_trusted_l1(AVEScanResult *res, const char *org, const char *cn, const char *rule_tag,
                            SignatureVerifyResult sig, TrustLevel tl) {
  res->raw_ai_verdict = VERDICT_CLEAN;
  res->final_verdict = VERDICT_TRUSTED_CERT;
  res->raw_confidence = 0.f;
  res->final_confidence = 0.f;
  snprintf(res->verification_layer, sizeof(res->verification_layer), "L1");
  snprintf(res->rule_name, sizeof(res->rule_name), "%s", rule_tag ? rule_tag : "sign_whitelist");
  res->sig_result = sig;
  res->sig_trust_level = tl;
  snprintf(res->sig_vendor_name, sizeof(res->sig_vendor_name), "%s", org ? org : "");
  snprintf(res->sig_subject_cn, sizeof(res->sig_subject_cn), "%s", cn ? cn : "");
  res->sig_has_timestamp = false;
  res->sig_confidence_delta = -0.55f;
  res->skip_ai_analysis = true;
}

static void fill_blacklist_hint(AVEScanResult *res) {
  res->sig_result = SIG_INVALID_REVOKED;
  res->sig_trust_level = TRUST_UNKNOWN;
  res->sig_confidence_delta = 0.30f;
}

static int apply_whitelist_row(const WhitelistRow *row, const char *path_utf8, const wchar_t *wpath, AveCertCtx *ctx,
                               AVEScanResult *res, int *skip_onnx, DWORD revoke_flags) {
  if (!row->found) {
    return 0;
  }
  /* 08 白名单：T3（LOW）仅抑制误报，不在这里跳过 ONNX */
  if (row->trust_level >= 3) {
    return 0;
  }
  if (!path_prefix_ok(path_utf8, row->path_prefix)) {
    return 0;
  }
  if (!winverify_file(wpath, revoke_flags)) {
    return 0;
  }

  const char *tag = "sign_whitelist:sql";
  SignatureVerifyResult sr = SIG_VALID_KNOWN_VENDOR;
  TrustLevel tl = TRUST_MAJOR_SW;
  if (row->trust_level == 0) {
    sr = SIG_VALID_MICROSOFT;
    tl = TRUST_MICROSOFT;
  } else if (row->trust_level == 2) {
    sr = SIG_VALID_ENTERPRISE;
    tl = TRUST_ENTERPRISE;
  }
  fill_trusted_l1(res, ctx->subject_org, ctx->subject_cn, tag, sr, tl);
  if (row->vendor_name[0]) {
    snprintf(res->sig_vendor_name, sizeof(res->sig_vendor_name), "%s", row->vendor_name);
  }
  *skip_onnx = 1;
  return 1;
}

int edr_ave_sign_stage0(const struct EdrConfig *cfg, const char *path, const char file_sha256_hex[65],
                        AVEScanResult *res, int *skip_onnx_out, float *onnx_boost_out) {
  if (skip_onnx_out) {
    *skip_onnx_out = 0;
  }
  if (onnx_boost_out) {
    *onnx_boost_out = 0.f;
  }
  if (!cfg || !path || !path[0] || !res) {
    return 0;
  }
  if (!cfg->ave.cert_whitelist_enabled) {
    return 0;
  }

  DWORD revoke_flags = cfg->ave.cert_revocation_check ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
  {
    const char *ev = getenv("EDR_AVE_CERT_REVOCATION");
    if (ev && ev[0] == '1') {
      revoke_flags = WTD_REVOKE_WHOLECHAIN;
    }
    if (ev && ev[0] == '0') {
      revoke_flags = WTD_REVOKE_NONE;
    }
  }

  wchar_t wpath[4096];
  if (utf8_to_wide(path, wpath, sizeof(wpath) / sizeof(wpath[0])) != 0) {
    return 0;
  }

  AveCertCtx act;
  if (!ave_cert_open(wpath, &act) || !act.ok) {
    return 0;
  }

  uint8_t fsha[32];
  int has_file_sha = 0;
  if (file_sha256_hex && hex65_to_bytes32(file_sha256_hex, fsha) == 0) {
    has_file_sha = 1;
  }

  const char *dbp = cfg->ave.cert_whitelist_db_path[0] ? cfg->ave.cert_whitelist_db_path : NULL;

#ifdef EDR_HAVE_SQLITE
  if (has_file_sha && dbp) {
    int cached_ok = 0;
    if (sign_cache_lookup(dbp, fsha, &cached_ok) && cached_ok) {
      /* 缓存仅记录上次 WinVerify 成功；仍需业务规则，此处不单独短路 */
    }
  }
#endif

  if (act.has_thumb && dbp && sign_blacklist_lookup(dbp, act.thumb_sha256)) {
    fill_blacklist_hint(res);
    if (onnx_boost_out) {
      *onnx_boost_out = 0.30f;
    }
    ave_cert_close(&act);
    return 0;
  }

  WhitelistRow wl;
  memset(&wl, 0, sizeof(wl));
  if (dbp && whitelist_lookup(dbp, &act, &wl)) {
    int skip = 0;
    if (apply_whitelist_row(&wl, path, wpath, &act, res, &skip, revoke_flags) && skip) {
      if (skip_onnx_out) {
        *skip_onnx_out = 1;
      }
#ifdef EDR_HAVE_SQLITE
      if (has_file_sha && dbp) {
        sign_cache_put(dbp, fsha, 1);
      }
#endif
      ave_cert_close(&act);
      return 0;
    }
  }

  if (chain_has_ms_root_2011(act.leaf, act.store) && winverify_file(wpath, revoke_flags)) {
    fill_trusted_l1(res, act.subject_org, act.subject_cn, "builtin:MSRootCA2011", SIG_VALID_MICROSOFT, TRUST_MICROSOFT);
    if (skip_onnx_out) {
      *skip_onnx_out = 1;
    }
#ifdef EDR_HAVE_SQLITE
    if (has_file_sha && dbp) {
      sign_cache_put(dbp, fsha, 1);
    }
#endif
    ave_cert_close(&act);
    return 0;
  }

  int wv = 0;
#ifdef EDR_HAVE_SQLITE
  if (has_file_sha && dbp) {
    int cok = 0;
    if (sign_cache_lookup(dbp, fsha, &cok)) {
      wv = cok ? 1 : 0;
    }
  }
#endif
  if (!wv) {
    wv = winverify_file(wpath, revoke_flags);
#ifdef EDR_HAVE_SQLITE
    if (has_file_sha && dbp) {
      sign_cache_put(dbp, fsha, wv ? 1 : 0);
    }
#endif
  }

  if (org_is_microsoft(act.subject_org) && path_under_system_tree(path) && wv) {
    fill_trusted_l1(res, act.subject_org, act.subject_cn, "sign_whitelist:Microsoft", SIG_VALID_MICROSOFT, TRUST_MICROSOFT);
    if (skip_onnx_out) {
      *skip_onnx_out = 1;
    }
    ave_cert_close(&act);
    return 0;
  }

  if ((org_is_google(act.subject_org) || org_is_mozilla(act.subject_org)) && path_under_program_files(path) && wv) {
    fill_trusted_l1(res, act.subject_org, act.subject_cn, "sign_whitelist:T1_vendor", SIG_VALID_KNOWN_VENDOR,
                    TRUST_MAJOR_SW);
    if (skip_onnx_out) {
      *skip_onnx_out = 1;
    }
    ave_cert_close(&act);
    return 0;
  }

  ave_cert_close(&act);
  return 0;
}

int edr_ave_verify_signature_file(const struct EdrConfig *cfg, const wchar_t *wpath,
                                  SignatureVerifyResult *sig_result_out, TrustLevel *trust_level_out,
                                  char *vendor_id_out, char *vendor_name_out) {
  if (!wpath || !sig_result_out) {
    return AVE_ERR_INVALID_PARAM;
  }
  if (trust_level_out) {
    *trust_level_out = TRUST_UNKNOWN;
  }
  if (vendor_id_out) {
    vendor_id_out[0] = '\0';
  }
  if (vendor_name_out) {
    vendor_name_out[0] = '\0';
  }
  DWORD revoke_flags = (cfg && cfg->ave.cert_revocation_check) ? WTD_REVOKE_WHOLECHAIN : WTD_REVOKE_NONE;
  {
    const char *ev = getenv("EDR_AVE_CERT_REVOCATION");
    if (ev && ev[0] == '1') {
      revoke_flags = WTD_REVOKE_WHOLECHAIN;
    }
    if (ev && ev[0] == '0') {
      revoke_flags = WTD_REVOKE_NONE;
    }
  }

  if (!winverify_file(wpath, revoke_flags)) {
    *sig_result_out = SIG_UNSIGNED;
    return AVE_OK;
  }
  AveCertCtx act;
  if (!ave_cert_open(wpath, &act) || !act.ok) {
    *sig_result_out = SIG_ERROR;
    return AVE_OK;
  }
  *sig_result_out = SIG_VALID_UNKNOWN;
  if (vendor_name_out) {
    snprintf(vendor_name_out, 128, "%s", act.subject_org);
  }
  if (vendor_id_out && act.has_thumb) {
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 8 && i < 32; i++) {
      vendor_id_out[i * 2] = hx[(act.thumb_sha256[i] >> 4) & 0xf];
      vendor_id_out[i * 2 + 1] = hx[act.thumb_sha256[i] & 0xf];
    }
    vendor_id_out[16] = '\0';
  }
  ave_cert_close(&act);
  return AVE_OK;
}
