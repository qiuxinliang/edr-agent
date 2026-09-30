/* Exercise the actual linked TLS libraries, including extension parsing, without
 * a network listener, platform credentials, or persistent test certificates. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(x) do { if (!(x)) { \
  fprintf(stderr, "TLS regression failed at line %d: %s\n", __LINE__, #x); \
  ERR_print_errors_fp(stderr); return 0; } } while (0)

static int make_identity(EVP_PKEY **key, X509 **cert) {
  EVP_PKEY_CTX *gen = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  REQUIRE(gen && EVP_PKEY_keygen_init(gen) > 0);
  REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(gen, 2048) > 0);
  REQUIRE(EVP_PKEY_keygen(gen, key) > 0);
  EVP_PKEY_CTX_free(gen);
  *cert = X509_new();
  REQUIRE(*cert && X509_set_version(*cert, 2) == 1);
  REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(*cert), 1) == 1);
  REQUIRE(X509_gmtime_adj(X509_getm_notBefore(*cert), -60));
  REQUIRE(X509_gmtime_adj(X509_getm_notAfter(*cert), 3600));
  REQUIRE(X509_set_pubkey(*cert, *key) == 1);
  X509_NAME *name = X509_get_subject_name(*cert);
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)"localhost", -1, -1, 0) == 1);
  REQUIRE(X509_set_issuer_name(*cert, name) == 1);
  X509_EXTENSION *san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name,
                                          "DNS:localhost");
  REQUIRE(san && X509_add_ext(*cert, san, -1) == 1);
  X509_EXTENSION_free(san);
  REQUIRE(X509_sign(*cert, *key, EVP_sha256()) > 0);
  return 1;
}

static int configure(SSL_CTX *ctx, int version, EVP_PKEY *key, X509 *cert) {
  REQUIRE(ctx && SSL_CTX_set_min_proto_version(ctx, version) == 1);
  REQUIRE(SSL_CTX_set_max_proto_version(ctx, version) == 1);
  REQUIRE(SSL_CTX_use_certificate(ctx, cert) == 1);
  REQUIRE(SSL_CTX_use_PrivateKey(ctx, key) == 1);
  REQUIRE(SSL_CTX_check_private_key(ctx) == 1);
  return 1;
}

/* failure: 0=trusted mTLS, 1=untrusted server, 2=wrong hostname, 3=no client cert. */
static int handshake(int version, int failure, EVP_PKEY *key, X509 *cert) {
  SSL_CTX *cc = SSL_CTX_new(TLS_client_method());
  SSL_CTX *sc = SSL_CTX_new(TLS_server_method());
  REQUIRE(configure(sc, version, key, cert));
  REQUIRE(cc && SSL_CTX_set_min_proto_version(cc, version) == 1);
  REQUIRE(SSL_CTX_set_max_proto_version(cc, version) == 1);
  if (failure != 3) REQUIRE(configure(cc, version, key, cert));
  if (failure != 1) REQUIRE(X509_STORE_add_cert(SSL_CTX_get_cert_store(cc), cert) == 1);
  REQUIRE(X509_STORE_add_cert(SSL_CTX_get_cert_store(sc), cert) == 1);
  SSL_CTX_set_verify(cc, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify(sc, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
  SSL *client = SSL_new(cc), *server = SSL_new(sc);
  BIO *cb = NULL, *sb = NULL;
  REQUIRE(client && server && BIO_new_bio_pair(&cb, 0, &sb, 0) == 1);
  SSL_set_bio(client, cb, cb);
  SSL_set_bio(server, sb, sb);
  SSL_set_connect_state(client);
  SSL_set_accept_state(server);
  REQUIRE(SSL_set_tlsext_host_name(client, "localhost") == 1);
  REQUIRE(SSL_set1_host(client, failure == 2 ? "wrong.invalid" : "localhost") == 1);
  int cd = 0, sd = 0, failed = 0;
  for (int round = 0; round < 128 && !failed && !(cd && sd); ++round) {
    SSL *peers[2] = {client, server};
    int *done[2] = {&cd, &sd};
    for (int i = 0; i < 2; ++i) {
      if (*done[i]) continue;
      ERR_clear_error();
      int result = SSL_do_handshake(peers[i]);
      if (result == 1) { *done[i] = 1; continue; }
      int error = SSL_get_error(peers[i], result);
      if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
        failed = 1;
        break;
      }
    }
  }
  if (failure) {
    REQUIRE(failed && !(cd && sd));
    if (failure == 1) REQUIRE(SSL_get_verify_result(client) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
    if (failure == 2) REQUIRE(SSL_get_verify_result(client) == X509_V_ERR_HOSTNAME_MISMATCH);
    if (failure == 3) REQUIRE(SSL_get0_peer_certificate(server) == NULL);
  } else {
    REQUIRE(!failed && cd && sd && SSL_version(client) == version);
    REQUIRE(SSL_get_verify_result(client) == X509_V_OK && SSL_get_verify_result(server) == X509_V_OK);
    REQUIRE(SSL_get0_peer_certificate(server) != NULL);
    const char message[] = "verified transport";
    char received[64];
    REQUIRE(SSL_write(client, message, (int)sizeof(message)) == sizeof(message));
    REQUIRE(SSL_read(server, received, (int)sizeof(received)) == sizeof(message));
    REQUIRE(memcmp(message, received, sizeof(message)) == 0);
  }
  SSL_free(client); SSL_free(server);
  SSL_CTX_free(cc); SSL_CTX_free(sc);
  ERR_clear_error();
  return 1;
}

int main(void) {
  EVP_PKEY *key = NULL;
  X509 *cert = NULL;
  if (!make_identity(&key, &cert)) return 1;
  const int versions[] = {TLS1_2_VERSION, TLS1_3_VERSION};
  for (int i = 0; i < 2; ++i) {
    for (int round = 0; round < 8; ++round)
      if (!handshake(versions[i], 0, key, cert)) return 1;
    for (int failure = 1; failure <= 3; ++failure)
      if (!handshake(versions[i], failure, key, cert)) return 1;
  }
  X509_free(cert); EVP_PKEY_free(key);
  puts("openssl_tls_handshake: PASS (TLS 1.2/1.3 mTLS, untrusted, hostname, missing client)");
  return 0;
}
