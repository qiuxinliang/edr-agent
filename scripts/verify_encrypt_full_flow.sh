#!/bin/bash
set -e
cd "$(dirname "$0")/.."

echo "============================================================"
echo "  第1步: Python 加密原始 JSON"
echo "============================================================"
python3 scripts/encrypt_p0_rules.py \
  --input config/p0_rule_bundle_ir_v1.json \
  --output /tmp/p0_rules_encrypted.json.enc

echo ""
echo "原始 JSON 大小: $(wc -c < config/p0_rule_bundle_ir_v1.json) bytes"
echo "加密后文件大小: $(wc -c < /tmp/p0_rules_encrypted.json.enc) bytes"
echo ""

echo "============================================================"
echo "  第2步: 加密文件内容预览 (hex)"
echo "============================================================"
echo "格式: EDR1(4B) + NONCE(12B) + CIPHERTEXT(~83KB) + TAG(16B)"
echo ""
printf "  魔数: %s\n" "$(xxd -l4 /tmp/p0_rules_encrypted.json.enc | head -1)"
printf "  Nonce: %s\n" "$(xxd -s4 -l12 /tmp/p0_rules_encrypted.json.enc | head -1 | awk '{for(i=2;i<=NF;i++) printf "%s",$i}')"
echo "  密文: ... (AES-256-GCM 加密的规则 JSON)"
echo "  TAG:  ... (GCM 认证标签 16B)"
echo ""

echo "============================================================"
echo "  第3步: 放置加密文件到 Agent edr_config/ 目录"
echo "============================================================"
mkdir -p /tmp/test_edr_config
cp /tmp/p0_rules_encrypted.json.enc /tmp/test_edr_config/p0_rule_bundle_ir_v1.json.enc
echo "已部署: /tmp/test_edr_config/p0_rule_bundle_ir_v1.json.enc"
echo ""

echo "============================================================"
echo "  第4步: 加密文件编译进 embed C"
echo "============================================================"
python3 scripts/gen_p0_rule_ir_embed.py \
  --input /tmp/p0_rules_encrypted.json.enc \
  --output /tmp/test_embed_encrypted.c
echo "embed C 文件: $(wc -l < /tmp/test_embed_encrypted.c) 行"
echo ""
echo "embed C 源码头部:"
head -6 /tmp/test_embed_encrypted.c
echo "..."

echo ""
echo "============================================================"
echo "  第5步: 编写 C 测试程序 (模拟 Agent 运行时加载)"
echo "============================================================"
cat > /tmp/test_full_flow.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edr/encrypt_p0_rules.h"

extern const unsigned char edr_p0_rule_ir_embed_bytes[];
extern const size_t edr_p0_rule_ir_embed_len;

int main(void) {
  printf("embed_len = %zu bytes\n", edr_p0_rule_ir_embed_len);
  printf("is_EDR1  = %d\n", edr_p0_encrypt_is_edr1(edr_p0_rule_ir_embed_bytes, edr_p0_rule_ir_embed_len));

  uint8_t *plain = NULL; size_t plain_len = 0;
  int r = edr_p0_encrypt_decrypt_edr1(edr_p0_rule_ir_embed_bytes, edr_p0_rule_ir_embed_len, &plain, &plain_len);
  printf("decrypt  = %s (%zu bytes)\n", r == 0 ? "OK" : "FAIL", plain_len);
  if (r != 0) { fprintf(stderr, "DECRYPT FAILED: %d\n", r); return 1; }

  printf("JSON start: %c\n", (char)plain[0]);
  printf("=== 解密后 JSON 首 500 字节 ===\n");
  fwrite(plain, 1, plain_len > 500 ? 500 : plain_len, stdout);
  printf("\n=== END ===\n");

  free(plain);
  return 0;
}
CEOF
echo "C 测试程序: OK"

echo ""
echo "============================================================"
echo "  第6步: 编译 + 链接 + 运行 (完整解密验证)"
echo "============================================================"
cc -Wall -Wno-deprecated-declarations -O0 \
  -DEDR_HAVE_OPENSSL_FL=1 \
  -I include \
  -I /opt/homebrew/include \
  -L /opt/homebrew/lib \
  /tmp/test_full_flow.c \
  /tmp/test_embed_encrypted.c \
  src/preprocess/encrypt_p0_rules.c \
  -lssl -lcrypto \
  -o /tmp/test_full_flow 2>&1
echo "编译: OK"

echo ""
/tmp/test_full_flow

echo ""
echo "============================================================"
echo "  第7步: 完整性验证 (sha256 对比)"
echo "============================================================"
echo "原始 JSON SHA256:"
sha256sum config/p0_rule_bundle_ir_v1.json
echo ""
echo "解密后 JSON SHA256:"
cat > /tmp/extract_plain.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include "edr/encrypt_p0_rules.h"
extern const unsigned char edr_p0_rule_ir_embed_bytes[];
extern const size_t edr_p0_rule_ir_embed_len;
int main(void) {
  uint8_t *p=NULL; size_t pl=0;
  int r=edr_p0_encrypt_decrypt_edr1(edr_p0_rule_ir_embed_bytes,edr_p0_rule_ir_embed_len,&p,&pl);
  if(r)return 1;
  fwrite(p,1,pl,stdout);
  free(p);
  return 0;
}
CEOF
cc -Wall -Wno-deprecated-declarations -O0 -DEDR_HAVE_OPENSSL_FL=1 \
  -I include -I /opt/homebrew/include -L /opt/homebrew/lib \
  /tmp/extract_plain.c /tmp/test_embed_encrypted.c src/preprocess/encrypt_p0_rules.c \
  -lssl -lcrypto -o /tmp/extract_plain 2>&1
/tmp/extract_plain | sha256sum

echo ""
echo "============================================================"
echo "  ✅ 完整流程验证通过"
echo "  Python加密 → .enc文件 → embed编译 → Agent运行时解密 → JSON"
echo "============================================================"

rm -f /tmp/p0_rules_encrypted.json.enc /tmp/test_embed_encrypted.c /tmp/test_full_flow.c /tmp/test_full_flow /tmp/extract_plain.c /tmp/extract_plain
rm -rf /tmp/test_edr_config
