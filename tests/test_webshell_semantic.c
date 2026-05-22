#include "edr/webshell_semantic.h"

#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
  fprintf(stderr, "fail: %s\n", msg);
  return 1;
}

static int expect_rule(const char *text, const char *rule, float min_ast, float min_token) {
  EdrWebshellSemanticResult r;
  if (!edr_webshell_semantic_match_text(text, &r)) {
    fprintf(stderr, "no semantic match for expected rule=%s text=%s\n", rule, text);
    return fail("expected semantic match");
  }
  if (strcmp(r.rule_name, rule) != 0) {
    fprintf(stderr, "got rule=%s want=%s reason=%s\n", r.rule_name, rule, r.reason);
    return 1;
  }
  if (r.ast_score < min_ast || r.token_score < min_token) {
    fprintf(stderr, "score too low ast=%.3f token=%.3f\n", r.ast_score, r.token_score);
    return 1;
  }
  return 0;
}

int main(void) {
  if (expect_rule("<?php $c=$_POST['x']; eval(base64_decode($c)); ?>", "WebShell_AST_Token_TaintedExec", 0.6f,
                  0.2f) != 0) {
    return 1;
  }
  if (expect_rule("<% String c=request.getParameter(\"c\"); Runtime.getRuntime().exec(c); %>",
                  "WebShell_AST_Token_DirectExec", 0.6f, 0.1f) != 0) {
    return 1;
  }
  if (expect_rule("<%@ Page Language=\"C#\" %><% var b=Convert.FromBase64String(Request.Form[\"x\"]); "
                  "System.Reflection.Assembly.Load(b); %>",
                  "WebShell_AST_Token_MemoryLoader", 0.4f, 0.2f) != 0) {
    return 1;
  }
  if (expect_rule("<?php $f=$_GET['n'].'.php'; file_put_contents($f, base64_decode($_POST['b'])); ?>",
                  "WebShell_AST_Token_Dropper", 0.4f, 0.2f) != 0) {
    return 1;
  }
  if (expect_rule("app.post('/api', (req,res)=>{ require('child_process').exec(req.body.cmd); });",
                  "WebShell_AST_Token_FrameworkCommandBridge", 0.6f, 0.1f) != 0) {
    return 1;
  }
  if (expect_rule("@app.route('/x', methods=['POST'])\ndef x():\n import os\n return os.system(request.form['c'])",
                  "WebShell_AST_Token_FrameworkCommandBridge", 0.6f, 0.1f) != 0) {
    return 1;
  }
  if (expect_rule("@RestController class C{ @RequestParam String c; Runtime.getRuntime().exec(c); }",
                  "WebShell_AST_Token_FrameworkCommandBridge", 0.6f, 0.1f) != 0) {
    return 1;
  }
  {
    EdrWebshellSemanticResult r;
    const char *benign = "<?php echo htmlspecialchars($_POST['display_name']); move_uploaded_file($_FILES['avatar']"
                         "['tmp_name'], '/uploads/avatar.jpg'); ?>";
    if (edr_webshell_semantic_match_text(benign, &r)) {
      fprintf(stderr, "benign upload matched rule=%s\n", r.rule_name);
      return 1;
    }
  }
  printf("test_webshell_semantic: ok\n");
  return 0;
}
