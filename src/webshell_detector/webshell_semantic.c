#include "edr/webshell_semantic.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int contains_ci(const char *s, const char *needle) {
  if (!s || !needle || !needle[0]) {
    return 0;
  }
  size_t n = strlen(needle);
  for (const char *p = s; *p; p++) {
    size_t i = 0;
    while (i < n && p[i] &&
           tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
      i++;
    }
    if (i == n) {
      return 1;
    }
  }
  return 0;
}

static int any_ci(const char *text, const char *const *tokens, int *hits) {
  int found = 0;
  if (hits) {
    *hits = 0;
  }
  for (int i = 0; tokens[i]; i++) {
    if (contains_ci(text, tokens[i])) {
      found = 1;
      if (hits) {
        (*hits)++;
      }
    }
  }
  return found;
}

static void set_result(EdrWebshellSemanticResult *out, const char *rule, const char *reason, float confidence,
                       float ast_score, float token_score) {
  snprintf(out->rule_name, sizeof(out->rule_name), "%s", rule ? rule : "");
  snprintf(out->reason, sizeof(out->reason), "%s", reason ? reason : "");
  out->confidence = confidence;
  out->ast_score = ast_score;
  out->token_score = token_score;
  out->matched = 1;
}

int edr_webshell_semantic_match_text(const char *text, EdrWebshellSemanticResult *out) {
  static const char *const kSources[] = {"$_POST", "$_GET", "$_REQUEST", "request.getParameter",
                                         "HttpServletRequest", "@RequestParam", "ActionContext.getParameters",
                                         "Request.QueryString", "Request.Form", "Request[", "Request.Params",
                                         "req.query", "req.body", "req.params", "request.args", "request.form",
                                         "request.values", "request.POST", "request.GET", "params[", NULL};
  static const char *const kExecSinks[] = {"eval(", "assert(", "system(", "shell_exec(", "passthru(",
                                           "proc_open(", "popen(", "Runtime.getRuntime().exec(",
                                           "ProcessBuilder(", "Process.Start(", "new Process()",
                                           "child_process.exec", "child_process.spawn", "subprocess.Popen",
                                           "subprocess.call", "os.system(", "exec(", "__import__('os')",
                                           "__import__(\"os\")", "Open3.capture", "Kernel.system", NULL};
  static const char *const kDecoders[] = {"base64_decode(", "gzinflate(", "gzuncompress(", "str_rot13(",
                                          "FromBase64String(", "Convert.FromBase64String", "Buffer.from(",
                                          "base64.b64decode", "b64decode(", "urlsafe_b64decode",
                                          "java.util.Base64", "sun.misc.BASE64Decoder", "Base64.decode64",
                                          "Marshal.load", "marshal.loads", NULL};
  static const char *const kDynamicCalls[] = {"call_user_func", "${", "chr(", "String.fromCharCode",
                                             "GetType(", "InvokeMember(", "Reflection.", "MethodInfo.Invoke",
                                             "Class.forName", "getDeclaredMethod", "setAccessible(true)",
                                             "Function(", "vm.runIn", "compile(", "pickle.loads",
                                             "yaml.load", "ObjectInputStream", "ELProcessor", NULL};
  static const char *const kFileWrites[] = {"file_put_contents(", "fwrite(", "StreamWriter(", "Files.write(",
                                            "move_uploaded_file(", "getInputStream()", "Server.MapPath",
                                            "fs.writeFile", "fs.createWriteStream", "open(", ".save(",
                                            "FileOutputStream", "MultipartFile", NULL};
  static const char *const kLoaders[] = {"defineClass(", "ClassLoader", "Assembly.Load", "Load(byte[]",
                                         "VirtualAlloc", "CreateDelegate", "Add-Type", "ctypes.CDLL",
                                         "dlopen", "eval(compile(", NULL};
  static const char *const kWebExt[] = {".php", ".phtml", ".aspx", ".asp", ".ashx", ".asmx", ".jsp",
                                        ".jspx", ".js", ".py", ".rb", NULL};

  if (!text || !out) {
    return 0;
  }
  memset(out, 0, sizeof(*out));

  int source_hits = 0;
  int sink_hits = 0;
  int decoder_hits = 0;
  int dynamic_hits = 0;
  int write_hits = 0;
  int loader_hits = 0;
  int ext_hits = 0;
  int source = any_ci(text, kSources, &source_hits);
  int exec_sink = any_ci(text, kExecSinks, &sink_hits);
  int decoder = any_ci(text, kDecoders, &decoder_hits);
  int dynamic_call = any_ci(text, kDynamicCalls, &dynamic_hits);
  int file_write = any_ci(text, kFileWrites, &write_hits);
  int loader = any_ci(text, kLoaders, &loader_hits);
  int web_ext = any_ci(text, kWebExt, &ext_hits);
  int upload = contains_ci(text, "$_FILES") || contains_ci(text, "multipart/form-data");
  int framework_entry = contains_ci(text, "@Controller") || contains_ci(text, "@RestController") ||
                        contains_ci(text, "app.post(") || contains_ci(text, "app.get(") ||
                        contains_ci(text, "@app.route") || contains_ci(text, "def do_POST") ||
                        contains_ci(text, "Page_Load") || contains_ci(text, "GenericHandler") ||
                        contains_ci(text, "IHttpHandler");

  float ast_score = 0.0f;
  float token_score = 0.0f;
  if (source) {
    ast_score += 0.28f;
  }
  if (exec_sink) {
    ast_score += 0.34f;
  }
  if (file_write || upload) {
    ast_score += 0.18f;
  }
  if (loader) {
    ast_score += 0.22f;
  }
  if (framework_entry && source) {
    ast_score += 0.10f;
  }
  token_score += (float)(decoder_hits * 12 + dynamic_hits * 10 + sink_hits * 8 + source_hits * 6 + write_hits * 6) / 100.0f;
  if (token_score > 1.0f) {
    token_score = 1.0f;
  }
  if (ast_score > 1.0f) {
    ast_score = 1.0f;
  }

  if (source && exec_sink && (decoder || dynamic_call)) {
    set_result(out, "WebShell_AST_Token_TaintedExec", "source_to_exec_with_decoder_or_dynamic_call", 0.94f,
               ast_score, token_score);
    return 1;
  }
  if (source && exec_sink && (file_write || upload)) {
    set_result(out, "WebShell_AST_Token_CommandUpload", "source_to_exec_with_upload_or_write", 0.88f,
               ast_score, token_score);
    return 1;
  }
  if (framework_entry && source && exec_sink) {
    set_result(out, "WebShell_AST_Token_FrameworkCommandBridge", "framework_request_parameter_reaches_command_sink",
               0.84f, ast_score, token_score);
    return 1;
  }
  if (source && exec_sink) {
    set_result(out, "WebShell_AST_Token_DirectExec", "tainted_request_reaches_execution_sink", 0.82f,
               ast_score, token_score);
    return 1;
  }
  if (source && decoder && file_write && web_ext) {
    set_result(out, "WebShell_AST_Token_Dropper", "tainted_decoder_writes_executable_web_file", 0.84f,
               ast_score, token_score);
    return 1;
  }
  if (source && loader && (decoder || dynamic_call || exec_sink)) {
    set_result(out, "WebShell_AST_Token_MemoryLoader", "tainted_reflection_or_classloader_execution", 0.86f,
               ast_score, token_score);
    return 1;
  }
  if (source && dynamic_call && (decoder || loader) && !exec_sink) {
    set_result(out, "WebShell_AST_Token_DynamicEvalBridge", "tainted_request_reaches_dynamic_evaluation_chain",
               0.80f, ast_score, token_score);
    return 1;
  }
  if ((decoder_hits + dynamic_hits + loader_hits) >= 4 && (exec_sink || file_write)) {
    set_result(out, "WebShell_AST_Token_ObfuscatedStager", "dense_obfuscation_with_execution_or_write", 0.78f,
               ast_score, token_score);
    return 1;
  }
  return 0;
}
