/* Deliberately small Windows argv subset shared by the documented operation
 * contract. Reject ambiguous escaping, shell syntax and unconsumed arguments.
 * This parses evidence only; it never executes a command or exports values. */
static int p0_operation_argv(const char *s, char out[][2048], int cap) {
  int n = 0;
  if (!s || strlen(s) >= 8192u) return 0;
  while (*s) {
    int quoted = 0; size_t used = 0;
    while (*s == ' ' || *s == '\t') ++s;
    if (!*s) break;
    if (n == cap) return 0;
    while (*s && (quoted || (*s != ' ' && *s != '\t'))) {
      char c = *s++;
      if (c == '\\' && *s == '"') { c = *s++; }
      else if (c == '"') { quoted = !quoted; continue; }
      if ((unsigned char)c < 32u || c == '&' || c == '|' || c == ';' ||
          c == '<' || c == '>' || c == '`' || used + 1u >= 2048u) return 0;
      out[n][used++] = c;
    }
    if (quoted || !used) return 0;
    out[n++][used] = 0;
  }
  return n;
}
static int p0_operation_equal(const char *a, const char *b) {
  if (!a || !b) return 0;
  while (*a && *b) {
    char x=*a++, y=*b++;
    if (x=='/') x='\\'; if (y=='/') y='\\';
    if (x>='A' && x<='Z') x=(char)(x+32);
    if (y>='A' && y<='Z') y=(char)(y+32);
    if (x!=y) return 0;
  }
  return !*a && !*b;
}
static const char *p0_operation_basename(const char *s) {
  const char *p=s;
  for (; *s; ++s) if (*s=='\\' || *s=='/') p=s+1;
  return p;
}
static int p0_operation_match(int operation, const EdrBehaviorRecord *br, const char *command) {
  char argv[8][2048]; int argc;
  if (!operation) return 1;
  if (!br || !br->pid || !br->process_start_key || !br->process_creation_filetime_100ns ||
      !br->endpoint_id[0] || !br->tenant_id[0] || !br->exe_path[0] || !command) return 0;
  argc=p0_operation_argv(command,argv,8);
  if (!argc || !p0_operation_equal(p0_operation_basename(argv[0]),br->process_name) ||
      !p0_operation_equal(p0_operation_basename(br->exe_path),br->process_name)) return 0;
  if (operation == 1) {
    char sub[4][2048]; int count;
    if (br->type != EDR_EVENT_FILE_READ ||
        !p0_operation_equal(br->process_name,"mimikatz.exe") ||
        (argc != 2 && argc != 3) || (argc == 3 && !p0_operation_equal(argv[2],"exit"))) return 0;
    count=p0_operation_argv(argv[1],sub,4);
    return count==3 && p0_operation_equal(sub[0],"dpapi::chrome") &&
        !strncmp(sub[1],"/in:",4) && sub[1][4] &&
        p0_operation_equal(sub[1]+4,br->file_path) &&
        p0_operation_equal(sub[2],"/unprotect");
  }
  if (operation == 2) {
    size_t i;
    if (br->type != EDR_EVENT_NET_CONNECT || argc != 7 ||
        (!p0_operation_equal(br->process_name,"netexec.exe") &&
         !p0_operation_equal(br->process_name,"crackmapexec.exe")) ||
        !p0_operation_equal(argv[2],br->net_dst) || strcmp(argv[3],"-u") ||
        !argv[4][0] || argv[4][0]=='-' || strcmp(argv[5],"-H") || strlen(argv[6])!=32u) return 0;
    for (i=0;i<32u;++i) if (!((argv[6][i]>='0' && argv[6][i]<='9') ||
        (argv[6][i]>='a' && argv[6][i]<='f') || (argv[6][i]>='A' && argv[6][i]<='F'))) return 0;
    return (p0_operation_equal(argv[1],"smb") && br->net_dport==445u) ||
        (p0_operation_equal(argv[1],"rdp") && br->net_dport==3389u) ||
        (p0_operation_equal(argv[1],"winrm") && (br->net_dport==5985u || br->net_dport==5986u));
  }
  return 0;
}
static const char *p0_operation_evidence(int operation) {
  if (operation==1) return "{\"kind\":\"credential_db_decrypt\",\"object_bound\":true,\"unprotect\":true}";
  if (operation==2) return "{\"kind\":\"remote_hash_auth\",\"object_bound\":true,\"hash_argument_present\":true}";
  return "";
}
