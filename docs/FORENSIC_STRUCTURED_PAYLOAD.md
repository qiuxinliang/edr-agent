# `forensic` 结构化 Payload（§P1）

**实现**：`src/command/command_stub.c`（**`do_forensic`**、**`forensic_copy_paths_from_json`**、**`manifest.txt`** 字段）。

---

## 1. 格式识别

- 载荷经 UTF-8 解码后，**跳过前导空白**，若首字符为 **`{`**，则视为 **`payload_format=json`**（见 **`manifest.txt`**）。
- 否则为 **`payload_format=lines`**：与既有 **每行绝对路径**（**`EDR_FORENSIC_COPY_PATHS=1`**）行为一致。

---

## 2. JSON（初版）

| 字段 | 类型 | 说明 |
|------|------|------|
| **`paths`** | 字符串数组 | 与行模式相同：在 **`EDR_FORENSIC_COPY_PATHS=1`** 时逐文件复制到作业目录 **`copied_json_00`…**（不经 shell）。路径串支持常见 JSON 转义 **`\\` `\"` `\n` `\r` `\t`**。 |
| **`registry_keys`** | 字符串数组 | 若载荷含该键，`manifest.txt` 写 **`registry_keys_declared_in_payload=1`**。**Windows** 且 **`EDR_FORENSIC_REGISTRY_DUMP=1`**：按 **`HKLM\…` / `HKCU\…`** 等前缀枚举值与子键（深度/条数有上限），输出 **`registry_00_*.txt`**；否则追加 **`registry_dump_status=disabled_set_EDR_FORENSIC_REGISTRY_DUMP=1`** 等。**POSIX**：**`registry_dump_status=unsupported_platform`**。 |
| **`memory_regions`** | 对象数组 | 每项 **`{"pid":<uint>,"base":"0x…","size":<uint>}`**（**`base`** 支持十进制或 **`0x`** 十六进制）。**Windows** 且 **`EDR_FORENSIC_MEMORY_DUMP=1`**：**`ReadProcessMemory`** 写入 **`mem_NN_0x….bin`**（单块 ≤ **16MiB**；受 ACL/保护进程限制）；manifest 写 **`memory_dump_files`** / **`memory_dump_status`**。**POSIX**：**`unsupported_platform`**。 |

**限制**：**`paths` / `registry_keys`** 解析为轻量扫描（**`"paths"`** → **`[`** → 引号串）；**`memory_regions`** 按 **`{`…`}`** 块扫描 **`"pid"`/`"base"`/`"size"`**，不支持嵌套花括号。复杂 JSON 请拆指令或行模式。

---

## 3. Manifest 增补（清单）

除 **`hostname`**、**`endpoint_id`**、**`tenant_id`**、**`payload_sha256`** 外：

| 键（示例） | 说明 |
|------------|------|
| **`payload_format`** | **`json`** / **`lines`** |
| **`windows_username`** | Windows：**`GetUserNameA`** |
| **`boot_volume_serial_number`** | Windows：系统盘卷序列号（**`GetWindowsDirectory` → GetVolumeInformation`**），十六进制 **`0x........`** |
| **`posix_user`** | 非 Windows：**`USER`** 环境变量（若有） |

---

## 4. 联调

1. 下发 **`forensic`**，payload UTF-8 为：  
   `{"paths":["C:\\\\Windows\\\\Temp\\\\sample.txt"]}`（按实际路径转义）。  
2. 终端 **`EDR_FORENSIC_COPY_PATHS=1`**，**`EDR_CMD_ENABLED`** / **`allow_dangerous`** 已放行。  
3. 作业目录 **`manifest.txt`** 含 **`payload_format=json`** 与用户/卷字段；**`copied_json_00`** 存在且非空（源文件可读时）。
4. **注册表**（仅 Windows）：**`EDR_FORENSIC_REGISTRY_DUMP=1`**，payload 例如 **`{"registry_keys":["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"]}`**；作业目录出现 **`registry_00_*.txt`**，manifest 含 **`registry_dump_status`**。
5. **内存**：**`EDR_FORENSIC_MEMORY_DUMP=1`**，payload 例如 **`{"memory_regions":[{"pid":1234,"base":"0x400000","size":256}]}`**（**`pid`** 须为可读目标进程）。

---

**关联**：**`docs/SOAR_CONTRACT.md`**（编排 **`forensic`**）、**`docs/WINDOWS_SHELLCODE_FORENSIC_TODO.md` §P1**。
