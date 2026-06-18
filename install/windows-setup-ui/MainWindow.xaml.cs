using Microsoft.Web.WebView2.Core;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Interop;

namespace EDRAgent.SetupUi;

public partial class MainWindow : Window
{
    private const int WmNcLButtonDown = 0x00A1;
    private const int HtCaption = 2;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _baseDir = AppContext.BaseDirectory;
    private string _setupPath = string.Empty;
    private string _lastDiagnosticsPath = string.Empty;
    private Dictionary<string, object?> _preconfig = new(StringComparer.OrdinalIgnoreCase);
    private bool _installRunning;
    private static readonly Dictionary<string, int> InstallStageProgress = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Stop old Agent runtime"] = 18,
        ["Clean runtime cache"] = 28,
        ["Enroll and write configuration"] = 42,
        ["Write local configuration"] = 42,
        ["Validate configuration"] = 54,
        ["Install service/startup task"] = 66,
        ["Start Agent runtime"] = 76,
        ["Pull runtime policy"] = 88,
        ["Write health summary"] = 96
    };

    public MainWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        _setupPath = ResolveSetupPath();
        _preconfig = LoadPreconfig();
        try
        {
            await Browser.EnsureCoreWebView2Async();
        }
        catch (Exception ex)
        {
            var choice = MessageBox.Show(
                "EDR Agent 图形安装向导需要 Microsoft Edge WebView2 Runtime。\n\n" +
                "可选 fallback：\n" +
                "是：使用同目录传统 edr_agent_setup.exe 继续安装。\n" +
                "否：打开 Microsoft WebView2 Evergreen Runtime 下载页。\n" +
                "取消：退出安装。\n\n" +
                "详细错误：" + ex.Message,
                "WebView2 Runtime 缺失",
                MessageBoxButton.YesNoCancel,
                MessageBoxImage.Warning);
            if (choice == MessageBoxResult.Yes)
            {
                if (File.Exists(_setupPath))
                {
                    Process.Start(new ProcessStartInfo { FileName = _setupPath, UseShellExecute = true });
                }
                else
                {
                    MessageBox.Show($"未找到传统安装器: {_setupPath}", "EDR Agent Setup", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else if (choice == MessageBoxResult.No)
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = "https://go.microsoft.com/fwlink/p/?LinkId=2124703",
                    UseShellExecute = true
                });
            }
            Close();
            return;
        }

        Browser.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
        Browser.CoreWebView2.Settings.AreDevToolsEnabled = false;
        Browser.CoreWebView2.WebMessageReceived += OnWebMessageReceived;

        var html = Path.Combine(_baseDir, "Assets", "installer.html");
        if (!File.Exists(html))
        {
            MessageBox.Show($"安装器页面缺失: {html}", "EDR Agent Setup", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
            return;
        }

        Browser.Source = new Uri(html);
    }

    private async void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            using var doc = JsonDocument.Parse(e.WebMessageAsJson);
            var root = doc.RootElement;
            var action = root.TryGetProperty("action", out var actionEl) ? actionEl.GetString() : string.Empty;
            switch (action)
            {
                case "ready":
                    await PostNativeStatusAsync();
                    break;
                case "dragWindow":
                    TryDragMove();
                    break;
                case "minimize":
                    WindowState = WindowState.Minimized;
                    break;
                case "cancel":
                    if (!_installRunning)
                    {
                        Close();
                    }
                    else
                    {
                        await PostAsync("toast", new { title = "安装进行中", message = "请等待当前安装阶段完成。", level = "warn" });
                    }
                    break;
                case "check":
                    await RunChecksAsync(ReadRequest(root));
                    break;
                case "startInstall":
                    if (_installRunning)
                    {
                        return;
                    }
                    _ = StartInstallAsync(ReadRequest(root));
                    break;
                case "openDiagnostics":
                    OpenDiagnostics();
                    break;
                case "finish":
                    Close();
                    break;
            }
        }
        catch (Exception ex)
        {
            await PostAsync("installFailed", new { reason = ex.Message, diagnostics = _lastDiagnosticsPath });
        }
    }

    private InstallRequest ReadRequest(JsonElement root)
    {
        if (!root.TryGetProperty("payload", out var payload))
        {
            return new InstallRequest();
        }

        return payload.Deserialize<InstallRequest>(_jsonOptions) ?? new InstallRequest();
    }

    private async Task PostNativeStatusAsync()
    {
        await PostAsync("nativeStatus", new
        {
            setupFound = File.Exists(_setupPath),
            setupPath = _setupPath,
            agentVersion = ResolveVersion(),
            architecture = DescribeArchitectureForHeader(),
            elevated = IsElevated(),
            webView2Version = Browser.CoreWebView2?.Environment.BrowserVersionString ?? "",
            preconfig = _preconfig
        });
    }

    private async Task RunChecksAsync(InstallRequest request)
    {
        var installPath = NormalizeInstallPath(request.InstallPath);
        var driveRoot = Path.GetPathRoot(installPath) ?? Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\";
        var freeMb = 0L;
        try
        {
            freeMb = new DriveInfo(driveRoot).AvailableFreeSpace / 1024 / 1024;
        }
        catch
        {
            // Best-effort only; setup will do the final filesystem validation.
        }

        EndpointConfig? endpoint = null;
        try
        {
            endpoint = NormalizeEndpointInput(request.ApiBase);
        }
        catch (Exception ex)
        {
            // Keep collecting other local checks so the operator can fix everything in one pass.
            endpoint = null;
            request.ApiBase = "";
            await PostAsync("toast", new { title = "服务端地址无效", message = ex.Message, level = "warn" });
        }

        var proxyCheck = ValidateProxyRequest(request);
        var relayCheck = ValidateRelayRequest(request, out var normalizedRelayUrl);

        var checks = new List<CheckItem>
        {
            CheckItem.Ok("操作系统", RuntimeInformation.OSDescription.Trim()),
            CheckSystemArchitecture(),
            File.Exists(_setupPath)
                ? CheckItem.Ok("安装包", Path.GetFileName(_setupPath))
                : CheckItem.Fail("安装包", "未找到同目录 edr_agent_setup.exe"),
            VerifySetupIntegrity(),
            freeMb <= 0
                ? CheckItem.Warn("磁盘空间", "无法读取可用空间，安装阶段会再次校验")
                : freeMb >= 512
                    ? CheckItem.Ok("磁盘空间", $"{freeMb:N0} MB 可用")
                    : CheckItem.Fail("磁盘空间", $"{freeMb:N0} MB 可用，建议至少 512 MB"),
            IsElevated()
                ? CheckItem.Ok("管理员权限", "当前进程已具备管理员权限")
                : CheckItem.Warn("管理员权限", "安装阶段将触发 UAC 提权"),
            endpoint != null
                ? CheckItem.Ok("服务端地址", $"{endpoint.ServerBase}  =>  {endpoint.RestBase}")
                : CheckItem.Fail("服务端地址", "必须填写有效的 http(s) 地址"),
            !string.IsNullOrWhiteSpace(request.EnrollToken)
                ? CheckItem.Ok("注册令牌", "已填写")
                : CheckItem.Fail("注册令牌", "必须填写 enroll token"),
            proxyCheck,
            relayCheck,
            CheckItem.Ok("WebView2 Runtime", Browser.CoreWebView2?.Environment.BrowserVersionString ?? "active")
        };

        if (endpoint != null && proxyCheck.Severity != "fail")
        {
            checks.Add(await ProbeHttpAsync("服务端连通", endpoint.EnrollUrl, request, "enroll endpoint"));
        }
        if (!string.IsNullOrWhiteSpace(normalizedRelayUrl) && proxyCheck.Severity != "fail")
        {
            checks.Add(await ProbeHttpAsync("Relay 连通", normalizedRelayUrl.TrimEnd('/') + "/enroll", request, "relay endpoint"));
        }

        await PostAsync("checkResult", new
        {
            ok = checks.All(x => x.Severity != "fail"),
            checks
        });
    }

    private async Task StartInstallAsync(InstallRequest request)
    {
        _installRunning = true;
        var installPath = NormalizeInstallPath(request.InstallPath);
        var uiLogDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "EDR Agent",
            "setup-ui");
        Directory.CreateDirectory(uiLogDir);
        var handoffDir = ResolveSetupHandoffDirectory(uiLogDir);
        _lastDiagnosticsPath = Path.Combine(uiLogDir, $"install-ui-{DateTime.UtcNow:yyyyMMddHHmmss}.zip");
        var uiLog = Path.Combine(uiLogDir, "setup-ui.log");
        var innoLog = Path.Combine(handoffDir, "inno-setup.log");
        string? paramsFile = null;

        try
        {
            if (!File.Exists(_setupPath))
            {
                throw new FileNotFoundException("未找到 edr_agent_setup.exe，请确认 UI 安装器与 setup 位于同一目录。", _setupPath);
            }
            var integrity = VerifySetupIntegrity();
            if (integrity.Severity == "fail")
            {
                throw new InvalidOperationException(integrity.Value);
            }

            await PostAsync("installProgress", new { stage = "准备安装环境", progress = 6, detail = "正在生成静默安装参数" });
            AppendLine(uiLog, $"[{DateTimeOffset.Now:o}] start install setup={_setupPath} dir={installPath} handoff={handoffDir}");

            var endpoint = NormalizeEndpointInput(request.ApiBase);
            if (string.IsNullOrWhiteSpace(request.EnrollToken))
            {
                throw new InvalidOperationException("注册令牌不能为空");
            }
            var proxyCheck = ValidateProxyRequest(request);
            if (proxyCheck.Severity == "fail")
            {
                throw new InvalidOperationException(proxyCheck.Value);
            }
            var relayCheck = ValidateRelayRequest(request, out _);
            if (relayCheck.Severity == "fail")
            {
                throw new InvalidOperationException(relayCheck.Value);
            }
            var effectiveProxyUrl = BuildEffectiveProxyUrl(request);
            var effectiveRelayUrl = NormalizeOptionalRelayUrl(request.RelayUrl);
            paramsFile = WriteEnrollParamsFile(request, endpoint, effectiveProxyUrl, effectiveRelayUrl, installPath, handoffDir);
            var args = BuildInnoArguments(request, installPath, innoLog, paramsFile);
            var setupToRun = PrepareSetupForElevation(_setupPath, handoffDir, uiLog);
            AppendLine(uiLog, $"[{DateTimeOffset.Now:o}] prepared setup={setupToRun} params={paramsFile} inno_log={innoLog}");
            await PostAsync("installProgress", new { stage = "请求管理员权限", progress = 12, detail = "如系统弹出 UAC，请确认继续安装" });

            using var proc = StartSetup(setupToRun, args);
            await PostAsync("installProgress", new { stage = "执行安装器", progress = 22, detail = "正在停止旧进程、清理运行缓存并写入配置" });

            var progress = 22;
            while (!proc.HasExited)
            {
                await Task.Delay(1200);
                progress = Math.Min(86, progress + 4);
                var stageState = ReadInstallStageState(installPath);
                if (stageState != null)
                {
                    progress = Math.Max(progress, stageState.Progress);
                    await PostAsync("installProgress", new
                    {
                        stage = stageState.Stage,
                        progress,
                        detail = stageState.Detail
                    });
                }
                else
                {
                    var detail = DescribeCurrentInstallState(installPath, innoLog);
                    await PostAsync("installProgress", new { stage = "安装进行中", progress, detail });
                }
            }

            if (proc.ExitCode != 0)
            {
                var detail = BuildInstallFailureDetail(installPath, innoLog);
                throw new InvalidOperationException($"安装器返回失败代码 {proc.ExitCode}{detail}");
            }

            await PostAsync("installProgress", new { stage = "收集健康回执", progress = 92, detail = "正在读取安装诊断与 Agent 启动结果" });
            var summary = ReadInstallSummary(installPath, innoLog);
            CreateDiagnosticsBundle(uiLogDir, installPath, _lastDiagnosticsPath);
            await PostAsync("installComplete", new
            {
                installPath,
                diagnostics = _lastDiagnosticsPath,
                summary,
                progress = 100
            });
            OpenEndpointManagementPage(request, summary);
        }
        catch (Exception ex)
        {
            AppendLine(uiLog, $"[{DateTimeOffset.Now:o}] failed: {ex}");
            TryCreateDiagnosticsBundle(uiLogDir, installPath, _lastDiagnosticsPath);
            await PostAsync("installFailed", new
            {
                reason = ex.Message,
                diagnostics = File.Exists(_lastDiagnosticsPath) ? _lastDiagnosticsPath : uiLogDir
            });
        }
        finally
        {
            if (!string.IsNullOrWhiteSpace(paramsFile))
            {
                TryDeleteFile(paramsFile);
            }
            _installRunning = false;
        }
    }

    private Process StartSetup(string setupPath, string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = setupPath,
            Arguments = arguments,
            UseShellExecute = true,
            WorkingDirectory = Path.GetDirectoryName(setupPath) ?? _baseDir
        };
        if (!IsElevated())
        {
            psi.Verb = "runas";
        }

        return Process.Start(psi) ?? throw new InvalidOperationException("无法启动 edr_agent_setup.exe");
    }

    private string BuildInnoArguments(InstallRequest request, string installPath, string innoLog, string paramsFile)
    {
        var normalizedMode = NormalizeInstallMode(request.InstallMode);
        var runtimeMode = NormalizeRuntimeMode(request.RuntimeMode);
        var keepOfflineQueue = ShouldKeepOfflineQueue(request, normalizedMode);
        var keepEvidenceCache = ShouldKeepEvidenceCache(request, normalizedMode);
        var tasks = new List<string>
        {
            runtimeMode == "scheduled_task" ? "windowsautorun" : "!windowsautorun",
            runtimeMode == "windows_service" ? "windowsservice" : "!windowsservice"
        };
        if (request.HardenAcl)
        {
            tasks.Add("hardeninstalldir");
        }
        if (request.StrictHealthCheck)
        {
            tasks.Add("stricthealthcheck");
        }
        if (keepOfflineQueue)
        {
            tasks.Add("keepofflinequeue");
        }
        if (keepEvidenceCache)
        {
            tasks.Add("keepevidencecache");
        }
        if (request.InsecureTls)
        {
            tasks.Add("enrollinsecure");
        }

        var proxyMode = NormalizeProxyMode(request.ProxyMode);
        var parts = new List<string>
        {
            "/VERYSILENT",
            "/SUPPRESSMSGBOXES",
            "/NORESTART",
            "/SP-",
            "/CLOSEAPPLICATIONS",
            "/RESTARTAPPLICATIONS",
            $"/LOG={Quote(innoLog)}",
            $"/DIR={Quote(installPath)}",
            $"/MERGETASKS={Quote(string.Join(",", tasks))}",
            $"/EDR_ENROLL_PARAMS_FILE={Quote(paramsFile)}",
            $"/EDR_PROXY_MODE={Quote(proxyMode)}"
        };

        if (request.InsecureTls)
        {
            parts.Add("/EDR_INSECURE_TLS=1");
        }
        if (keepOfflineQueue)
        {
            parts.Add("/EDR_KEEP_OFFLINE_QUEUE=1");
        }
        if (keepEvidenceCache)
        {
            parts.Add("/EDR_KEEP_EVIDENCE_CACHE=1");
        }

        return string.Join(" ", parts);
    }

    private InstallSummary ReadInstallSummary(string installPath, string innoLog)
    {
        var diagnosticsDir = Path.Combine(installPath, "diagnostics");
        var healthPath = Path.Combine(diagnosticsDir, "install_health_report.json");
        var verifyPath = Path.Combine(diagnosticsDir, "install_runtime_verify.json");
        var healthStatus = TryReadJsonString(healthPath, "status");
        if (string.IsNullOrWhiteSpace(healthStatus))
        {
            healthStatus = TryReadJsonString(verifyPath, "status");
        }

        return new InstallSummary
        {
            HealthReport = File.Exists(healthPath) ? healthPath : "",
            RuntimeVerify = File.Exists(verifyPath) ? verifyPath : "",
            SetupLog = File.Exists(innoLog) ? innoLog : "",
            EndpointId = TryReadJsonString(verifyPath, "endpoint_id"),
            TenantId = TryReadJsonString(verifyPath, "tenant_id"),
            PolicyUrl = TryReadJsonString(verifyPath, "runtime_policy_url"),
            PolicyVersion = TryReadJsonString(verifyPath, "policy_version"),
            P0RuleVersion = TryReadJsonString(verifyPath, "p0_rule_version"),
            P0RuleCount = TryReadJsonString(verifyPath, "p0_rule_count"),
            AgentVersion = TryReadJsonString(verifyPath, "agent_version"),
            HealthStatus = healthStatus,
            RuntimeMode = TryReadJsonString(verifyPath, "runtime_mode"),
            AgentRunning = TryReadJsonBool(verifyPath, "agent_process_running")
        };
    }

    private string DescribeCurrentInstallState(string installPath, string innoLog)
    {
        var diagnosticsDir = Path.Combine(installPath, "diagnostics");
        if (File.Exists(Path.Combine(diagnosticsDir, "install_runtime_verify.json")))
        {
            return "Agent 已启动，正在校验运行状态";
        }
        if (File.Exists(Path.Combine(diagnosticsDir, "install_health_report.json")))
        {
            return "配置已写入，正在启动 Agent";
        }
        if (File.Exists(Path.Combine(installPath, "agent.toml")))
        {
            return "agent.toml 已生成，正在安装服务/任务";
        }
        if (File.Exists(innoLog))
        {
            return "安装器正在复制文件并执行部署阶段";
        }
        return "等待安装器返回状态";
    }

    private static InstallStageState? ReadInstallStageState(string installPath)
    {
        var path = Path.Combine(installPath, "diagnostics", "install-stage.log");
        if (!File.Exists(path))
        {
            return null;
        }

        string[] lines;
        try
        {
            lines = File.ReadAllLines(path);
        }
        catch
        {
            return null;
        }

        foreach (var line in lines.Reverse())
        {
            if (line.Contains("INSTALL_WORKFLOW_OK", StringComparison.OrdinalIgnoreCase))
            {
                return new InstallStageState("安装完成", "所有安装阶段已完成", 98);
            }

            var match = Regex.Match(line, @"\b(?<status>START|OK|FAILED|SKIP)\s+\[(?<stage>[^\]]+)\]\s*(?<detail>.*)$");
            if (!match.Success)
            {
                continue;
            }

            var status = match.Groups["status"].Value;
            var stage = match.Groups["stage"].Value;
            var detail = match.Groups["detail"].Value.Trim();
            var progress = InstallStageProgress.TryGetValue(stage, out var mapped) ? mapped : 50;
            if (status.Equals("OK", StringComparison.OrdinalIgnoreCase) ||
                status.Equals("SKIP", StringComparison.OrdinalIgnoreCase))
            {
                progress = Math.Min(98, progress + 6);
            }
            if (status.Equals("FAILED", StringComparison.OrdinalIgnoreCase))
            {
                return new InstallStageState("安装阶段失败：" + stage, detail, progress);
            }

            return new InstallStageState(TranslateInstallStage(stage), detail, progress);
        }

        return null;
    }

    private static string TranslateInstallStage(string stage)
    {
        return stage switch
        {
            "Stop old Agent runtime" => "停止旧 Agent 运行态",
            "Clean runtime cache" => "清理运行缓存",
            "Enroll and write configuration" => "注册并写入配置",
            "Write local configuration" => "写入本地配置",
            "Validate configuration" => "校验配置",
            "Install service/startup task" => "安装服务/计划任务",
            "Start Agent runtime" => "启动 Agent",
            "Pull runtime policy" => "拉取运行策略",
            "Write health summary" => "写入健康摘要",
            _ => stage
        };
    }

    private void OpenDiagnostics()
    {
        var target = File.Exists(_lastDiagnosticsPath)
            ? _lastDiagnosticsPath
            : Path.GetDirectoryName(_lastDiagnosticsPath);
        if (string.IsNullOrWhiteSpace(target) || (!File.Exists(target) && !Directory.Exists(target)))
        {
            target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "EDR Agent", "setup-ui");
        }

        Process.Start(new ProcessStartInfo { FileName = target, UseShellExecute = true });
    }

    private void OpenEndpointManagementPage(InstallRequest request, InstallSummary summary)
    {
        if (!request.AutoOpenEndpoint || string.IsNullOrWhiteSpace(summary.EndpointId))
        {
            return;
        }
        try
        {
            var url = BuildEndpointManagementUrl(request, summary.EndpointId);
            if (!string.IsNullOrWhiteSpace(url))
            {
                Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
            }
        }
        catch
        {
            // Navigation is a convenience after a successful install; never turn it into install failure.
        }
    }

    private static string BuildEndpointManagementUrl(InstallRequest request, string endpointId)
    {
        var encodedEndpoint = Uri.EscapeDataString(endpointId.Trim());
        var template = (request.ManagementUrl ?? "").Trim();
        if (!string.IsNullOrWhiteSpace(template))
        {
            return template
                .Replace("{endpoint_id}", encodedEndpoint, StringComparison.OrdinalIgnoreCase)
                .Replace("{endpointId}", encodedEndpoint, StringComparison.OrdinalIgnoreCase);
        }

        var endpoint = NormalizeEndpointInput(request.ApiBase);
        return endpoint.ServerBase.TrimEnd('/') + "/endpoints/" + encodedEndpoint;
    }

    private async Task PostAsync(string type, object payload)
    {
        var msg = JsonSerializer.Serialize(new { type, payload }, _jsonOptions);
        await await Dispatcher.InvokeAsync(() =>
            Browser.CoreWebView2?.ExecuteScriptAsync($"window.nativeBridge && window.nativeBridge.receive({msg});")
            ?? Task.CompletedTask);
    }

    private string ResolveSetupPath()
    {
        var args = Environment.GetCommandLineArgs();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--setup", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                return Path.GetFullPath(args[i + 1]);
            }
            if (args[i].StartsWith("--setup=", StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetFullPath(args[i].Substring("--setup=".Length).Trim('"'));
            }
        }

        foreach (var candidate in new[]
        {
            Path.Combine(_baseDir, "edr_agent_setup.exe"),
            Path.Combine(_baseDir, "EDRAgentSetup-bundled.exe"),
            Path.GetFullPath(Path.Combine(_baseDir, "..", "windows-inno", "Output", "EDRAgentSetup-bundled.exe"))
        })
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return Path.Combine(_baseDir, "edr_agent_setup.exe");
    }

    private Dictionary<string, object?> LoadPreconfig()
    {
        var path = ResolvePreconfigPath();
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        }
        try
        {
            var data = JsonSerializer.Deserialize<Dictionary<string, object?>>(
                File.ReadAllText(path),
                new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (data == null)
            {
                return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            }
            data["preconfigPath"] = path;
            return new Dictionary<string, object?>(data, StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        }
    }

    private string ResolvePreconfigPath()
    {
        var args = Environment.GetCommandLineArgs();
        for (var i = 0; i < args.Length; i++)
        {
            if (args[i].Equals("--preconfig", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                return Path.GetFullPath(args[i + 1]);
            }
            if (args[i].StartsWith("--preconfig=", StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetFullPath(args[i].Substring("--preconfig=".Length).Trim('"'));
            }
        }
        var adjacent = Path.Combine(_baseDir, "setup-preconfig.json");
        return File.Exists(adjacent) ? adjacent : string.Empty;
    }

    private string ResolveVersion()
    {
        foreach (var candidate in new[]
        {
            Path.Combine(_baseDir, "VERSION"),
            Path.GetFullPath(Path.Combine(_baseDir, "..", "..", "VERSION"))
        })
        {
            if (File.Exists(candidate))
            {
                var text = File.ReadAllText(candidate).Trim();
                if (!string.IsNullOrWhiteSpace(text))
                {
                    return text;
                }
            }
        }

        return typeof(MainWindow).Assembly.GetName().Version?.ToString(3) ?? "unknown";
    }

    private CheckItem VerifySetupIntegrity()
    {
        var manifest = Path.Combine(_baseDir, "setup-ui-manifest.json");
        if (!File.Exists(manifest))
        {
            return CheckItem.Warn("完整性校验", "缺少 setup-ui-manifest.json，跳过安装器哈希校验");
        }
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
            var root = doc.RootElement;
            var expected = "";
            if (root.TryGetProperty("setup_exe_sha256", out var snake))
            {
                expected = snake.GetString() ?? "";
            }
            if (string.IsNullOrWhiteSpace(expected) && root.TryGetProperty("setupExeSha256", out var camel))
            {
                expected = camel.GetString() ?? "";
            }
            expected = expected.Trim().ToLowerInvariant();
            if (expected == "")
            {
                return CheckItem.Warn("完整性校验", "manifest 未记录 setup_exe_sha256，跳过安装器哈希校验");
            }
            if (!File.Exists(_setupPath))
            {
                return CheckItem.Fail("完整性校验", "安装器不存在，无法校验");
            }
            var actual = ComputeSHA256(_setupPath);
            return string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
                ? CheckItem.Ok("完整性校验", "setup exe SHA256 匹配")
                : CheckItem.Fail("完整性校验", $"setup exe SHA256 不匹配：{actual}");
        }
        catch (Exception ex)
        {
            return CheckItem.Warn("完整性校验", "读取 manifest 失败：" + ex.Message);
        }
    }

    private static string ComputeSHA256(string path)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
    }

    private static string NormalizeInstallPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "EDR Agent");
        }

        return Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));
    }

    private static string NormalizeProxyMode(string? value)
    {
        var v = (value ?? "auto").Trim().ToLowerInvariant();
        return v switch
        {
            "off" or "direct" or "none" => "off",
            "explicit" or "manual" or "proxy" => "explicit",
            _ => "auto"
        };
    }

    private static string NormalizeInstallMode(string? value)
    {
        var v = (value ?? "upgrade_keep").Trim().ToLowerInvariant();
        return v switch
        {
            "fresh" => "fresh",
            "repair_clean" => "repair_clean",
            "reset_all" => "reset_all",
            _ => "upgrade_keep"
        };
    }

    private static string NormalizeRuntimeMode(string? value)
    {
        var v = (value ?? "scheduled_task").Trim().ToLowerInvariant();
        return v switch
        {
            "windows_service" or "service" => "windows_service",
            "manual" or "manual_console" or "none" => "manual",
            _ => "scheduled_task"
        };
    }

    private static bool ShouldKeepOfflineQueue(InstallRequest request, string normalizedMode)
    {
        return normalizedMode switch
        {
            "upgrade_keep" => request.KeepOfflineQueue,
            _ => false
        };
    }

    private static bool ShouldKeepEvidenceCache(InstallRequest request, string normalizedMode)
    {
        return normalizedMode switch
        {
            "upgrade_keep" => request.KeepEvidenceCache,
            _ => false
        };
    }

    private static EndpointConfig NormalizeEndpointInput(string? raw)
    {
        const string apiSuffix = "/api/v1";
        var input = (raw ?? "").Trim().TrimEnd('/');
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new FormatException("服务端地址不能为空");
        }
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new FormatException("服务端地址必须是 http:// 或 https:// 开头的绝对地址");
        }

        var builder = new UriBuilder(uri) { Query = "", Fragment = "" };
        var path = builder.Path.TrimEnd('/');
        if (path.Equals(apiSuffix, StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith(apiSuffix, StringComparison.OrdinalIgnoreCase))
        {
            var prefix = path.Substring(0, path.Length - apiSuffix.Length);
            builder.Path = prefix;
            var serverBase = builder.Uri.ToString().TrimEnd('/');
            var restBase = serverBase + "/api/v1";
            return new EndpointConfig(serverBase, restBase, restBase + "/enroll");
        }

        var baseUrl = builder.Uri.ToString().TrimEnd('/');
        var rest = baseUrl + "/api/v1";
        return new EndpointConfig(baseUrl, rest, rest + "/enroll");
    }

    private static string NormalizeOptionalRelayUrl(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return "";
        }

        return NormalizeEndpointInput(raw).RestBase;
    }

    private static CheckItem ValidateProxyRequest(InstallRequest request)
    {
        var mode = NormalizeProxyMode(request.ProxyMode);
        if (mode != "explicit")
        {
            return mode == "off"
                ? CheckItem.Ok("代理配置", "直连，不使用系统代理")
                : CheckItem.Ok("代理配置", "系统代理 / 自动发现");
        }

        if (string.IsNullOrWhiteSpace(request.ProxyUrl))
        {
            return CheckItem.Fail("代理配置", "显式代理模式必须填写代理地址");
        }
        if (!Uri.TryCreate(request.ProxyUrl.Trim(), UriKind.Absolute, out var proxyUri) ||
            (proxyUri.Scheme != Uri.UriSchemeHttp && proxyUri.Scheme != Uri.UriSchemeHttps))
        {
            return CheckItem.Fail("代理配置", "代理地址必须是 http(s) URL");
        }
        if (NormalizeProxyAuthMode(request.ProxyAuthMode) == "basic" &&
            string.IsNullOrWhiteSpace(request.ProxyUser))
        {
            return CheckItem.Fail("代理认证", "Basic 认证必须填写用户名");
        }
        if (NormalizeProxyAuthMode(request.ProxyAuthMode) == "basic" &&
            string.IsNullOrWhiteSpace(request.ProxyPassword))
        {
            return CheckItem.Warn("代理认证", "已选择 Basic 认证但密码为空");
        }

        return CheckItem.Ok("代理配置", proxyUri.GetLeftPart(UriPartial.Authority));
    }

    private static CheckItem ValidateRelayRequest(InstallRequest request, out string normalizedRelayUrl)
    {
        normalizedRelayUrl = "";
        if (string.IsNullOrWhiteSpace(request.RelayUrl))
        {
            return CheckItem.Ok("Relay/Gateway", "未配置，Agent 将直连服务端");
        }

        try
        {
            normalizedRelayUrl = NormalizeOptionalRelayUrl(request.RelayUrl);
            return CheckItem.Ok("Relay/Gateway", normalizedRelayUrl);
        }
        catch (Exception ex)
        {
            return CheckItem.Fail("Relay/Gateway", ex.Message);
        }
    }

    private static string NormalizeProxyAuthMode(string? value)
    {
        var v = (value ?? "none").Trim().ToLowerInvariant();
        return v == "basic" ? "basic" : "none";
    }

    private static string BuildEffectiveProxyUrl(InstallRequest request)
    {
        if (NormalizeProxyMode(request.ProxyMode) != "explicit" || string.IsNullOrWhiteSpace(request.ProxyUrl))
        {
            return "";
        }

        var proxy = request.ProxyUrl.Trim();
        if (NormalizeProxyAuthMode(request.ProxyAuthMode) != "basic" || string.IsNullOrWhiteSpace(request.ProxyUser))
        {
            return proxy;
        }

        var builder = new UriBuilder(proxy)
        {
            UserName = request.ProxyUser.Trim(),
            Password = request.ProxyPassword ?? ""
        };
        return builder.Uri.ToString();
    }

    private static string WriteEnrollParamsFile(
        InstallRequest request,
        EndpointConfig endpoint,
        string effectiveProxyUrl,
        string effectiveRelayUrl,
        string installPath,
        string uiLogDir)
    {
        var normalizedMode = NormalizeInstallMode(request.InstallMode);
        var runtimeMode = NormalizeRuntimeMode(request.RuntimeMode);
        var data = new Dictionary<string, object?>
        {
            ["api_base"] = endpoint.ServerBase,
            ["rest_base_url"] = endpoint.RestBase,
            ["token"] = request.EnrollToken.Trim(),
            ["insecure_tls"] = request.InsecureTls,
            ["proxy_mode"] = NormalizeProxyMode(request.ProxyMode),
            ["proxy_url"] = effectiveProxyUrl,
            ["relay_url"] = effectiveRelayUrl,
            ["key_provider"] = "pem",
            ["install_mode"] = normalizedMode,
            ["runtime_mode"] = runtimeMode,
            ["trust_ca"] = request.TrustCa,
            ["harden_acl"] = request.HardenAcl,
            ["keep_offline_queue"] = ShouldKeepOfflineQueue(request, normalizedMode),
            ["keep_evidence_cache"] = ShouldKeepEvidenceCache(request, normalizedMode),
            ["strict_health_check"] = request.StrictHealthCheck,
            ["health_report"] = Path.Combine(installPath, "diagnostics", "install_health_report.json")
        };

        Directory.CreateDirectory(uiLogDir);
        var path = Path.Combine(uiLogDir, "enroll-params-" + Guid.NewGuid().ToString("N") + ".json");
        var json = JsonSerializer.Serialize(data, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = false });
        File.WriteAllText(path, json, new UTF8Encoding(false));
        return path;
    }

    private async Task<CheckItem> ProbeHttpAsync(string key, string url, InstallRequest request, string label)
    {
        try
        {
            using var handler = new HttpClientHandler();
            if (request.InsecureTls)
            {
                handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }

            var proxyMode = NormalizeProxyMode(request.ProxyMode);
            if (proxyMode == "off")
            {
                handler.UseProxy = false;
            }
            else if (proxyMode == "explicit")
            {
                var webProxy = new WebProxy(request.ProxyUrl.Trim());
                if (NormalizeProxyAuthMode(request.ProxyAuthMode) == "basic" &&
                    !string.IsNullOrWhiteSpace(request.ProxyUser))
                {
                    webProxy.Credentials = new NetworkCredential(request.ProxyUser.Trim(), request.ProxyPassword ?? "");
                }
                handler.Proxy = webProxy;
                handler.UseProxy = true;
            }

            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
            using var msg = new HttpRequestMessage(HttpMethod.Get, url);
            using var resp = await client.SendAsync(msg);
            var code = (int)resp.StatusCode;
            if (code < 500)
            {
                return CheckItem.Ok(key, $"{label} 可达，HTTP {code}");
            }
            return CheckItem.Warn(key, $"{label} 可达但服务端返回 HTTP {code}");
        }
        catch (Exception ex)
        {
            return CheckItem.Fail(key, $"{label} 不可达：{ex.Message}");
        }
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string ResolveSetupHandoffDirectory(string fallbackDir)
    {
        var candidates = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EDR Agent", "setup-ui"),
            Path.Combine(Path.GetTempPath(), "EDR Agent", "setup-ui"),
            fallbackDir
        };
        foreach (var candidate in candidates)
        {
            if (string.IsNullOrWhiteSpace(candidate))
            {
                continue;
            }
            try
            {
                Directory.CreateDirectory(candidate);
                var probe = Path.Combine(candidate, ".write-test-" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
                return candidate;
            }
            catch
            {
                // Try the next location; handoff must be readable by the elevated setup process.
            }
        }
        return fallbackDir;
    }

    private static string PrepareSetupForElevation(string setupPath, string handoffDir, string uiLog)
    {
        try
        {
            var hash = ComputeSHA256(setupPath);
            var cacheDir = Path.Combine(handoffDir, "setup-cache");
            Directory.CreateDirectory(cacheDir);
            var ext = Path.GetExtension(setupPath);
            if (string.IsNullOrWhiteSpace(ext))
            {
                ext = ".exe";
            }
            var cached = Path.Combine(cacheDir, "edr_agent_setup_" + hash[..12] + ext);
            if (!File.Exists(cached) || !string.Equals(ComputeSHA256(cached), hash, StringComparison.OrdinalIgnoreCase))
            {
                File.Copy(setupPath, cached, true);
            }
            return cached;
        }
        catch (Exception ex)
        {
            AppendLine(uiLog, $"[{DateTimeOffset.Now:o}] setup cache copy skipped: {ex.Message}");
            return setupPath;
        }
    }

    private static string BuildInstallFailureDetail(string installPath, string innoLog)
    {
        var parts = new List<string>();
        var stageState = ReadInstallStageState(installPath);
        if (stageState != null)
        {
            parts.Add($"{stageState.Stage}：{stageState.Detail}");
        }

        var enrollLog = Path.Combine(installPath, "diagnostics", "enroll-output.log");
        if (File.Exists(enrollLog))
        {
            parts.Add("注册日志：" + enrollLog);
            var enrollTail = ReadLogTail(enrollLog, 1000);
            if (!string.IsNullOrWhiteSpace(enrollTail))
            {
                parts.Add("注册日志尾部：" + enrollTail);
            }
        }

        if (File.Exists(innoLog))
        {
            parts.Add("Inno日志：" + innoLog);
            var innoTail = ReadLogTail(innoLog, 1200);
            if (!string.IsNullOrWhiteSpace(innoTail))
            {
                parts.Add("Inno日志尾部：" + innoTail);
            }
        }

        return parts.Count == 0 ? "" : "；" + string.Join("；", parts);
    }

    private static string ReadLogTail(string path, int maxChars)
    {
        try
        {
            if (!File.Exists(path))
            {
                return "";
            }
            var text = File.ReadAllText(path);
            if (text.Length > maxChars)
            {
                text = text[^maxChars..];
            }
            return Regex.Replace(text, @"\s+", " ").Trim();
        }
        catch
        {
            return "";
        }
    }

    private static CheckItem CheckSystemArchitecture()
    {
        var os = RuntimeInformation.OSArchitecture;
        var process = RuntimeInformation.ProcessArchitecture;
        if (os == Architecture.X64 && process == Architecture.X64)
        {
            return CheckItem.Ok("系统架构", "x64 / AMD64");
        }
        if (os == Architecture.Arm64 && process == Architecture.X64)
        {
            return CheckItem.Warn("系统架构", "ARM64 Windows，当前通过 x64 仿真运行；虚拟机/兼容场景可继续安装");
        }
        if (os == Architecture.Arm64)
        {
            return CheckItem.Warn("系统架构", $"ARM64 Windows / 进程 {process}；安装包为 x64，将尝试兼容安装");
        }
        return CheckItem.Fail("系统架构", $"当前为 OS={os}, Process={process}，此安装包要求 x64 或 ARM64+x64 仿真");
    }

    private static string DescribeArchitectureForHeader()
    {
        var os = RuntimeInformation.OSArchitecture;
        var process = RuntimeInformation.ProcessArchitecture;
        if (os == Architecture.Arm64 && process == Architecture.X64)
        {
            return "ARM64 / x64 emulation";
        }
        return os == process ? os.ToString().ToLowerInvariant() : $"{os}/{process}".ToLowerInvariant();
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\\\"") + "\"";
    }

    private static void AppendLine(string path, string line)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        File.AppendAllText(path, line + Environment.NewLine);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // The file contains an enroll token; if deletion fails, setup diagnostics still point to the folder for cleanup.
        }
    }

    private static void TryCreateDiagnosticsBundle(string uiLogDir, string installPath, string zipPath)
    {
        try
        {
            CreateDiagnosticsBundle(uiLogDir, installPath, zipPath);
        }
        catch
        {
            // Diagnostics are helpful but must not hide the original install failure.
        }
    }

    private static void CreateDiagnosticsBundle(string uiLogDir, string installPath, string zipPath)
    {
        var staging = Path.Combine(Path.GetTempPath(), "edr_setup_ui_diag_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(staging);

        CopyDirectoryIfExists(uiLogDir, Path.Combine(staging, "setup-ui"));
        var commonHandoffDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EDR Agent", "setup-ui");
        if (!string.Equals(Path.GetFullPath(uiLogDir), Path.GetFullPath(commonHandoffDir), StringComparison.OrdinalIgnoreCase))
        {
            CopyDirectoryIfExists(commonHandoffDir, Path.Combine(staging, "setup-handoff"));
        }
        CopyDirectoryIfExists(Path.Combine(installPath, "diagnostics"), Path.Combine(staging, "agent-diagnostics"));

        if (File.Exists(zipPath))
        {
            File.Delete(zipPath);
        }
        Directory.CreateDirectory(Path.GetDirectoryName(zipPath) ?? ".");
        ZipFile.CreateFromDirectory(staging, zipPath, CompressionLevel.Fastest, false);
        Directory.Delete(staging, true);
    }

    private static void CopyDirectoryIfExists(string source, string dest)
    {
        if (!Directory.Exists(source))
        {
            return;
        }

        Directory.CreateDirectory(dest);
        foreach (var file in Directory.GetFiles(source, "*", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(source, file);
            if (relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                .Any(part => part.Equals("setup-cache", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }
            var target = Path.Combine(dest, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target) ?? dest);
            File.Copy(file, target, true);
        }
    }

    private static string TryReadJsonString(string path, string property)
    {
        try
        {
            if (!File.Exists(path))
            {
                return string.Empty;
            }
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty(property, out var value) ? value.ToString() : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static bool TryReadJsonBool(string path, string property)
    {
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.True;
        }
        catch
        {
            return false;
        }
    }

    private void TryDragMove()
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var handle = new WindowInteropHelper(this).Handle;
                if (handle != IntPtr.Zero)
                {
                    ReleaseCapture();
                    SendMessage(handle, WmNcLButtonDown, new IntPtr(HtCaption), IntPtr.Zero);
                    return;
                }
            }
            DragMove();
        }
        catch
        {
            // WebView can emit drag messages after the mouse has moved away; ignore.
        }
    }

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
}

public sealed class InstallRequest
{
    public string ApiBase { get; set; } = "";
    public string EnrollToken { get; set; } = "";
    public string ManagementUrl { get; set; } = "";
    public string InstallMode { get; set; } = "upgrade_keep";
    public string RuntimeMode { get; set; } = "scheduled_task";
    public string ProxyMode { get; set; } = "auto";
    public string ProxyUrl { get; set; } = "";
    public string ProxyAuthMode { get; set; } = "none";
    public string ProxyUser { get; set; } = "";
    public string ProxyPassword { get; set; } = "";
    public string RelayUrl { get; set; } = "";
    public string InstallPath { get; set; } = "";
    public bool InstallAutorun { get; set; } = true;
    public bool TrustCa { get; set; }
    public bool HardenAcl { get; set; }
    public bool InsecureTls { get; set; }
    public bool KeepOfflineQueue { get; set; }
    public bool KeepEvidenceCache { get; set; }
    public bool StrictHealthCheck { get; set; }
    public bool AutoOpenEndpoint { get; set; }
}

public sealed class InstallSummary
{
    public string HealthReport { get; set; } = "";
    public string RuntimeVerify { get; set; } = "";
    public string SetupLog { get; set; } = "";
    public string EndpointId { get; set; } = "";
    public string TenantId { get; set; } = "";
    public string PolicyUrl { get; set; } = "";
    public string PolicyVersion { get; set; } = "";
    public string P0RuleVersion { get; set; } = "";
    public string P0RuleCount { get; set; } = "";
    public string AgentVersion { get; set; } = "";
    public string HealthStatus { get; set; } = "";
    public string RuntimeMode { get; set; } = "";
    public bool AgentRunning { get; set; }
}

public sealed class CheckItem
{
    public string Key { get; init; } = "";
    public string Severity { get; init; } = "ok";
    public string Value { get; init; } = "";

    public static CheckItem Ok(string key, string value) => new() { Key = key, Value = value, Severity = "ok" };
    public static CheckItem Warn(string key, string value) => new() { Key = key, Value = value, Severity = "warn" };
    public static CheckItem Fail(string key, string value) => new() { Key = key, Value = value, Severity = "fail" };
}

public sealed record EndpointConfig(string ServerBase, string RestBase, string EnrollUrl);

public sealed record InstallStageState(string Stage, string Detail, int Progress);
