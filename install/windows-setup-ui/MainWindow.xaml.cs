using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.Wpf;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Threading;

namespace EDRAgent.SetupUi;

public partial class MainWindow : Window
{
    private const int WmNcLButtonDown = 0x00A1;
    private const int HtCaption = 2;
    private const int ProbeTimeoutSeconds = 15;
    private const int CheckProgressPauseMs = 70;
    private readonly JsonSerializerOptions _jsonOptions = new(JsonSerializerDefaults.Web);
    private readonly string _baseDir = AppContext.BaseDirectory;
    private string _setupPath = string.Empty;
    private string _lastDiagnosticsPath = string.Empty;
    private Dictionary<string, object?> _preconfig = new(StringComparer.OrdinalIgnoreCase);
    private string _setupIntegrityKey = string.Empty;
    private string _setupHashKey = string.Empty;
    private string _setupHashCache = string.Empty;
    private CheckItem? _setupIntegrityCache;
    private WebView2? _browser;
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
        ContentRendered += OnContentRendered;
    }

    private async void OnContentRendered(object? sender, EventArgs e)
    {
        ContentRendered -= OnContentRendered;
        LoadingPanel.Visibility = Visibility.Visible;
        LoadingText.Text = "正在定位安装包...";
        _setupPath = ResolveSetupPath();
        _preconfig = LoadPreconfig();
        await Dispatcher.Yield(DispatcherPriority.Background);
        try
        {
            LoadingText.Text = "正在初始化 WebView2...";
            _browser = new WebView2();
            BrowserHost.Children.Add(_browser);
            var env = await CreateWebViewEnvironmentAsync();
            await Browser.EnsureCoreWebView2Async(env);
        }
        catch (Exception ex)
        {
            var choice = MessageBox.Show(
                "FDSecurity 图形安装向导需要 Microsoft Edge WebView2 Runtime。\n\n" +
                "可选 fallback：\n" +
                "是：使用同目录传统 FDSecuritySetup.exe 继续安装。\n" +
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
                    MessageBox.Show($"未找到传统安装器: {_setupPath}", "FDSecurity Setup", MessageBoxButton.OK, MessageBoxImage.Error);
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
        Browser.CoreWebView2.NavigationCompleted += (_, _) => HideLoadingPanel();

        var html = Path.Combine(_baseDir, "Assets", "installer.html");
        if (!File.Exists(html))
        {
            MessageBox.Show($"安装器页面缺失: {html}", "FDSecurity Setup", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
            return;
        }

        LoadingText.Text = "正在加载安装页面...";
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
                    HideLoadingPanel();
                    await PostNativeStatusAsync();
                    BeginSetupIntegrityWarmup();
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

    private void HideLoadingPanel()
    {
        LoadingPanel.Visibility = Visibility.Collapsed;
    }

    private WebView2 Browser => _browser ?? throw new InvalidOperationException("WebView2 is not initialized");

    private static async Task<CoreWebView2Environment> CreateWebViewEnvironmentAsync()
    {
        var userDataFolder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "FDSecurity",
            "setup-ui-runtime",
            "webview2");
        Directory.CreateDirectory(userDataFolder);
        var options = new CoreWebView2EnvironmentOptions(
            "--disable-background-networking --disable-component-update --disable-default-apps --disable-sync --metrics-recording-only --no-first-run");
        return await CoreWebView2Environment.CreateAsync(null, userDataFolder, options);
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

        var checks = new List<CheckItem>();
        async Task AddCheckAsync(CheckItem item)
        {
            checks.Add(item);
            await PostAsync("checkProgress", new { check = item, index = checks.Count - 1 });
            await Task.Delay(CheckProgressPauseMs);
        }

        await AddCheckAsync(CheckItem.Ok("操作系统", RuntimeInformation.OSDescription.Trim()));
        await AddCheckAsync(CheckSystemArchitecture());
        await AddCheckAsync(File.Exists(_setupPath)
            ? CheckItem.Ok("安装包", Path.GetFileName(_setupPath))
            : CheckItem.Fail("安装包", "未找到同目录 FDSecuritySetup.exe"));
        await AddCheckAsync(GetSetupIntegrityPrecheck());

        BootstrapTrustMaterial bootstrap = BootstrapTrustMaterial.Empty;
        try
        {
            bootstrap = await ResolveBootstrapTrustAsync(request);
            await AddCheckAsync(bootstrap.Enabled
                ? CheckItem.Ok("Bootstrap 信任", $"manifest 已验签 key={bootstrap.KeyId}")
                : CheckItem.Ok("Bootstrap 信任", "未配置，使用系统信任库"));
        }
        catch (Exception ex)
        {
            await AddCheckAsync(CheckItem.Fail("Bootstrap 信任", ex.Message));
            await PostAsync("toast", new { title = "Bootstrap 信任失败", message = ex.Message, level = "warn" });
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

        await AddCheckAsync(freeMb <= 0
            ? CheckItem.Warn("磁盘空间", "无法读取可用空间，安装阶段会再次校验")
            : freeMb >= 512
                ? CheckItem.Ok("磁盘空间", $"{freeMb:N0} MB 可用")
                : CheckItem.Fail("磁盘空间", $"{freeMb:N0} MB 可用，建议至少 512 MB"));
        await AddCheckAsync(IsElevated()
            ? CheckItem.Ok("管理员权限", "当前进程已具备管理员权限")
            : CheckItem.Warn("管理员权限", "安装阶段将触发 UAC 提权"));
        await AddCheckAsync(endpoint != null
            ? CheckItem.Ok("服务端地址", $"{endpoint.ServerBase}  =>  {endpoint.RestBase}")
            : CheckItem.Fail("服务端地址", "必须填写有效的 http(s) 地址"));
        await AddCheckAsync(!string.IsNullOrWhiteSpace(request.EnrollToken)
            ? CheckItem.Ok("注册令牌", "已填写")
            : CheckItem.Fail("注册令牌", "必须填写 enroll token"));
        await AddCheckAsync(proxyCheck);
        await AddCheckAsync(relayCheck);
        await AddCheckAsync(CheckItem.Ok("WebView2 Runtime", Browser.CoreWebView2?.Environment.BrowserVersionString ?? "active"));

        if (endpoint != null && proxyCheck.Severity != "fail")
        {
            await AddCheckAsync(await ProbeHttpAsync("服务端连通", endpoint.ReadyUrl, request, bootstrap, "platform ready"));
            await AddCheckAsync(await ProbeHttpAsync(
                "注册入口",
                endpoint.EnrollUrl,
                request,
                bootstrap,
                "enroll endpoint",
                required: true,
                method: HttpMethod.Post,
                body: "{}"));
        }
        else
        {
            await AddCheckAsync(CheckItem.Warn(
                "服务端连通",
                endpoint == null ? "服务端地址无效，跳过连通性预检" : "代理配置未通过，跳过连通性预检"));
            await AddCheckAsync(CheckItem.Warn(
                "注册入口",
                endpoint == null ? "服务端地址无效，跳过注册入口预检" : "代理配置未通过，跳过注册入口预检"));
        }
        if (!string.IsNullOrWhiteSpace(normalizedRelayUrl) && proxyCheck.Severity != "fail")
        {
            await AddCheckAsync(await ProbeHttpAsync("Relay 连通", normalizedRelayUrl.TrimEnd('/') + "/healthz", request, BootstrapTrustMaterial.Empty, "relay healthz"));
        }
        else
        {
            await AddCheckAsync(CheckItem.Ok(
                "Relay 连通",
                string.IsNullOrWhiteSpace(normalizedRelayUrl) ? "未配置 Relay/Gateway，跳过" : "代理配置未通过，跳过"));
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
            "FDSecurity",
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
                throw new FileNotFoundException("未找到 FDSecuritySetup.exe，请确认 UI 安装器与 setup 位于同一目录。", _setupPath);
            }
            await PostAsync("installProgress", new { stage = "准备安装环境", progress = 4, detail = "正在校验安装包并准备提权缓存" });
            var integrity = VerifySetupIntegrity();
            if (integrity.Severity == "fail")
            {
                throw new InvalidOperationException(integrity.Value);
            }

            await PostAsync("installProgress", new { stage = "准备安装环境", progress = 6, detail = "正在生成静默安装参数" });
            AppendLine(uiLog, $"[{DateTimeOffset.Now:o}] start install setup={_setupPath} dir={installPath} handoff={handoffDir}");

            var bootstrap = await ResolveBootstrapTrustAsync(request);
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
            paramsFile = WriteEnrollParamsFile(request, endpoint, effectiveProxyUrl, effectiveRelayUrl, bootstrap, installPath, handoffDir);
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
            var finalStageState = ReadInstallStageState(installPath);
            if (finalStageState != null &&
                finalStageState.Stage.StartsWith("安装阶段失败：", StringComparison.OrdinalIgnoreCase))
            {
                var detail = BuildInstallFailureDetail(installPath, innoLog);
                throw new InvalidOperationException($"安装阶段失败{detail}");
            }

            await PostAsync("installProgress", new { stage = "收集健康回执", progress = 92, detail = "正在读取安装诊断与 Agent 启动结果" });
            var summary = ReadInstallSummary(installPath, innoLog);
            TryCreateDiagnosticsBundle(uiLogDir, installPath, _lastDiagnosticsPath);
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

        return Process.Start(psi) ?? throw new InvalidOperationException("无法启动 FDSecuritySetup.exe");
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
            target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FDSecurity", "setup-ui");
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
            Path.Combine(_baseDir, "FDSecuritySetup.exe"),
            Path.Combine(_baseDir, "FDSecuritySetup-bundled.exe"),
            Path.GetFullPath(Path.Combine(_baseDir, "..", "windows-inno", "Output", "FDSecuritySetup-bundled.exe")),
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

        return Path.Combine(_baseDir, "FDSecuritySetup.exe");
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
        var key = GetFileCacheKey(_setupPath);
        if (_setupIntegrityCache != null && string.Equals(_setupIntegrityKey, key, StringComparison.OrdinalIgnoreCase))
        {
            return _setupIntegrityCache;
        }

        _setupIntegrityKey = key;
        var manifest = Path.Combine(_baseDir, "setup-ui-manifest.json");
        if (!File.Exists(manifest))
        {
            return CacheSetupIntegrity(CheckItem.Warn("完整性校验", "缺少 setup-ui-manifest.json，跳过安装器哈希校验"));
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
                return CacheSetupIntegrity(CheckItem.Warn("完整性校验", "manifest 未记录 setup_exe_sha256，跳过安装器哈希校验"));
            }
            if (!File.Exists(_setupPath))
            {
                return CacheSetupIntegrity(CheckItem.Fail("完整性校验", "安装器不存在，无法校验"));
            }
            var actual = ComputeSetupSHA256Cached(_setupPath);
            return CacheSetupIntegrity(string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
                ? CheckItem.Ok("完整性校验", "setup exe SHA256 匹配")
                : CheckItem.Fail("完整性校验", $"setup exe SHA256 不匹配：{actual}"));
        }
        catch (Exception ex)
        {
            return CacheSetupIntegrity(CheckItem.Warn("完整性校验", "读取 manifest 失败：" + ex.Message));
        }
    }

    private CheckItem GetSetupIntegrityPrecheck()
    {
        if (_setupIntegrityCache != null)
        {
            return _setupIntegrityCache;
        }
        var manifest = Path.Combine(_baseDir, "setup-ui-manifest.json");
        if (!File.Exists(manifest))
        {
            return CheckItem.Warn("完整性校验", "缺少 setup-ui-manifest.json，安装开始时跳过哈希校验");
        }
        if (!File.Exists(_setupPath))
        {
            return CheckItem.Fail("完整性校验", "安装器不存在，无法校验");
        }
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
            var root = doc.RootElement;
            var hasExpected = (root.TryGetProperty("setup_exe_sha256", out var snake) && !string.IsNullOrWhiteSpace(snake.GetString())) ||
                              (root.TryGetProperty("setupExeSha256", out var camel) && !string.IsNullOrWhiteSpace(camel.GetString()));
            return hasExpected
                ? CheckItem.Ok("完整性校验", "安装开始前执行 SHA256 校验")
                : CheckItem.Warn("完整性校验", "manifest 未记录 setup_exe_sha256，安装开始时跳过哈希校验");
        }
        catch (Exception ex)
        {
            return CheckItem.Warn("完整性校验", "读取 manifest 失败：" + ex.Message);
        }
    }

    private void BeginSetupIntegrityWarmup()
    {
        _ = Task.Run(() =>
        {
            try
            {
                VerifySetupIntegrity();
            }
            catch
            {
                // Warmup only; install start still performs the authoritative check.
            }
        });
    }

    private CheckItem CacheSetupIntegrity(CheckItem item)
    {
        _setupIntegrityCache = item;
        return item;
    }

    private string ComputeSetupSHA256Cached(string path)
    {
        var key = GetFileCacheKey(path);
        if (!string.IsNullOrWhiteSpace(_setupHashCache) &&
            string.Equals(_setupHashKey, key, StringComparison.OrdinalIgnoreCase))
        {
            return _setupHashCache;
        }
        _setupHashKey = key;
        _setupHashCache = ComputeSHA256(path);
        return _setupHashCache;
    }

    private static string GetFileCacheKey(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return path;
        }
        var info = new FileInfo(path);
        return string.Join("|", info.FullName, info.Length.ToString(), info.LastWriteTimeUtc.Ticks.ToString());
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
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FDSecurity");
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
            return new EndpointConfig(serverBase, restBase, restBase + "/enroll", serverBase + "/ready");
        }

        var baseUrl = builder.Uri.ToString().TrimEnd('/');
        var rest = baseUrl + "/api/v1";
        return new EndpointConfig(baseUrl, rest, rest + "/enroll", baseUrl + "/ready");
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

    private async Task<BootstrapTrustMaterial> ResolveBootstrapTrustAsync(InstallRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.BootstrapManifestJson) &&
            string.IsNullOrWhiteSpace(request.BootstrapManifestPath) &&
            string.IsNullOrWhiteSpace(request.BootstrapManifestUrl))
        {
            return BootstrapTrustMaterial.Empty;
        }

        var manifestJson = await ReadBootstrapManifestSourceAsync(request);
        var trustPublicKey = LoadBootstrapTrustPublicKeyPem();
        if (string.IsNullOrWhiteSpace(trustPublicKey))
        {
            throw new InvalidOperationException("已配置 bootstrap manifest，但缺少 bootstrap_trust_public_key.pem 或 setup-ui-manifest 中的 bootstrap_trust_public_key_pem");
        }

        var payloadJson = VerifyBootstrapManifest(manifestJson, trustPublicKey);
        using var payloadDoc = JsonDocument.Parse(payloadJson);
        var payload = payloadDoc.RootElement;

        var notBefore = JsonString(payload, "not_before", "notBefore");
        var notAfter = JsonString(payload, "not_after", "notAfter");
        if (!string.IsNullOrWhiteSpace(notBefore) &&
            DateTimeOffset.TryParse(notBefore, out var nbf) &&
            DateTimeOffset.UtcNow < nbf.ToUniversalTime())
        {
            throw new InvalidOperationException("bootstrap manifest 尚未生效");
        }
        if (!string.IsNullOrWhiteSpace(notAfter) &&
            DateTimeOffset.TryParse(notAfter, out var exp) &&
            DateTimeOffset.UtcNow > exp.ToUniversalTime())
        {
            throw new InvalidOperationException("bootstrap manifest 已过期");
        }

        var apiBase = JsonString(payload, "api_base", "apiBase", "server_base", "serverBase");
        var enrollToken = JsonString(payload, "enroll_token", "enrollToken", "token");
        var relayUrl = JsonString(payload, "relay_url", "relayUrl");
        var proxyMode = JsonString(payload, "proxy_mode", "proxyMode");
        var tlsCaPem = NormalizePemNewlines(JsonString(payload, "tls_ca_pem", "tlsCaPem", "ca_pem", "caPem"));
        var leafSha256 = NormalizeSha256List(JsonString(payload, "tls_leaf_sha256", "tlsLeafSha256", "certificate_sha256", "certificateSha256"));
        if (string.IsNullOrWhiteSpace(leafSha256) &&
            (payload.TryGetProperty("tls_leaf_sha256", out var pins) || payload.TryGetProperty("tlsLeafSha256", out pins)))
        {
            leafSha256 = NormalizeSha256Array(pins);
        }

        if (!string.IsNullOrWhiteSpace(apiBase))
        {
            request.ApiBase = apiBase;
        }
        if (!string.IsNullOrWhiteSpace(enrollToken))
        {
            request.EnrollToken = enrollToken;
        }
        if (!string.IsNullOrWhiteSpace(relayUrl))
        {
            request.RelayUrl = relayUrl;
        }
        if (!string.IsNullOrWhiteSpace(proxyMode))
        {
            request.ProxyMode = proxyMode;
        }

        if (string.IsNullOrWhiteSpace(tlsCaPem) && string.IsNullOrWhiteSpace(leafSha256))
        {
            throw new InvalidOperationException("bootstrap manifest 已验签，但未包含 tls_ca_pem 或 tls_leaf_sha256");
        }

        return new BootstrapTrustMaterial(
            Enabled: true,
            KeyId: JsonStringFromManifest(manifestJson, "key_id", "keyId"),
            CaPem: tlsCaPem,
            LeafSha256: leafSha256);
    }

    private static async Task<string> ReadBootstrapManifestSourceAsync(InstallRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.BootstrapManifestJson))
        {
            return request.BootstrapManifestJson.Trim();
        }
        if (!string.IsNullOrWhiteSpace(request.BootstrapManifestPath))
        {
            return await File.ReadAllTextAsync(Environment.ExpandEnvironmentVariables(request.BootstrapManifestPath.Trim().Trim('"')));
        }
        if (!string.IsNullOrWhiteSpace(request.BootstrapManifestUrl))
        {
            using var handler = new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
            return await client.GetStringAsync(request.BootstrapManifestUrl.Trim());
        }
        throw new InvalidOperationException("bootstrap manifest 来源为空");
    }

    private string LoadBootstrapTrustPublicKeyPem()
    {
        var env = Environment.GetEnvironmentVariable("EDR_BOOTSTRAP_TRUST_PUBLIC_KEY_PEM");
        if (!string.IsNullOrWhiteSpace(env))
        {
            return NormalizePemNewlines(env);
        }
        var keyFile = Path.Combine(_baseDir, "bootstrap_trust_public_key.pem");
        if (File.Exists(keyFile))
        {
            return File.ReadAllText(keyFile);
        }
        var manifest = Path.Combine(_baseDir, "setup-ui-manifest.json");
        if (File.Exists(manifest))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
                return NormalizePemNewlines(JsonString(doc.RootElement, "bootstrap_trust_public_key_pem", "bootstrapTrustPublicKeyPem"));
            }
            catch
            {
                return "";
            }
        }
        return "";
    }

    private static string VerifyBootstrapManifest(string manifestJson, string trustPublicKeyPem)
    {
        using var doc = JsonDocument.Parse(manifestJson);
        var root = doc.RootElement;
        var payloadB64 = JsonString(root, "payload_b64", "payloadB64");
        var signatureB64 = JsonString(root, "signature", "sig");
        if (string.IsNullOrWhiteSpace(signatureB64) && root.TryGetProperty("signature", out var sigObj) && sigObj.ValueKind == JsonValueKind.Object)
        {
            signatureB64 = JsonString(sigObj, "value", "signature", "sig");
        }
        var alg = JsonString(root, "alg", "algorithm", "signature_alg", "signatureAlg");
        if (string.IsNullOrWhiteSpace(alg) && root.TryGetProperty("signature", out var sigAlgObj) && sigAlgObj.ValueKind == JsonValueKind.Object)
        {
            alg = JsonString(sigAlgObj, "alg", "algorithm");
        }
        if (!string.Equals(alg, "RS256", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("bootstrap manifest 仅支持 RS256 签名");
        }
        if (string.IsNullOrWhiteSpace(payloadB64) || string.IsNullOrWhiteSpace(signatureB64))
        {
            throw new InvalidOperationException("bootstrap manifest 缺少 payload_b64 或 signature");
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(trustPublicKeyPem.AsSpan());
        var ok = rsa.VerifyData(
            Encoding.ASCII.GetBytes(payloadB64),
            Base64UrlDecode(signatureB64),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        if (!ok)
        {
            throw new InvalidOperationException("bootstrap manifest 签名校验失败");
        }
        return Encoding.UTF8.GetString(Base64UrlDecode(payloadB64));
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var s = value.Trim().Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static string JsonStringFromManifest(string manifestJson, params string[] names)
    {
        try
        {
            using var doc = JsonDocument.Parse(manifestJson);
            return JsonString(doc.RootElement, names);
        }
        catch
        {
            return "";
        }
    }

    private static string JsonString(JsonElement element, params string[] names)
    {
        foreach (var name in names)
        {
            if (element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }
        }
        return "";
    }

    private static string NormalizePemNewlines(string value)
    {
        return (value ?? "").Replace("\\r\\n", "\n").Replace("\\n", "\n").Trim();
    }

    private static string NormalizeSha256Array(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Array)
        {
            var pins = new List<string>();
            foreach (var item in element.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    var pin = NormalizeSha256List(item.GetString() ?? "");
                    if (!string.IsNullOrWhiteSpace(pin))
                    {
                        pins.Add(pin);
                    }
                }
            }
            return string.Join(",", pins);
        }
        return element.ValueKind == JsonValueKind.String ? NormalizeSha256List(element.GetString() ?? "") : "";
    }

    private static string NormalizeSha256List(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "";
        }
        var pins = value
            .Split(new[] { ',', ';', ' ', '\r', '\n', '\t' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(x => x.Trim().Replace(":", "").Replace("-", "").ToLowerInvariant())
            .Where(x => Regex.IsMatch(x, "^[0-9a-f]{64}$"))
            .Distinct(StringComparer.OrdinalIgnoreCase);
        return string.Join(",", pins);
    }

    private static string WriteEnrollParamsFile(
        InstallRequest request,
        EndpointConfig endpoint,
        string effectiveProxyUrl,
        string effectiveRelayUrl,
        BootstrapTrustMaterial bootstrap,
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
            ["key_provider"] = "cng",
            ["bootstrap_manifest_verified"] = bootstrap.Enabled,
            ["bootstrap_manifest_key_id"] = bootstrap.KeyId,
            ["bootstrap_ca_pem"] = bootstrap.CaPem,
            ["bootstrap_tls_leaf_sha256"] = bootstrap.LeafSha256,
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

    private static bool ValidateBootstrapServerCertificate(X509Certificate2? certificate, BootstrapTrustMaterial bootstrap)
    {
        if (certificate == null || !bootstrap.Enabled)
        {
            return false;
        }

        var pins = NormalizeSha256List(bootstrap.LeafSha256)
            .Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (pins.Count > 0)
        {
            using var sha = SHA256.Create();
            var leaf = BitConverter.ToString(sha.ComputeHash(certificate.RawData)).Replace("-", "").ToLowerInvariant();
            if (pins.Contains(leaf))
            {
                return true;
            }
        }

        if (string.IsNullOrWhiteSpace(bootstrap.CaPem))
        {
            return false;
        }

        var roots = new List<X509Certificate2>();
        try
        {
            foreach (Match match in Regex.Matches(
                         bootstrap.CaPem,
                         "-----BEGIN CERTIFICATE-----\\s*(?<b64>.*?)\\s*-----END CERTIFICATE-----",
                         RegexOptions.Singleline))
            {
                var b64 = Regex.Replace(match.Groups["b64"].Value, "\\s+", "");
                roots.Add(new X509Certificate2(Convert.FromBase64String(b64)));
            }
            if (roots.Count == 0)
            {
                return false;
            }

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var root in roots)
            {
                chain.ChainPolicy.CustomTrustStore.Add(root);
            }
            return chain.Build(certificate);
        }
        catch
        {
            return false;
        }
        finally
        {
            foreach (var root in roots)
            {
                root.Dispose();
            }
        }
    }

    private static void ConfigureTlsValidation(HttpClientHandler handler, InstallRequest request, BootstrapTrustMaterial bootstrap)
    {
        if (request.InsecureTls)
        {
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            return;
        }

        if (!bootstrap.Enabled)
        {
            return;
        }

        handler.ServerCertificateCustomValidationCallback = (_, certificate, _, errors) =>
        {
            if (errors == SslPolicyErrors.None)
            {
                return true;
            }
            return ValidateBootstrapServerCertificate(certificate, bootstrap);
        };
    }

    private async Task<CheckItem> ProbeHttpAsync(
        string key,
        string url,
        InstallRequest request,
        BootstrapTrustMaterial bootstrap,
        string label,
        bool required = false,
        HttpMethod? method = null,
        string? body = null)
    {
        for (var attempt = 1; attempt <= 2; attempt++)
        {
            try
            {
                using var handler = new HttpClientHandler();
                ConfigureTlsValidation(handler, request, bootstrap);

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

                using var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
                var probeMethod = method ?? HttpMethod.Get;
                using var msg = new HttpRequestMessage(probeMethod, url);
                if (body != null)
                {
                    msg.Content = new StringContent(body, Encoding.UTF8, "application/json");
                }
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(ProbeTimeoutSeconds));
                using var resp = await client.SendAsync(msg, HttpCompletionOption.ResponseHeadersRead, cts.Token);
                var code = (int)resp.StatusCode;
                var suffix = attempt > 1 ? "，重试成功" : "";
                if (required && code == 404)
                {
                    return CheckItem.Fail(key, $"{label} 路由不存在，HTTP 404{suffix}");
                }
                if (probeMethod == HttpMethod.Post &&
                    label.Contains("enroll", StringComparison.OrdinalIgnoreCase) &&
                    code == 400)
                {
                    return CheckItem.Ok(key, $"{label} 路由存在，HTTP 400（空探测请求被正确拒绝）{suffix}");
                }
                if (code < 500)
                {
                    return CheckItem.Ok(key, $"{label} 可达，HTTP {code}{suffix}");
                }
                return CheckItem.Warn(key, $"{label} 可达但服务端返回 HTTP {code}{suffix}");
            }
            catch (TaskCanceledException) when (attempt < 2)
            {
                await Task.Delay(600);
            }
            catch (HttpRequestException) when (attempt < 2)
            {
                await Task.Delay(600);
            }
            catch (TaskCanceledException)
            {
                var msg = $"{label} {ProbeTimeoutSeconds}s 内未响应；请检查地址、端口、防火墙、代理模式和 TLS。";
                return required
                    ? CheckItem.Fail(key, msg + "注册阶段需要该入口可达。")
                    : CheckItem.Warn(key, msg + "可继续安装，注册阶段会再次 POST enroll。");
            }
            catch (Exception ex)
            {
                var msg = $"{label} 不可达：{ex.Message}";
                return required ? CheckItem.Fail(key, msg) : CheckItem.Fail(key, msg);
            }
        }

        return CheckItem.Warn(key, $"{label} 预检未完成；注册阶段会再次 POST enroll。");
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
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FDSecurity", "setup-ui"),
            Path.Combine(Path.GetTempPath(), "FDSecurity", "setup-ui"),
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

    private string PrepareSetupForElevation(string setupPath, string handoffDir, string uiLog)
    {
        try
        {
            if (IsElevated() && !IsUncPath(setupPath))
            {
                return setupPath;
            }
            var hash = ComputeSetupSHA256Cached(setupPath);
            var sourceInfo = new FileInfo(setupPath);
            var cacheDir = Path.Combine(handoffDir, "setup-cache");
            Directory.CreateDirectory(cacheDir);
            var ext = Path.GetExtension(setupPath);
            if (string.IsNullOrWhiteSpace(ext))
            {
                ext = ".exe";
            }
            var cached = Path.Combine(cacheDir, "FDSecuritySetup_" + hash[..12] + ext);
            var sidecar = cached + ".sha256";
            var cachedOk = false;
            if (File.Exists(cached) && File.Exists(sidecar))
            {
                var cachedInfo = new FileInfo(cached);
                var cachedHash = File.ReadAllText(sidecar).Trim();
                cachedOk = cachedInfo.Length == sourceInfo.Length &&
                           string.Equals(cachedHash, hash, StringComparison.OrdinalIgnoreCase);
            }
            if (!cachedOk)
            {
                File.Copy(setupPath, cached, true);
                File.WriteAllText(sidecar, hash, new UTF8Encoding(false));
            }
            return cached;
        }
        catch (Exception ex)
        {
            AppendLine(uiLog, $"[{DateTimeOffset.Now:o}] setup cache copy skipped: {ex.Message}");
            return setupPath;
        }
    }

    private static bool IsUncPath(string path)
    {
        return path.StartsWith(@"\\", StringComparison.OrdinalIgnoreCase);
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
        var skipped = new List<string>();

        CopyDirectoryIfExists(uiLogDir, Path.Combine(staging, "setup-ui"), skipped);
        var commonHandoffDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FDSecurity", "setup-ui");
        if (!string.Equals(Path.GetFullPath(uiLogDir), Path.GetFullPath(commonHandoffDir), StringComparison.OrdinalIgnoreCase))
        {
            CopyDirectoryIfExists(commonHandoffDir, Path.Combine(staging, "setup-handoff"), skipped);
        }
        CopyDirectoryIfExists(Path.Combine(installPath, "diagnostics"), Path.Combine(staging, "agent-diagnostics"), skipped);
        if (skipped.Count > 0)
        {
            File.WriteAllLines(Path.Combine(staging, "diagnostics-skipped-files.txt"), skipped, new UTF8Encoding(false));
        }

        if (File.Exists(zipPath))
        {
            File.Delete(zipPath);
        }
        Directory.CreateDirectory(Path.GetDirectoryName(zipPath) ?? ".");
        ZipFile.CreateFromDirectory(staging, zipPath, CompressionLevel.Fastest, false);
        Directory.Delete(staging, true);
    }

    private static void CopyDirectoryIfExists(string source, string dest, List<string> skipped)
    {
        if (!Directory.Exists(source))
        {
            return;
        }

        Directory.CreateDirectory(dest);
        CopyDirectoryContents(source, source, dest, skipped);
    }

    private static void CopyDirectoryContents(string root, string current, string destRoot, List<string> skipped)
    {
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(current);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            skipped.Add("directory skipped: " + current + " (" + ex.Message + ")");
            return;
        }

        foreach (var file in files)
        {
            var relative = Path.GetRelativePath(root, file);
            if (ShouldSkipDiagnosticsFile(relative))
            {
                skipped.Add("skipped by policy: " + Path.Combine(root, relative));
                continue;
            }
            var target = Path.Combine(destRoot, relative);
            Directory.CreateDirectory(Path.GetDirectoryName(target) ?? destRoot);
            try
            {
                File.Copy(file, target, true);
            }
            catch (IOException ex)
            {
                skipped.Add("locked: " + Path.Combine(root, relative) + " (" + ex.Message + ")");
            }
            catch (UnauthorizedAccessException ex)
            {
                skipped.Add("denied: " + Path.Combine(root, relative) + " (" + ex.Message + ")");
            }
        }

        IEnumerable<string> directories;
        try
        {
            directories = Directory.EnumerateDirectories(current);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            skipped.Add("directory skipped: " + current + " (" + ex.Message + ")");
            return;
        }

        foreach (var directory in directories)
        {
            var relative = Path.GetRelativePath(root, directory);
            if (ShouldSkipDiagnosticsPath(relative))
            {
                skipped.Add("skipped by policy: " + directory);
                continue;
            }
            CopyDirectoryContents(root, directory, destRoot, skipped);
        }
    }

    private static bool ShouldSkipDiagnosticsFile(string relative)
    {
        var name = Path.GetFileName(relative);
        return ShouldSkipDiagnosticsPath(relative) ||
               (name.StartsWith("enroll-params-", StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) ||
               (name.StartsWith("install-ui-", StringComparison.OrdinalIgnoreCase) &&
                name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase)) ||
               name.Equals("install-diagnostics.zip", StringComparison.OrdinalIgnoreCase) ||
               name.Equals("Cookies", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".lock", StringComparison.OrdinalIgnoreCase) ||
               name.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldSkipDiagnosticsPath(string relative)
    {
        var parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return parts.Any(part =>
            part.Equals("setup-cache", StringComparison.OrdinalIgnoreCase) ||
            part.Equals("webview2", StringComparison.OrdinalIgnoreCase) ||
            part.Equals("EBWebView", StringComparison.OrdinalIgnoreCase));
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
    public string BootstrapManifestUrl { get; set; } = "";
    public string BootstrapManifestPath { get; set; } = "";
    public string BootstrapManifestJson { get; set; } = "";
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

public sealed record EndpointConfig(string ServerBase, string RestBase, string EnrollUrl, string ReadyUrl);

public sealed record InstallStageState(string Stage, string Detail, int Progress);

public sealed record BootstrapTrustMaterial(bool Enabled, string KeyId, string CaPem, string LeafSha256)
{
    public static BootstrapTrustMaterial Empty { get; } = new(false, "", "", "");
}
