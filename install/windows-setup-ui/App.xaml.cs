using System.Globalization;
using System.IO;
using System.Windows;
using System.Threading.Tasks;

namespace EDRAgent.SetupUi;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        ConfigureSupportedCulture();
        InstallExceptionLogging();
        WriteSetupUiLog("process_start");
        base.OnStartup(e);
    }

    private static void ConfigureSupportedCulture()
    {
        var uiName = CultureInfo.CurrentUICulture.Name;
        var culture = uiName.StartsWith("zh", StringComparison.OrdinalIgnoreCase)
            ? CultureInfo.GetCultureInfo("zh-CN")
            : CultureInfo.GetCultureInfo("en-US");
        CultureInfo.DefaultThreadCurrentCulture = culture;
        CultureInfo.DefaultThreadCurrentUICulture = culture;
    }

    private void InstallExceptionLogging()
    {
        DispatcherUnhandledException += (_, e) =>
        {
            WriteSetupUiLog("dispatcher_unhandled_exception " + e.Exception);
        };
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
        {
            WriteSetupUiLog("appdomain_unhandled_exception " + e.ExceptionObject);
        };
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            WriteSetupUiLog("task_unobserved_exception " + e.Exception);
        };
    }

    private static void WriteSetupUiLog(string message)
    {
        try
        {
            var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(localAppData) || !Path.IsPathFullyQualified(localAppData))
            {
                localAppData = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? Path.GetTempPath();
            }
            var dir = Path.Combine(localAppData, "FDSecurity", "setup-ui");
            Directory.CreateDirectory(dir);
            File.AppendAllText(
                Path.Combine(dir, "setup-ui.log"),
                $"[{DateTimeOffset.Now:o}] {message}{Environment.NewLine}");
        }
        catch
        {
            // Last-resort startup logging must never block the installer UI.
        }
    }
}
