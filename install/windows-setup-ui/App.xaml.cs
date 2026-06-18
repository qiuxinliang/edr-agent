using System.Globalization;
using System.Windows;

namespace EDRAgent.SetupUi;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        ConfigureSupportedCulture();
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
}
