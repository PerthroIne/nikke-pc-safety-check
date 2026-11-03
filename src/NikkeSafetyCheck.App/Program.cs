using System.Reflection;
using System.Windows;
using NikkeSafetyCheck.UI;
using NikkeSafetyCheck.Windows;

namespace NikkeSafetyCheck.App;

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == ElevatedHelper.Flag) return ElevatedHelper.Run(args);
        if (args.Length > 0) return 64;
        if (System.Runtime.InteropServices.RuntimeInformation.OSArchitecture != System.Runtime.InteropServices.Architecture.X64)
        {
            MessageBox.Show("이 프로그램은 Windows x64 전용입니다. ARM64 Windows는 지원하지 않습니다.", "지원하지 않는 환경", MessageBoxButton.OK, MessageBoxImage.Warning);
            return 2;
        }
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";
        var app = new Application { ShutdownMode = ShutdownMode.OnMainWindowClose };
        return app.Run(new MainWindow(MainWindow.DefaultServices(version)));
    }
}
