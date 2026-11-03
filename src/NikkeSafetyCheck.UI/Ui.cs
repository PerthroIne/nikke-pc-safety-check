using System.Windows;
using System.Windows.Controls;
using System.Windows.Markup;
using System.Windows.Media;

namespace NikkeSafetyCheck.UI;

/// <summary>화면 구성 도우미. 밝은 배경과 충분한 글자 크기를 쓰고, 상태는 색과 함께 아이콘과 문구로 표시한다.</summary>
internal static class Ui
{
    public static readonly FontFamily Font = new("Malgun Gothic, Segoe UI, Segoe UI Symbol");
    public static Brush B(string hex) { var b = (Brush)new BrushConverter().ConvertFromString(hex)!; b.Freeze(); return b; }
    public static readonly Brush Ink = B("#1F2733"), Muted = B("#4F5B6B"), Line = B("#D5DBE3"), PageBg = B("#F6F7F9"), White = B("#FFFFFF"),
        Accent = B("#14519C"), AccentHover = B("#0F3F7A");

    private static ControlTemplate Template(string bg, string fg, string border, string hover) => (ControlTemplate)XamlReader.Parse($$"""
        <ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" TargetType="Button">
          <Border x:Name="b" Background="{{bg}}" BorderBrush="{{border}}" BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}">
            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="{{fg}}"/>
          </Border>
          <ControlTemplate.Triggers>
            <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="{{hover}}"/></Trigger>
            <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="b" Property="BorderBrush" Value="#000000"/><Setter TargetName="b" Property="BorderThickness" Value="2"/></Trigger>
            <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.5"/></Trigger>
          </ControlTemplate.Triggers>
        </ControlTemplate>
        """);

    private static readonly ControlTemplate PrimaryT = Template("#14519C", "#FFFFFF", "#14519C", "#0F3F7A");
    private static readonly ControlTemplate SecondaryT = Template("#FFFFFF", "#14519C", "#9FB3CC", "#E8EEF6");

    public static Button Btn(string text, bool primary, RoutedEventHandler onClick)
    {
        var b = new Button
        {
            Content = text, Template = primary ? PrimaryT : SecondaryT, Padding = new Thickness(18, 10, 18, 10), Margin = new Thickness(0, 0, 10, 10),
            FontSize = primary ? 16 : 14, FontWeight = primary ? FontWeights.SemiBold : FontWeights.Normal, MinHeight = 42, Cursor = System.Windows.Input.Cursors.Hand,
        };
        b.Click += onClick;
        return b;
    }

    public static TextBlock Text(string s, double size = 14, bool bold = false, Brush? color = null, double bottom = 6) => new()
    {
        Text = s, FontSize = size, FontWeight = bold ? FontWeights.SemiBold : FontWeights.Normal, Foreground = color ?? Ink,
        TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, bottom), LineHeight = size * 1.5,
    };

    public static TextBox Selectable(string s) => new()
    {
        Text = s, IsReadOnly = true, BorderThickness = new Thickness(0), Background = Brushes.Transparent, TextWrapping = TextWrapping.Wrap,
        FontSize = 12, Foreground = Muted, Margin = new Thickness(0, 0, 0, 2), Padding = new Thickness(0),
    };

    public static Border Card(UIElement content, string bg = "#FFFFFF", string border = "#D5DBE3") => new()
    {
        Child = content, Background = B(bg), BorderBrush = B(border), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8),
        Padding = new Thickness(16, 14, 16, 12), Margin = new Thickness(0, 0, 0, 10),
    };

    public static StackPanel Stack(params UIElement[] kids)
    {
        var s = new StackPanel();
        foreach (var k in kids) s.Children.Add(k);
        return s;
    }

    public static WrapPanel Row(params UIElement[] kids)
    {
        var w = new WrapPanel { Margin = new Thickness(0, 4, 0, 6) };
        foreach (var k in kids) w.Children.Add(k);
        return w;
    }

    public static UIElement Bullets(IEnumerable<string> items)
    {
        var s = new StackPanel { Margin = new Thickness(0, 0, 0, 6) };
        foreach (var i in items)
        {
            var g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(18) });
            g.ColumnDefinitions.Add(new ColumnDefinition());
            var dot = Text("•", 14, bottom: 3);
            var t = Text(i, 14, bottom: 3);
            Grid.SetColumn(t, 1);
            g.Children.Add(dot); g.Children.Add(t);
            s.Children.Add(g);
        }
        return s;
    }
}
