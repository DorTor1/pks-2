using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace NetworkAnalyzer;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    private ObservableCollection<string> _urlHistory = new ObservableCollection<string>();
    
    public MainWindow()
    {
        InitializeComponent();
        LoadNetworkInterfaces();
        UrlHistoryListBox.ItemsSource = _urlHistory;
    }
    
    private void LoadNetworkInterfaces()
    {
        NetworkInterfacesListBox.Items.Clear();
        
        NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
        
        foreach (NetworkInterface networkInterface in interfaces)
        {
            NetworkInterfacesListBox.Items.Add(networkInterface.Name);
        }
        
        if (NetworkInterfacesListBox.Items.Count > 0)
        {
            NetworkInterfacesListBox.SelectedIndex = 0;
        }
    }
    
    private void RefreshInterfacesButton_Click(object sender, RoutedEventArgs e)
    {
        LoadNetworkInterfaces();
    }
    
    private void NetworkInterfacesListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (NetworkInterfacesListBox.SelectedItem == null)
            return;
            
        string? selectedInterfaceName = NetworkInterfacesListBox.SelectedItem.ToString();
        if (selectedInterfaceName != null)
        {
            DisplayInterfaceInfo(selectedInterfaceName);
        }
    }
    
    private void DisplayInterfaceInfo(string interfaceName)
    {
        NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
        NetworkInterface? selectedInterface = interfaces.FirstOrDefault(i => i.Name == interfaceName);
        
        if (selectedInterface == null)
            return;
            
        InterfaceName.Text = selectedInterface.Name;
        ConnectionStatus.Text = selectedInterface.OperationalStatus.ToString();
        ConnectionSpeed.Text = selectedInterface.Speed / 1000000 + " Мбит/с";
        MACAddress.Text = FormatMacAddress(selectedInterface.GetPhysicalAddress().ToString());
        
        // Получение IP и маски подсети
        IPInterfaceProperties ipProps = selectedInterface.GetIPProperties();
        StringBuilder ipAddressesBuilder = new StringBuilder();
        StringBuilder subnetMaskBuilder = new StringBuilder();
        
        foreach (UnicastIPAddressInformation ip in ipProps.UnicastAddresses)
        {
            if (ip.Address.AddressFamily == AddressFamily.InterNetwork) // для IPv4
            {
                ipAddressesBuilder.AppendLine(ip.Address.ToString());
                subnetMaskBuilder.AppendLine(ip.IPv4Mask.ToString());
            }
        }
        
        InterfaceIPAddress.Text = ipAddressesBuilder.ToString().Trim();
        SubnetMask.Text = subnetMaskBuilder.ToString().Trim();
    }
    
    private string FormatMacAddress(string macAddress)
    {
        if (string.IsNullOrEmpty(macAddress))
            return string.Empty;
            
        StringBuilder formattedMac = new StringBuilder();
        
        for (int i = 0; i < macAddress.Length; i += 2)
        {
            if (i > 0)
                formattedMac.Append(':');
                
            formattedMac.Append(macAddress.Substring(i, 2));
        }
        
        return formattedMac.ToString();
    }
    
    private void AnalyzeButton_Click(object sender, RoutedEventArgs e)
    {
        string url = UrlTextBox.Text.Trim();
        
        if (string.IsNullOrEmpty(url))
        {
            MessageBox.Show("Пожалуйста, введите URL для анализа.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }
        
        // Добавляем протокол, если его нет
        if (!url.StartsWith("http://") && !url.StartsWith("https://") && !url.StartsWith("ftp://"))
        {
            url = "http://" + url;
            UrlTextBox.Text = url;
        }
        
        // Анализируем URL
        try
        {
            Uri uri = new Uri(url);
            
            // Отображаем компоненты URL
            SchemeTextBlock.Text = uri.Scheme;
            HostTextBlock.Text = uri.Host;
            PortTextBlock.Text = uri.Port.ToString();
            PathTextBlock.Text = uri.AbsolutePath;
            QueryTextBlock.Text = uri.Query;
            FragmentTextBlock.Text = uri.Fragment;
            
            // Определяем тип адреса
            string addressType = DetermineAddressType(uri.Host);
            AddressTypeTextBlock.Text = addressType;
            
            // Выполняем ping
            PingHost(uri.Host);
            
            // Получаем DNS информацию
            GetDnsInfo(uri.Host);
            
            // Добавляем URL в историю, если его еще нет
            if (!_urlHistory.Contains(url))
            {
                _urlHistory.Add(url);
            }
        }
        catch (UriFormatException ex)
        {
            MessageBox.Show($"Неверный формат URL: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Ошибка при анализе URL: {ex.Message}", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    
    private string DetermineAddressType(string host)
    {
        try
        {
            IPAddress[] addresses = Dns.GetHostAddresses(host);
            
            if (addresses.Length == 0)
                return "Не удалось определить";
                
            IPAddress ip = addresses[0];
            
            if (System.Net.IPAddress.IsLoopback(ip))
                return "Локальный (loopback)";
                
            byte[] bytes = ip.GetAddressBytes();
            
            // Проверка на частные сети (RFC 1918)
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                // 10.0.0.0/8
                if (bytes[0] == 10)
                    return "Частный (локальная сеть)";
                    
                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                    return "Частный (локальная сеть)";
                    
                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168)
                    return "Частный (локальная сеть)";
                    
                return "Публичный";
            }
            
            // IPv6
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (ip.IsIPv6LinkLocal)
                    return "IPv6 Link-Local";
                if (ip.IsIPv6SiteLocal)
                    return "IPv6 Site-Local";
                    
                return "IPv6 Публичный";
            }
            
            return "Не удалось определить";
        }
        catch
        {
            return "Не удалось определить";
        }
    }
    
    private void PingHost(string host)
    {
        try
        {
            Ping ping = new Ping();
            PingReply reply = ping.Send(host, 3000);
            
            if (reply.Status == IPStatus.Success)
            {
                PingTextBlock.Text = $"Успешно: {reply.RoundtripTime} мс";
            }
            else
            {
                PingTextBlock.Text = $"Неудачно: {reply.Status}";
            }
        }
        catch (Exception ex)
        {
            PingTextBlock.Text = $"Ошибка: {ex.Message}";
        }
    }
    
    private void GetDnsInfo(string host)
    {
        try
        {
            IPHostEntry hostEntry = Dns.GetHostEntry(host);
            
            StringBuilder dnsInfo = new StringBuilder();
            dnsInfo.AppendLine($"Имя хоста: {hostEntry.HostName}");
            dnsInfo.AppendLine("IP адреса:");
            
            foreach (IPAddress address in hostEntry.AddressList)
            {
                dnsInfo.AppendLine($"  {address}");
            }
            
            DNSTextBlock.Text = dnsInfo.ToString();
        }
        catch (Exception ex)
        {
            DNSTextBlock.Text = $"Ошибка: {ex.Message}";
        }
    }
    
    private void UrlHistoryListBox_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        string? selectedUrl = UrlHistoryListBox.SelectedItem as string;
        
        if (!string.IsNullOrEmpty(selectedUrl))
        {
            UrlTextBox.Text = selectedUrl;
            AnalyzeButton_Click(sender, e);
        }
    }
}