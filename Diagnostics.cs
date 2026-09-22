using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32;

namespace SchoolScope;
static class Diagnostics
{
    public static async Task<string> Command(string exe, string args)
    {
        try {
            using var p = new Process { StartInfo = new(exe,args) { UseShellExecute=false, RedirectStandardOutput=true, RedirectStandardError=true, CreateNoWindow=true, StandardOutputEncoding=Encoding.UTF8, StandardErrorEncoding=Encoding.UTF8 } };
            p.Start(); var stdout=p.StandardOutput.ReadToEndAsync(); var stderr=p.StandardError.ReadToEndAsync();
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try { await p.WaitForExitAsync(timeout.Token); } catch(OperationCanceledException) { p.Kill(true); return "Превышено время ожидания."; }
            return (await stdout)+ (p.ExitCode==0 ? "" : "\nНедоступно: "+await stderr);
        } catch(Exception e) { return "Недоступно: "+e.Message; }
    }
    public static Task<string> PowerShell(string script) => Command("powershell.exe", "-NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes("[Console]::OutputEncoding=[Text.Encoding]::UTF8; "+script)));
    public static async Task<string> Inventory()
    {
        var b=new StringBuilder("SchoolScope — локальный отчёт\r\nВремя: "+DateTimeOffset.Now+"\r\n\r\n");
        b.AppendLine(await PowerShell("Get-CimInstance Win32_OperatingSystem | Select Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime | Format-List; Get-CimInstance Win32_ComputerSystem | Select Manufacturer,Model,TotalPhysicalMemory | Format-List; Get-CimInstance Win32_Processor | Select Name,NumberOfCores,NumberOfLogicalProcessors | Format-List; Get-CimInstance Win32_VideoController | Select Name,DriverVersion | Format-List; Get-CimInstance Win32_DiskDrive | Select Model,Size,MediaType | Format-List"));
        b.AppendLine("\r\nУСТАНОВЛЕННЫЕ ПРОГРАММЫ (portable и часть приложений Store могут отсутствовать)");
        var software=Software.Read(); b.AppendLine($"Найдено: {software.Apps.Count}. Откройте вкладку «Программы»: таблица, поиск, сортировка и отдельный экспорт."); foreach(var warning in software.Warnings) b.AppendLine("Недоступно: "+warning);
        b.AppendLine("\r\nБРАНДМАУЭР / АВТОЗАГРУЗКА / ОБНОВЛЕНИЯ");
        b.AppendLine(await PowerShell("Get-NetFirewallProfile | Select Name,Enabled,DefaultInboundAction,DefaultOutboundAction | Format-Table; Get-CimInstance Win32_StartupCommand | Select Name,Command,Location | Format-Table -Wrap; Get-HotFix | Sort InstalledOn -Descending | Select -First 10 HotFixID,InstalledOn | Format-Table"));
        return b.ToString();
    }
    public static async Task<string> Network()
    {
        var b=new StringBuilder("ПОДКЛЮЧЕНИЯ\r\nАктивный адаптер не обязательно обеспечивает доступ в интернет. VPN по названию достоверно не определяется.\r\n\r\n");
        foreach(var n in NetworkInterface.GetAllNetworkInterfaces()) {
            b.AppendLine($"{n.Name} — {n.NetworkInterfaceType}, {n.OperationalStatus}\r\n  {n.Description}");
            try { var p=n.GetIPProperties(); b.AppendLine("  IP: "+string.Join(", ",p.UnicastAddresses.Select(x=>x.Address.ToString()))); b.AppendLine("  Шлюз: "+string.Join(", ",p.GatewayAddresses.Select(x=>x.Address.ToString()))); b.AppendLine("  DNS: "+string.Join(", ",p.DnsAddresses)); b.AppendLine("  DHCP: "+string.Join(", ",p.DhcpServerAddresses)); } catch(Exception e) { b.AppendLine(e.Message); }
        }
        b.AppendLine(await PowerShell(@"netsh wlan show interfaces; Get-NetRoute | Where-Object { $_.DestinationPrefix -in @('0.0.0.0/0','::/0') } | Select InterfaceAlias,NextHop,RouteMetric | Format-Table; Get-VpnConnection -ErrorAction Continue | Select Name,ConnectionStatus,TunnelType | Format-Table; Get-VpnConnection -AllUserConnection -ErrorAction Continue | Select Name,ConnectionStatus,TunnelType | Format-Table; Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select ProxyEnable,ProxyServer,AutoConfigURL | Format-List; netsh winhttp show proxy"));
        b.AppendLine("\r\nHOSTS (активные строки)");
        try { b.AppendLine(string.Join("\r\n",File.ReadLines(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"drivers\etc\hosts")).Where(l=>!string.IsNullOrWhiteSpace(l)&&!l.TrimStart().StartsWith('#')))); } catch(Exception e) { b.AppendLine(e.Message); }
        b.AppendLine("\r\nVPN сторонних производителей и DNS внутри браузера могут не отражаться в этих настройках. Пароли не собираются.");
        return b.ToString();
    }
    public static async Task<string> Website(string input)
    {
        if(!Uri.TryCreate(input.Contains("://")?input:"https://"+input,UriKind.Absolute,out var uri) || uri.Scheme!="https" || !string.IsNullOrEmpty(uri.UserInfo)) throw new ArgumentException("Введите HTTPS-адрес без логина и пароля.");
        var b=new StringBuilder($"Проверка {uri.Host}:{uri.Port}\r\n");
        try { var addresses=await Dns.GetHostAddressesAsync(uri.Host).WaitAsync(TimeSpan.FromSeconds(8)); b.AppendLine("DNS: "+string.Join(", ",addresses.Select(a=>a.ToString()))); } catch(Exception e) { b.AppendLine("DNS: ошибка — "+e.Message+"\r\nВозможны сбой DNS, опечатка или фильтрация; причина не доказана."); }
        try { using var client=new TcpClient(); using var ct=new CancellationTokenSource(8000); await client.ConnectAsync(uri.Host,uri.Port,ct.Token); b.AppendLine("Прямое TCP-соединение: успешно. Локальный адрес маршрута: "+client.Client.LocalEndPoint); } catch(Exception e) { b.AppendLine("Прямое TCP-соединение: "+e.Message+". При обязательном прокси это возможно и без блокировки сайта."); }
        var proxy=HttpClient.DefaultProxy; b.AppendLine("Прокси для адреса: "+(proxy.IsBypassed(uri)?"прямой доступ":proxy.GetProxy(uri)?.ToString()));
        using var handler=new HttpClientHandler { AllowAutoRedirect=false };
        handler.ServerCertificateCustomValidationCallback=(_,cert,_,errors)=> { b.AppendLine($"TLS: {errors}; издатель: {cert?.Issuer}; срок: {cert?.NotAfter}"); return errors==System.Net.Security.SslPolicyErrors.None; };
        using var http=new HttpClient(handler) { Timeout=TimeSpan.FromSeconds(12) };
        try { using var response=await http.GetAsync(uri,HttpCompletionOption.ResponseHeadersRead); b.AppendLine($"HTTP: {(int)response.StatusCode} {response.ReasonPhrase}"); if(response.Headers.Location!=null) b.AppendLine("Перенаправление: "+response.Headers.Location); b.AppendLine("Server: "+response.Headers.Server); b.AppendLine("Via: "+(response.Headers.TryGetValues("Via",out var via)?string.Join(", ",via):"не указан")); try { b.AppendLine(await FilterEvidence.ReadPage(response)); } catch(Exception bodyError) { b.AppendLine("Тело страницы не прочитано: "+bodyError.Message); } b.AppendLine("Ответ сам по себе не доказывает наличие или отсутствие фильтра: 403 может вернуть сам сайт, а страница запрета может иметь код 200."); } catch(Exception e) { b.AppendLine("HTTPS: "+e.GetBaseException().Message); }
        b.AppendLine("\r\nИтог: выше — наблюдения. Точный продукт фильтрации без дополнительных данных не установлен. Настройки не изменялись."); return b.ToString();
    }
}




