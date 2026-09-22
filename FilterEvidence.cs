using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using Microsoft.Win32;
namespace SchoolScope;
static class FilterEvidence
{
    static string Clean(string html) {
        string text=Regex.Replace(html,@"<(script|style)\b[^>]*>[\s\S]*?</\1\s*>"," ",RegexOptions.IgnoreCase,TimeSpan.FromSeconds(1));
        text=Regex.Replace(text,@"<[^>]*>"," ",RegexOptions.None,TimeSpan.FromSeconds(1));
        return Regex.Replace(WebUtility.HtmlDecode(text),@"\s+"," ",RegexOptions.None,TimeSpan.FromSeconds(1)).Trim();
    }
    public static string Analyze(string html) {
        if(html.Length>262144) html=html[..262144];
        string text=Clean(html); var b=new StringBuilder();
        bool denied=Regex.IsMatch(text,@"страниц.{0,30}заблокир|доступ.{0,30}(запрещ|огранич)|access denied|web page blocked|website blocked|blocked by|url blocked",RegexOptions.IgnoreCase,TimeSpan.FromSeconds(1));
        b.AppendLine(denied?"Признак страницы запрета: найден текст ограничения. Это не устанавливает источник.":"Явного текста запрета не найдено; отсутствие блокировки не доказано.");
        foreach(string brand in new[]{"FortiGuard","Fortinet","Sophos","Squid","Kaspersky","Dr.Web","SkyDNS","NetPolice","ContentKeeper","UserGate","Zscaler","Cisco Umbrella","Forcepoint","SafeDNS","Check Point"})
            if(text.Contains(brand,StringComparison.OrdinalIgnoreCase)||html.Contains(brand,StringComparison.OrdinalIgnoreCase)) b.AppendLine("Упоминание продукта в HTML: "+brand+" — подсказка, не подтверждение установленного продукта.");
        var reasons=Regex.Matches(text,@"(?:причин\w*|категори\w*|reason|category|policy|правил\w*)\s*[:：=]?\s*.{0,220}",RegexOptions.IgnoreCase,TimeSpan.FromSeconds(1));
        foreach(Match reason in reasons.Cast<Match>().Take(8)) b.AppendLine("Возможная причина / правило: "+reason.Value);
        b.AppendLine("\r\nТЕКСТ HTML (без учёта цвета и CSS; скрытые элементы тоже могут попасть в вывод):");
        b.AppendLine(text.Length>20000?text[..20000]+" [вывод ограничен]":text);
        b.AppendLine("\r\nJavaScript не выполнялся. Текст, добавляемый скриптом, и страница, созданная расширением браузера, могут отсутствовать."); return b.ToString();
    }
    public static async Task<string> ReadPage(HttpResponseMessage response) {
        string type=response.Content.Headers.ContentType?.MediaType??"";
        if(!type.Contains("html")&&!type.StartsWith("text/")) return "Анализ тела пропущен: тип "+type;
        using var timeout=new CancellationTokenSource(8000); using var stream=await response.Content.ReadAsStreamAsync(timeout.Token);
        using var output=new MemoryStream(); byte[] buffer=new byte[8192];
        while(output.Length<262144) { int count=await stream.ReadAsync(buffer.AsMemory(0,(int)Math.Min(buffer.Length,262144-output.Length)),timeout.Token); if(count==0) break; output.Write(buffer,0,count); }
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); Encoding encoding=Encoding.UTF8;
        try { var charset=response.Content.Headers.ContentType?.CharSet?.Trim('"'); if(!string.IsNullOrEmpty(charset)) encoding=Encoding.GetEncoding(charset); } catch(ArgumentException) {}
        return Analyze(encoding.GetString(output.ToArray()))+(output.Length==262144?"\r\nЗагружены только первые 256 КиБ.":"");
    }
    static readonly string[] PolicyNames={"URLBlocklist","URLAllowlist","URLBlacklist","URLWhitelist","ExtensionInstallForcelist","ExtensionSettings","ProxySettings","ProxyMode","ProxyServer","ProxyPacUrl","DnsOverHttpsMode","DnsOverHttpsTemplates"};
    public static async Task<string> Collect() {
        var b=new StringBuilder("ПОИСК ПРИЗНАКОВ ФИЛЬТРАЦИИ\r\nНаличие политики, расширения, службы или MDM не доказывает, что именно оно блокирует сайт. Недоступные данные не означают отсутствия ограничений.\r\n\r\n1. СЕТЬ И DNS\r\n");
        b.AppendLine(await Diagnostics.Network());
        b.AppendLine("\r\n2. ПОЛИТИКИ БРАУЗЕРОВ (реестр; фактическое применение проверьте в браузере)");
        foreach(var hive in new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser}) foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}) foreach(var browser in new[]{@"Google\Chrome",@"Microsoft\Edge",@"Chromium",@"YandexBrowser"}) {
            try { using var root=RegistryKey.OpenBaseKey(hive,view); using var key=root.OpenSubKey(@"SOFTWARE\Policies\"+browser); if(key==null) continue;
                b.AppendLine($"{hive}/{view}: {browser}"); foreach(var name in PolicyNames) { var value=key.GetValue(name); if(value!=null) b.AppendLine(name+" = "+value); using var sub=key.OpenSubKey(name); if(sub!=null) foreach(var v in sub.GetValueNames().Take(100)) b.AppendLine(name+"/"+v+" = "+sub.GetValue(v)); }
            } catch(Exception e) { b.AppendLine("Недоступно: "+e.Message); }
        }
        b.AppendLine("\r\n3. РАСШИРЕНИЯ CHROMIUM-БРАУЗЕРОВ ТЕКУЩЕГО ПОЛЬЗОВАТЕЛЯ (наличие файла не означает, что расширение включено)");
        foreach(var relative in new[]{@"Google\Chrome\User Data",@"Microsoft\Edge\User Data",@"Yandex\YandexBrowser\User Data",@"Chromium\User Data"}) {
            string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),relative); if(!Directory.Exists(root)) continue;
            try { foreach(var profile in Directory.EnumerateDirectories(root).Where(p=>Path.GetFileName(p)=="Default"||Path.GetFileName(p).StartsWith("Profile ")).Take(30)) {
                string extensions=Path.Combine(profile,"Extensions"); if(!Directory.Exists(extensions)) continue;
                foreach(var id in Directory.EnumerateDirectories(extensions).Take(200)) foreach(var version in Directory.EnumerateDirectories(id).Take(10)) {
                    try { string path=Path.Combine(version,"manifest.json"); if(!File.Exists(path)||new FileInfo(path).Length>1048576) continue; using var doc=JsonDocument.Parse(await File.ReadAllTextAsync(path)); var item=doc.RootElement;
                        b.AppendLine($"{relative} / {Path.GetFileName(profile)} / {Path.GetFileName(id)}: "+(item.TryGetProperty("name",out var name)?name.ToString():"?")+"; версия "+(item.TryGetProperty("version",out var ver)?ver.ToString():"?"));
                        foreach(var prop in new[]{"permissions","host_permissions"}) if(item.TryGetProperty(prop,out var val)) b.AppendLine("  "+prop+": "+val);
                    } catch(Exception e) { b.AppendLine("Манифест недоступен: "+e.Message); }
                }
            } } catch(Exception e) { b.AppendLine("Профиль недоступен: "+e.Message); }
        }
        b.AppendLine("Firefox и другие профили не сканируются. Состояние расширений проверьте в интерфейсе браузера.");
        b.AppendLine("\r\n4. WINDOWS, УПРАВЛЕНИЕ И СЛУЖБЫ");
        b.AppendLine(await Diagnostics.PowerShell("Get-CimInstance Win32_ComputerSystem | Select PartOfDomain,Domain | Format-List; Get-Service | Where-Object { $_.Status -eq 'Running' } | Select Name,DisplayName | Format-Table -AutoSize; Get-NetFirewallRule -Enabled True -Action Block -ErrorAction Continue | Select -First 100 DisplayName,Direction,PolicyStoreSourceType,PolicyStoreSource | Format-Table -Wrap; Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Enrollments' -ErrorAction Continue | Get-ItemProperty -ErrorAction Continue | Select ProviderID,EnrollmentState | Format-Table"));
        b.AppendLine("Это признаки управления, не доказательство активного MDM или блокировки. Показано максимум 100 блокирующих правил; условия правил и сторонние драйверы фильтрации требуют отдельного анализа.");
        b.AppendLine("\r\n5. УСТАНОВЛЕННЫЕ ПРОГРАММЫ — для сопоставления со страницей запрета");
        var apps=Software.Read(); foreach(var app in apps.Apps) b.AppendLine($"{app.Name} | {app.Publisher}"); foreach(var warning in apps.Warnings) b.AppendLine("Недоступно: "+warning);
        b.AppendLine("\r\nКАК СОПОСТАВИТЬ\r\n• Текст запрета и название продукта — наиболее полезные прямые признаки; проверьте причину/категорию.\r\n• URLBlocklist с соответствующим адресом — возможное ограничение браузера; проверьте chrome://policy или edge://policy.\r\n• Если SchoolScope получает обычную страницу, а браузер — запрет, сравните расширения, политики, прокси и Secure DNS браузера. Это не доказывает единственную причину.\r\n• Одинаковая страница запрета в разных приложениях совместима с сетевым фильтром или локальным агентом.\r\n• DNS-сервер и сертификат сами по себе не доказывают фильтрацию. Для точного вывода сопоставьте отчёт с журналами администратора.\r\n\r\nНастройки и службы не изменялись. Отчёт может содержать внутренние адреса, домен и политики — проверьте перед публикацией.");
        return b.ToString();
    }
}
sealed partial class MainForm
{
    void AddFilterEvidence(TabControl inner) {
        var page=new TabPage("Источник ограничения"); var output=Output(); output.WordWrap=true; var bar=Bar(); bar.AutoSize=true;
        AddButton(bar,"Собрать признаки на ПК",async()=>await Run(output,FilterEvidence.Collect));
        AddButton(bar,"Вставить текст страницы",()=> { output.Text=FilterEvidence.Analyze(Clipboard.GetText()); });
        AddButton(bar,"Открыть сохранённый HTML…",async()=> { using var dialog=new OpenFileDialog { Filter="HTML или текст|*.html;*.htm;*.txt" }; if(dialog.ShowDialog(this)!=DialogResult.OK) return; if(new FileInfo(dialog.FileName).Length>2*1024*1024) throw new IOException("Лимит файла — 2 МБ."); output.Text=FilterEvidence.Analyze(await File.ReadAllTextAsync(dialog.FileName)); });
        AddButton(bar,"Сохранить",()=>Export(output.Text));
        AddButton(bar,"Как пользоваться",()=>Help("1. Соберите признаки на школьном ПК.\n2. Проверьте заблокированный URL в «Проверить сайты»: приложение прочитает текст HTML, включая элементы, скрытые цветом/CSS.\n3. Если запрет виден только в браузере, выделите текст страницы Ctrl+A, скопируйте Ctrl+C и нажмите «Вставить текст страницы». Либо сохраните HTML и откройте его здесь.\n4. Сопоставьте причину, название продукта и политики с отчётом ПК. Эти действия заменяют текущий текст результата — при необходимости сначала сохраните его.\nНазвания служб и наличие UEM не доказывают источник блокировки. Скрипты не выполняются."));
        output.Text="Соберите сведения о сетевых настройках, политиках браузеров, расширениях, службах, брандмауэре и признаках управления. Затем сопоставьте их с точным текстом страницы запрета и указанной причиной.";
        page.Controls.Add(output); page.Controls.Add(bar); inner.TabPages.Insert(0,page);
    }
}
