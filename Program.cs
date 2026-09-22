using System.Text;
using System.Text.Json;
using System.Net;
using System.Net.Sockets;

namespace SchoolScope;
static class Program
{
    [STAThread] static void Main(string[] args) {
        if(args.Contains("--self-test")) { try { SelfTest.Run().GetAwaiter().GetResult(); Environment.ExitCode=0; } catch(Exception e) { File.WriteAllText("self-test-result.txt",e.ToString()); Environment.ExitCode=1; } return; }
        ApplicationConfiguration.Initialize();
        if(args.Contains("--render-preview")) { using var form=new MainForm(); form.ShowInTaskbar=false; form.Opacity=0; form.Show(); Application.DoEvents(); foreach(var tab in form.Controls.OfType<TabControl>()) { for(int i=0;i<tab.TabPages.Count;i++) { tab.SelectedIndex=i; Application.DoEvents(); using var bitmap=new Bitmap(form.Width,form.Height); form.DrawToBitmap(bitmap,new Rectangle(0,0,form.Width,form.Height)); bitmap.Save("preview-"+i+".png"); } } return; }
        Application.Run(new MainForm());
    }
}
sealed partial class MainForm : Form
{
    readonly TabControl tabs=new() { Dock=DockStyle.Fill };
    readonly Label status=new() { Dock=DockStyle.Bottom,Height=30,Text="Готово. Отчёты сохраняются только по вашей команде.",Padding=new Padding(8) };
    readonly TextBox log=Output(); readonly TextBox user=new() { Text="Участник",Width=130,MaxLength=40 };
    readonly TextBox invitation=new() { Width=470,PlaceholderText="Приглашение SchoolScope" };
    
    readonly TextBox message=new() { Width=500,MaxLength=4000,PlaceholderText="Сообщение всем участникам комнаты" };
    readonly NumericUpDown port=new() { Minimum=1024,Maximum=65535,Value=45831,Width=80 };
    readonly Label connection=new() { Text="Не подключено",AutoSize=true,Padding=new Padding(8) };
    RoomServer? server; RoomClient? client; RoomDiscovery? discovery;
    public MainForm() {
        Text="SchoolScope • диагностика и комната"; Width=1100; Height=780; MinimumSize=new Size(850,600); Font=new Font("Segoe UI",10); StartPosition=FormStartPosition.CenterScreen;
        Controls.Add(tabs); Controls.Add(status);
        AddReport("Компьютер",Diagnostics.Inventory,"1. Нажмите «Проверить». Сбор может занять около минуты.\n2. Изучите оборудование, ОС и список программ. Объём памяти указан в байтах.\n3. Сохраните отчёт в HTML или JSON.\nPortable-программы и некоторые приложения Store отсутствуют в реестре. Недоступные данные отмечаются. Отчёт может содержать пути и другие внутренние сведения — проверьте его перед публикацией.");
        AddSoftware();
        AddReport("Подключение",Diagnostics.Network,"1. Нажмите «Проверить».\n2. Найдите адаптер со статусом Up: Wireless80211 — Wi-Fi, Ethernet — проводной или виртуальный интерфейс.\n3. Посмотрите шлюз и маршруты по умолчанию. Шлюз связывает ПК с другими сетями; DNS переводит имя сайта в IP.\n4. netsh показывает название Wi-Fi, если Windows разрешает это. Доступ может зависеть от разрешения определения местоположения.\n5. Для проверки связи с другим ПК создайте там комнату и попробуйте подключиться по приглашению.\nVPN может использовать виртуальный адаптер. Его наличие не доказывает активное VPN-соединение. Wi-Fi-пароли не запрашиваются.");
        var site=new TabPage("Проверка сайта"); var output=Output(); var bar=Bar(); var url=new TextBox { Text="https://youtube.com",Width=380 }; bar.Controls.Add(url); AddButton(bar,"Проверить",async()=>await Run(output,()=>Diagnostics.Website(url.Text))); AddButton(bar,"Как пользоваться",()=>Help("Введите HTTPS-адрес и нажмите «Проверить».\nDNS — поиск IP; TCP — прямое соединение; HTTPS — защищённый запрос с системным прокси.\nОшибка DNS не доказывает фильтрацию. Ошибка TCP может означать недоступность сервера или обязательный прокси. TLS-ошибка может быть связана с сертификатом, часами или перехватом соединения.\nHTTP 403 бывает ограничением самого сайта. При перенаправлении проверьте показанный адрес; программа не следует по нему автоматически.\nПроверки отправляют запросы только по введённому адресу, не меняют DNS и не обходят фильтры.")); AddButton(bar,"Сохранить",()=>Export(output.Text)); site.Controls.Add(output); site.Controls.Add(bar); tabs.TabPages.Add(site);
        AddBlockingTab();
        AddChat();
        var guide=new TabPage("Инструкция"); var guideText=Output(); guideText.Text="SCHOOLSCOPE 0.4\r\n\r\n1. Начните с вкладки «Подключение»: заранее менять сеть не нужно.\r\n2. Откройте «Компьютер» и запустите сбор характеристик.\r\n3. Во вкладке «Проверка сайта» введите адрес, который не открывается.\r\n4. Для общения откройте «Комната» на двух компьютерах. Подробные шаги — в кнопке «Как пользоваться».\r\n\r\nДля локального чата один ПК нажимает «Создать комнату», другой — «Найти комнаты» и вводит 12-символьный код. IPv4 выбирается автоматически. Если автопоиск недоступен, сохраните приглашение в файл и перенесите его на флешке. Он должен оставаться включённым, приложение — открытым. Одинаковый Wi-Fi не гарантирует связь: возможна изоляция клиентов.\r\n\r\nДля разных сетей нужен доступный сервер комнаты. Эта версия умеет подключаться к указанному узлу через интернет, но публичный сервер не предоставляется. Узел с комнатой должен иметь доступный TCP-порт; это настраивает владелец сети. GitHub не является сервером мессенджера.\r\n\r\nСистема и фильтры не изменяются. Если Windows предложит разрешить входящее соединение комнаты, согласуйте это с администратором школьной сети. При запрете можно продолжать диагностику.\r\n\r\nВсе участники комнаты получают сообщения и отправленные файлы; имена не являются подтверждённой личностью. Приглашение содержит секрет — передавайте его лично. TLS шифрует соединение до узла комнаты; владелец узла технически может читать данные. Это не сквозное шифрование.\r\n\r\nФайлы: до 4 МБ, только когда получатель онлайн. Сохранение после подтверждения, без автозапуска. Истории на диске и офлайн-доставки нет. Восстановление подключения — кнопкой «Подключиться».\r\n\r\nОтчёты могут содержать внутренние IP, имена сетей и пути. Автоматической отправки отчётов, телеметрии и сбора паролей нет. Перед публикацией проверьте содержимое.\r\n\r\nWindows 10/11 x64. Среда .NET включена в автономную сборку. Исходники и сборка: README.md."; guide.Controls.Add(guideText); tabs.TabPages.Add(guide);
        FormClosing+=(_,_)=> { discovery?.Dispose(); client?.Dispose(); server?.Dispose(); };
    }
    static TextBox Output()=>new() { Multiline=true,ReadOnly=true,Dock=DockStyle.Fill,ScrollBars=ScrollBars.Both,WordWrap=false,Font=new Font("Consolas",10),BackColor=Color.White };
    static FlowLayoutPanel Bar()=>new() { Dock=DockStyle.Top,Height=90,Padding=new Padding(8),AutoScroll=true };
    void AddButton(FlowLayoutPanel bar,string title,Action action) { var button=new Button { Text=title,AutoSize=true,Height=32 }; button.Click+=(_,_)=> { try { action(); } catch(Exception e) { ShowError(e); } }; bar.Controls.Add(button); }
    void AddButton(FlowLayoutPanel bar,string title,Func<Task> action) { var button=new Button { Text=title,AutoSize=true,Height=32 }; button.Click+=async(_,_)=> { button.Enabled=false; try { await action(); } catch(Exception e) { ShowError(e); } finally { if(!button.IsDisposed) button.Enabled=true; } }; bar.Controls.Add(button); }
    void ShowError(Exception e)=>MessageBox.Show(this,e.Message,"Не удалось выполнить действие",MessageBoxButtons.OK,MessageBoxIcon.Warning);
    void Help(string text)=>MessageBox.Show(this,text,"Как пользоваться",MessageBoxButtons.OK,MessageBoxIcon.Information);
    void AddReport(string title,Func<Task<string>> collect,string help) { var page=new TabPage(title); var output=Output(); var bar=Bar(); AddButton(bar,"Проверить",async()=>await Run(output,collect)); AddButton(bar,"Сохранить HTML / JSON",()=>Export(output.Text)); AddButton(bar,"Как пользоваться",()=>Help(help)); page.Controls.Add(output); page.Controls.Add(bar); tabs.TabPages.Add(page); }
    async Task Run(TextBox output,Func<Task<string>> task) { status.Text="Выполняется проверка…"; try { output.Text=await Task.Run(task); } finally { status.Text="Проверка завершена. Результаты доступны во вкладке."; } }
    void Export(string text) { if(string.IsNullOrWhiteSpace(text)) throw new InvalidOperationException("Сначала выполните проверку."); using var dialog=new SaveFileDialog { Filter="HTML|*.html|JSON|*.json",FileName="SchoolScope-report",AddExtension=true }; if(dialog.ShowDialog(this)!=DialogResult.OK) return; File.WriteAllText(dialog.FileName,dialog.FilterIndex==2 ? JsonSerializer.Serialize(new { created=DateTimeOffset.Now,report=text },new JsonSerializerOptions { WriteIndented=true }) : "<!doctype html><meta charset='utf-8'><title>SchoolScope</title><style>body{font:15px system-ui;margin:32px}pre{white-space:pre-wrap}</style><h1>SchoolScope</h1><pre>"+WebUtility.HtmlEncode(text)+"</pre>",Encoding.UTF8); }
    void AddChat() {
        var page=new TabPage("Комната"); var bar=CreateRoomControls();
        var bottom=Bar(); bottom.Dock=DockStyle.Bottom; bottom.Height=85; bottom.Controls.Add(message);
        AddButton(bottom,"Отправить",async()=> { if(!string.IsNullOrWhiteSpace(message.Text)) { await Send(new("chat",user.Text,message.Text)); message.Clear(); } });
        AddButton(bottom,"Файл всем…",async()=> { using var dialog=new OpenFileDialog(); if(dialog.ShowDialog(this)!=DialogResult.OK) return; using var input=new FileStream(dialog.FileName,FileMode.Open,FileAccess.Read,FileShare.Read); if(input.Length>4*1024*1024) throw new IOException("Лимит первой версии — 4 МБ."); if(MessageBox.Show(this,"Отправить файл всем участникам комнаты?","Передача файла",MessageBoxButtons.YesNo)!=DialogResult.Yes) return; byte[] bytes=new byte[(int)input.Length]; await input.ReadExactlyAsync(bytes); await Send(new("file",user.Text,Path.GetFileName(dialog.FileName),Convert.ToBase64String(bytes))); });
        page.Controls.Add(log); page.Controls.Add(bottom); page.Controls.Add(bar); tabs.TabPages.Add(page);
    }
    async Task Connect(string host,int port,string fingerprint,string secret) {
        if(string.IsNullOrWhiteSpace(user.Text)) throw new ArgumentException("Укажите имя.");
        var next=new RoomClient(); client=next;
        next.Received+=packet=> { if(IsDisposed||!IsHandleCreated) return; try { BeginInvoke((Action)(()=> { if(client==next) Receive(packet); })); } catch(InvalidOperationException) {} };
        try { await next.Connect(host,port,fingerprint,secret,user.Text.Trim()); connection.Text="В комнате"; } catch { next.Dispose(); client=null; connection.Text="Не подключено"; throw; }
    }
    Task Send(Packet packet)=>client?.Send(packet)??throw new InvalidOperationException("Подключитесь к комнате.");
    void Disconnect() { var old=client; client=null; old?.Dispose(); discovery?.Dispose(); discovery=null; server?.Dispose(); server=null; connection.Text="Не подключено"; }
    void Receive(Packet packet) {
        if(packet.Kind=="system"&&packet.Text.StartsWith("Отключено")) connection.Text="Соединение потеряно";
        if(log.TextLength>150000) log.Clear();
        if(packet.Kind!="file") { log.AppendText($"[{DateTime.Now:HH:mm}] {packet.Name}: {packet.Text}\r\n"); return; }
        try {
            string name=Path.GetFileName(packet.Text.Replace('\\','/')); foreach(var invalid in Path.GetInvalidFileNameChars()) name=name.Replace(invalid,'_'); if(string.IsNullOrWhiteSpace(name)) name="received.bin";
            log.AppendText($"{packet.Name} отправляет файл: {name}\r\n");
            if(MessageBox.Show(this,$"{packet.Name}: сохранить файл {name}?\nФайл не будет запущен.","Входящий файл",MessageBoxButtons.YesNo)!=DialogResult.Yes) return;
            using var dialog=new SaveFileDialog { FileName=name,Filter="Все файлы|*.*",OverwritePrompt=true }; if(dialog.ShowDialog(this)==DialogResult.OK) { byte[] data=Convert.FromBase64String(packet.Data??""); if(data.Length>4*1024*1024) throw new IOException("Размер превышает лимит."); File.WriteAllBytes(dialog.FileName,data); log.AppendText("Файл сохранён.\r\n"); }
        } catch(Exception e) { ShowError(e); }
    }
    record Invite(string Host,int Port,string Fingerprint,string Secret);
}







