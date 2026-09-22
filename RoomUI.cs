using System.Text.Json;
namespace SchoolScope;
sealed partial class MainForm
{
    FlowLayoutPanel CreateRoomControls() {
        var bar=Bar(); bar.AutoSize=true; bar.AutoSizeMode=AutoSizeMode.GrowAndShrink;
        var adapters=new ComboBox { Width=285,DropDownStyle=ComboBoxStyle.DropDownList };
        var rooms=new ComboBox { Width=285,DropDownStyle=ComboBoxStyle.DropDownList };
        var code=new TextBox { Width=170,MaxLength=20,PlaceholderText="XXXX-XXXX-XXXX",CharacterCasing=CharacterCasing.Upper };
        var ownCode=new Label { AutoSize=true,Text="Код появится после создания комнаты",Font=new Font("Segoe UI",12,FontStyle.Bold),ForeColor=Color.FromArgb(35,89,175),Padding=new Padding(5) };
        void NewLine() { if(bar.Controls.Count>0) bar.SetFlowBreak(bar.Controls[^1],true); }
        void Label(string text)=>bar.Controls.Add(new Label { Text=text,AutoSize=true,Padding=new Padding(3,7,3,0) });
        void RefreshAdapters() { string? old=(adapters.SelectedItem as LocalAddress)?.Address; adapters.Items.Clear(); foreach(var a in LocalNetwork.Addresses()) adapters.Items.Add(a); if(adapters.Items.Count>0) { adapters.SelectedIndex=0; for(int i=0;i<adapters.Items.Count;i++) if(((LocalAddress)adapters.Items[i]!).Address==old) adapters.SelectedIndex=i; } }
        RefreshAdapters();
        Label("Ваше имя"); bar.Controls.Add(user); Label("Адрес этого ПК"); bar.Controls.Add(adapters); AddButton(bar,"Обновить адреса",RefreshAdapters); NewLine();
        AddButton(bar,"Создать комнату",async()=> {
            if(adapters.SelectedItem is not LocalAddress local) throw new InvalidOperationException("Нет активного IPv4. Подключитесь к сети и обновите адреса.");
            if(string.IsNullOrWhiteSpace(user.Text)) throw new ArgumentException("Укажите имя.");
            Disconnect(); ownCode.Text="Создание…";
            try {
                server=new RoomServer((int)port.Value); invitation.Text=JsonSerializer.Serialize(new Invite(local.Address,server.Port,server.Fingerprint,server.Secret));
                await Connect("127.0.0.1",server.Port,server.Fingerprint,server.Secret);
                ownCode.Text="Код: "+server.JoinCode;
                try { discovery=new RoomDiscovery(server,"Комната: "+user.Text.Trim()); status.Text="Комната доступна для поиска. На другом ПК нажмите «Найти комнаты»."; }
                catch(System.Net.Sockets.SocketException) { status.Text="Чат создан, но автопоиск недоступен. Передайте файл приглашения."; }
            } catch { Disconnect(); ownCode.Text="Комната не создана"; throw; }
        }); bar.Controls.Add(ownCode); NewLine();
        AddButton(bar,"Найти комнаты",async()=> { status.Text="Поиск комнат в локальной сети…"; var found=await RoomDiscovery.Find(); rooms.Items.Clear(); foreach(var room in found) rooms.Items.Add(room); if(rooms.Items.Count>0) rooms.SelectedIndex=0; status.Text=found.Count==0?"Комнат не найдено. Проверьте первый ПК; при блокировке автопоиска перенесите файл приглашения.":$"Найдено комнат: {found.Count}. Выберите комнату и введите её код."; });
        bar.Controls.Add(rooms); Label("Код"); bar.Controls.Add(code);
        AddButton(bar,"Войти",async()=> {
            if(rooms.SelectedItem is not NearbyRoom room) throw new InvalidOperationException("Нажмите «Найти комнаты» и выберите комнату.");
            if(!RoomDiscovery.Verify(room.Advertisement,code.Text)) throw new InvalidOperationException("Код не соответствует комнате. Проверьте код у её создателя и повторите поиск.");
            var secret=RoomDiscovery.SecretFor(code.Text); Disconnect(); ownCode.Text="";
            await Connect(room.Host,room.Advertisement.Port,room.Advertisement.Fingerprint,secret);
        }); NewLine();
        AddButton(bar,"Сохранить приглашение…",()=> { if(server==null) throw new InvalidOperationException("Сначала создайте комнату."); using var dialog=new SaveFileDialog { Filter="Приглашение SchoolScope|*.schoolscope",FileName="Комната.schoolscope" }; if(dialog.ShowDialog(this)==DialogResult.OK) File.WriteAllText(dialog.FileName,invitation.Text); });
        async Task OpenInvite(string text) { var info=JsonSerializer.Deserialize<Invite>(text)??throw new ArgumentException("Неверное приглашение."); if(info.Port<1||info.Port>65535||string.IsNullOrWhiteSpace(info.Host)||info.Fingerprint?.Length!=64||info.Secret?.Length!=48) throw new ArgumentException("Приглашение повреждено."); Disconnect(); ownCode.Text=""; await Connect(info.Host,info.Port,info.Fingerprint,info.Secret); }
        AddButton(bar,"Открыть приглашение…",async()=> { using var dialog=new OpenFileDialog { Filter="Приглашение SchoolScope|*.schoolscope|JSON|*.json" }; if(dialog.ShowDialog(this)==DialogResult.OK) { if(new FileInfo(dialog.FileName).Length>4096) throw new IOException("Неверный файл приглашения."); await OpenInvite(await File.ReadAllTextAsync(dialog.FileName)); } });
        AddButton(bar,"Вставить старый код",async()=>await OpenInvite(Clipboard.GetText()));
        AddButton(bar,"Отключиться",()=> { Disconnect(); ownCode.Text="Комната закрыта / соединение завершено"; invitation.Clear(); });
        AddButton(bar,"Как пользоваться",()=>Help("1. На первом ПК задайте имя и нажмите «Создать комнату». IPv4 выбирается автоматически. Если адаптеров несколько, выберите нужный в списке.\n2. На втором ПК нажмите «Найти комнаты» и выберите комнату первого участника.\n3. Введите показанный на первом ПК код из 12 символов и нажмите «Войти». Дефисы можно не вводить.\n\nКомнат нет? Сохраните приглашение на первом ПК, перенесите файл на флешке и откройте его на втором. Переписывать JSON не нужно.\nФайл не поможет, если сеть вообще запрещает соединение между ПК. Автопоиск использует UDP 45832, чат — TCP 45831.\nКод и файл дают доступ ко всей комнате. Передавайте их только участникам. После пересоздания комнаты они меняются. Файлы чата отправляются всем участникам.")); NewLine();
        bar.Controls.Add(connection);
        return bar;
    }
}

