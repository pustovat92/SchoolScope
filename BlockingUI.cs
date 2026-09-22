using System.Diagnostics;
using System.Text.RegularExpressions;

namespace SchoolScope;
static class BlockInterpretation
{
    public static string Summarize(string details) {
        if(details.Contains("Признак страницы запрета: найден")) return "Найден текст запрета — откройте причину в деталях";
        var match=Regex.Match(details,@"(?m)^HTTP: (\d{3})");
        if(match.Success) { int code=int.Parse(match.Groups[1].Value);
            if(code==451) return "HTTP 451: ограничение доступа; источник уточняется";
            if(code==403) return "HTTP 403: отказ сайта или фильтра";
            if(code==407) return "Прокси требует авторизацию";
            if(code==429) return "Слишком много запросов — повторите позже";
            if(code>=500) return "Ошибка сервера или посредника";
            if(code>=300&&code<400) return "Перенаправление — проверьте адрес в деталях";
            if(code>=200&&code<300) return "Ответ получен; содержимое не проверено";
            return "HTTP "+code+": смотрите подробности";
        }
        if(details.Contains("TLS:")&&!details.Contains("TLS: None;")) return "Ошибка сертификата — проверьте время и издателя";
        if(details.Contains("DNS: ошибка")) return "Ошибка DNS; блокировка не доказана";
        return "Нет ответа HTTPS; причина не установлена";
    }
}
sealed partial class MainForm
{
    void AddBlockingTab() {
        var page=new TabPage("Блокировки"); var inner=new TabControl { Dock=DockStyle.Fill };
        var checks=new TabPage("Проверить сайты"); var links=new TabPage("Полезные ссылки");
        inner.TabPages.AddRange(new[]{checks,links}); page.Controls.Add(inner); tabs.TabPages.Add(page); AddFilterEvidence(inner);
        var bar=Bar(); bar.Height=112;
        var address=new TextBox { Width=300,PlaceholderText="https://адрес-сайта" };
        var grid=new DataGridView { Dock=DockStyle.Fill,AllowUserToAddRows=false,AllowUserToDeleteRows=false,RowHeadersVisible=false,BackgroundColor=Color.White,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,SelectionMode=DataGridViewSelectionMode.FullRowSelect,MultiSelect=false,EnableHeadersVisualStyles=false,BorderStyle=BorderStyle.None };
        grid.Columns.Add(new DataGridViewCheckBoxColumn { HeaderText="Тест",FillWeight=10 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText="Сайт",ReadOnly=true,FillWeight=36 });
        grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText="Наблюдение",ReadOnly=true,FillWeight=65 });
        grid.RowTemplate.Height=38; grid.ColumnHeadersHeight=40;
        grid.ColumnHeadersDefaultCellStyle.BackColor=Color.FromArgb(232,238,248); grid.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(247,249,252);
        foreach(var site in new[]{"https://youtube.com","https://github.com","https://discord.com","https://yandex.ru/games/","https://ya.ru","https://www.microsoft.com"}) grid.Rows.Add(site.Contains("youtube")||site.Contains("github"),site,"Не проверен");
        var detail=Output(); detail.WordWrap=true; detail.Text="Отметьте сайты и запустите проверку. Выделите строку, чтобы увидеть подробности.\r\n\r\nТест определяет этап ошибки, но не доказывает блокировку и не устанавливает название фильтра. HTTP 200 может содержать страницу запрета. Проверка главной страницы не проверяет видео, загрузки и все домены сервиса.";
        var split=new SplitContainer { Dock=DockStyle.Fill,Orientation=Orientation.Horizontal,Size=new Size(900,500),SplitterDistance=260 };
        split.Panel1.Controls.Add(grid); split.Panel2.Controls.Add(detail); checks.Controls.Add(split); checks.Controls.Add(bar);
        bool busy=false,stop=false;
        var start=new Button { Text="Проверить выбранные",AutoSize=true }; bar.Controls.Add(start);
        AddButton(bar,"Остановить после текущего",()=> { stop=true; status.Text="Проверка завершится после текущего сайта."; });
        AddButton(bar,"Сохранить отчёт",()=> { var reports=grid.Rows.Cast<DataGridViewRow>().Where(r=>r.Tag is string).Select(r=>r.Cells[1].Value+"\r\n"+r.Cells[2].Value+"\r\n"+r.Tag); Export(string.Join("\r\n\r\n",reports)); });
        AddButton(bar,"Как пользоваться",()=>Help("1. Отметьте сайты, включая один обычно доступный, для сравнения. Можно добавить свой HTTPS-адрес.\n2. Нажмите «Проверить выбранные». Выберите строку для подробностей DNS, TCP, TLS и HTTP.\n3. Если не работает всё — сначала проверьте подключение к сети. Если только один сервис — возможны сбой сервиса, ограничение самого сайта или фильтрация.\n4. Сохраните отчёт для администратора. Ошибка сама по себе не доказывает блокировку.\nТекст HTML анализируется без выполнения скриптов; тест не проверяет видеопотоки и все поддомены. Кнопка остановки ждёт завершения текущего адреса."));
        bar.SetFlowBreak(bar.Controls[^1],true); bar.Controls.Add(new Label { Text="Свой сайт:",AutoSize=true,Padding=new Padding(0,7,0,0) }); bar.Controls.Add(address);
        AddButton(bar,"Добавить",()=> { if(busy) throw new InvalidOperationException("Дождитесь завершения проверки."); string input=address.Text.Trim(); if(!Uri.TryCreate(input.Contains("://")?input:"https://"+input,UriKind.Absolute,out var uri)||uri.Scheme!="https"||!string.IsNullOrEmpty(uri.UserInfo)) throw new ArgumentException("Введите HTTPS-адрес без логина и пароля."); if(grid.Rows.Count>=30) throw new InvalidOperationException("Не более 30 сайтов за один список."); if(!grid.Rows.Cast<DataGridViewRow>().Any(r=>Equals(r.Cells[1].Value,uri.AbsoluteUri))) grid.Rows.Add(true,uri.AbsoluteUri,"Не проверен"); address.Clear(); });
        grid.SelectionChanged+=(_,_)=> { if(grid.CurrentRow?.Tag is string report) detail.Text=report; };
        start.Click+=async(_,_)=> {
            if(busy) return; grid.EndEdit(); var selected=grid.Rows.Cast<DataGridViewRow>().Where(r=>r.Cells[0].Value is true).ToList();
            if(selected.Count==0) { Help("Отметьте хотя бы один сайт."); return; }
            busy=true; stop=false; start.Enabled=false; grid.ReadOnly=true;
            try { foreach(var row in selected) { if(stop||IsDisposed) break; string target=(string)row.Cells[1].Value; row.Cells[2].Value="Проверяется…"; status.Text="Проверка: "+target;
                string report; try { report=await Diagnostics.Website(target); } catch(Exception e) { report="Проверка не завершена: "+e.Message; }
                if(IsDisposed) break; row.Tag=report; row.Cells[2].Value=BlockInterpretation.Summarize(report); if(grid.CurrentRow==row) detail.Text=report;
            } } finally { busy=false; if(!IsDisposed) { start.Enabled=true; grid.ReadOnly=false; status.Text=stop?"Проверка остановлена.":"Проверки завершены. Откройте подробности выбранной строки."; } }
        };
        var resources=new FlowLayoutPanel { Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(18) }; links.Controls.Add(resources);
        resources.Controls.Add(new Label { Text="Ссылки открываются в браузере. SchoolScope ничего не скачивает и не запускает автоматически.",AutoSize=true,MaximumSize=new Size(900,0),Margin=new Padding(0,0,0,18) });
        void Link(string title,string url,string explanation) {
            var link=new LinkLabel { Text=title,AutoSize=true,Margin=new Padding(0,8,0,3) }; link.LinkClicked+=(_,_)=> { try { Process.Start(new ProcessStartInfo(url) { UseShellExecute=true }); } catch(Exception e) { ShowError(e); } }; resources.Controls.Add(link);
            resources.Controls.Add(new Label { Text=explanation,AutoSize=true,MaximumSize=new Size(850,0),ForeColor=Color.DimGray });
        }
        Link("Flowseal / zapret-discord-youtube","https://github.com/Flowseal/zapret-discord-youtube","Запрошенный GitHub-проект. Наличие ссылки не означает, что он устранит причину ошибки в вашей сети.");
        Link("bol-van / zapret","https://github.com/bol-van/zapret","Документация исходного проекта. Изменения на школьном ПК согласуйте с администратором.");
        Link("GitHub Status","https://www.githubstatus.com/","Проверить, сообщает ли сам GitHub о сбое сервиса.");
    }
}

