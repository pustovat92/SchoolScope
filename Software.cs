using Microsoft.Win32;
namespace SchoolScope;
record InstalledApp(string Name,string Version,string Publisher);
record AppInventory(List<InstalledApp> Apps,List<string> Warnings);
static class Software
{
    public static AppInventory Read() {
        var apps=new HashSet<InstalledApp>(); var warnings=new List<string>();
        foreach(var hive in new[]{RegistryHive.LocalMachine,RegistryHive.CurrentUser}) foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32}) {
            try { using var root=RegistryKey.OpenBaseKey(hive,view); using var uninstall=root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"); if(uninstall==null) continue;
                foreach(var key in uninstall.GetSubKeyNames()) { try { using var app=uninstall.OpenSubKey(key); if(app?.GetValue("DisplayName") is string title && !string.IsNullOrWhiteSpace(title)) apps.Add(new(title,app.GetValue("DisplayVersion")?.ToString()??"",app.GetValue("Publisher")?.ToString()??"")); } catch(Exception e) { warnings.Add(key+": "+e.Message); } }
            } catch(Exception e) { warnings.Add(e.Message); }
        }
        return new(apps.OrderBy(a=>a.Name,StringComparer.CurrentCultureIgnoreCase).ToList(),warnings);
    }
    public static IEnumerable<InstalledApp> Filter(IEnumerable<InstalledApp> apps,string text) => apps.Where(a=>a.Name.Contains(text,StringComparison.CurrentCultureIgnoreCase)||a.Publisher.Contains(text,StringComparison.CurrentCultureIgnoreCase)||a.Version.Contains(text,StringComparison.CurrentCultureIgnoreCase));
}
sealed partial class MainForm
{
    void AddSoftware() {
        var page=new TabPage("Программы"); var bar=Bar(); bar.Height=100;
        var search=new TextBox { Width=340,PlaceholderText="Поиск по названию, версии или издателю" };
        var count=new Label { AutoSize=true,Padding=new Padding(8),Text="Нажмите «Обновить список»" };
        var table=new DataGridView { Dock=DockStyle.Fill,ReadOnly=true,AllowUserToAddRows=false,AllowUserToDeleteRows=false,AllowUserToResizeRows=false,RowHeadersVisible=false,AutoGenerateColumns=false,BackgroundColor=Color.White,BorderStyle=BorderStyle.None,SelectionMode=DataGridViewSelectionMode.FullRowSelect,AutoSizeColumnsMode=DataGridViewAutoSizeColumnsMode.Fill,MultiSelect=false,CellBorderStyle=DataGridViewCellBorderStyle.SingleHorizontal,GridColor=Color.FromArgb(231,235,241),EnableHeadersVisualStyles=false };
        table.ColumnHeadersDefaultCellStyle=new DataGridViewCellStyle { BackColor=Color.FromArgb(232,238,248),ForeColor=Color.FromArgb(35,49,70),Font=new Font("Segoe UI",10,FontStyle.Bold),Padding=new Padding(8) };
        table.ColumnHeadersHeight=44; table.RowTemplate.Height=36;
        table.DefaultCellStyle=new DataGridViewCellStyle { Padding=new Padding(8,3,8,3),SelectionBackColor=Color.FromArgb(217,232,255),SelectionForeColor=Color.Black };
        table.AlternatingRowsDefaultCellStyle.BackColor=Color.FromArgb(247,249,252);
        table.Columns.Add(new DataGridViewTextBoxColumn { HeaderText="Название",DataPropertyName="Name",FillWeight=48 });
        table.Columns.Add(new DataGridViewTextBoxColumn { HeaderText="Версия",DataPropertyName="Version",FillWeight=20 });
        table.Columns.Add(new DataGridViewTextBoxColumn { HeaderText="Издатель",DataPropertyName="Publisher",FillWeight=32 });
        List<InstalledApp> all=new(); List<string> warnings=new(); string sort="Name"; bool descending=false;
        void RefreshRows() { var filtered=Software.Filter(all,search.Text.Trim()); Func<InstalledApp,string> key=sort=="Version"?a=>a.Version:sort=="Publisher"?a=>a.Publisher:a=>a.Name; var rows=(descending?filtered.OrderByDescending(key,StringComparer.CurrentCultureIgnoreCase):filtered.OrderBy(key,StringComparer.CurrentCultureIgnoreCase)).ToList(); table.DataSource=rows; count.Text=$"Показано {rows.Count} из {all.Count}"+(warnings.Count>0?$" · недоступных записей: {warnings.Count}":""); }
        void LoadRows() { var result=Software.Read(); all=result.Apps; warnings=result.Warnings; RefreshRows(); }
        AddButton(bar,"Обновить список",LoadRows); bar.Controls.Add(new Label { Text="Поиск:",AutoSize=true,Padding=new Padding(4,7,0,0) }); bar.Controls.Add(search);
        AddButton(bar,"Сохранить",()=>Export(string.Join("\r\n",Software.Filter(all,search.Text.Trim()).Select(a=>$"{a.Name} | {a.Version} | {a.Publisher}"))));
        AddButton(bar,"Как пользоваться",()=>Help("Нажмите «Обновить список». Введите часть названия, версии или издателя для поиска.\nНажатие на заголовок колонки меняет сортировку. Выделенную строку можно скопировать Ctrl+C.\n«Сохранить» экспортирует отфильтрованный список.\nPortable-программы и часть Store-приложений могут отсутствовать. Список ничего не удаляет."));
        bar.SetFlowBreak(bar.Controls[^1],true); bar.Controls.Add(count);
        search.TextChanged+=(_,_)=>RefreshRows(); table.ColumnHeaderMouseClick+=(_,e)=> { string next=table.Columns[e.ColumnIndex].DataPropertyName; descending=sort==next&&!descending; sort=next; RefreshRows(); };
        page.Controls.Add(table); page.Controls.Add(bar); tabs.TabPages.Add(page);
        bool loaded=false; page.Enter+=(_,_)=> { if(!loaded) { loaded=true; LoadRows(); } };
    }
}

