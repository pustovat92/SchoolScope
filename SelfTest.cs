using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;

namespace SchoolScope;
static class SelfTest
{
    public static async Task Run() {
        var results=new List<string>(); using var server=new RoomServer(0);
        using var discovery=new RoomDiscovery(server,"Тестовая комната",0);
        var rooms=await RoomDiscovery.Find(discovery.Port,IPAddress.Loopback);
        if(rooms.Count!=1||!RoomDiscovery.Verify(rooms[0].Advertisement,server.JoinCode)) throw new Exception("Discovery failed");
        if(RoomDiscovery.Verify(rooms[0].Advertisement with { Port=1234 },server.JoinCode)) throw new Exception("Tampered discovery accepted");
        if(RoomDiscovery.Verify(rooms[0].Advertisement,RoomDiscovery.NewCode())) throw new Exception("Wrong code accepted");
        if(RoomDiscovery.SecretFor(server.JoinCode.ToLowerInvariant().Replace("-"," "))!=server.Secret) throw new Exception("Code normalization failed");
        results.Add("PASS: UDP discovery, short code, tamper rejection, wrong code, normalization");
        using var a=new RoomClient(); using var b=new RoomClient();
        var chat=new TaskCompletionSource<Packet>(TaskCreationOptions.RunContinuationsAsynchronously);
        var file=new TaskCompletionSource<Packet>(TaskCreationOptions.RunContinuationsAsynchronously);
        b.Received+=p=> { if(p.Kind=="chat") chat.TrySetResult(p); if(p.Kind=="file") file.TrySetResult(p); };
        await a.Connect("127.0.0.1",server.Port,server.Fingerprint,server.Secret,"Alice");
        await b.Connect(rooms[0].Host,rooms[0].Advertisement.Port,rooms[0].Advertisement.Fingerprint,RoomDiscovery.SecretFor(server.JoinCode),"Bob");
        await a.Send(new("chat","Spoofed","Привет ✓"));
        var received=await chat.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if(received.Name!="Alice"||received.Text!="Привет ✓") throw new Exception("Chat failed"); results.Add("PASS: TLS room, two clients, Unicode, authenticated display name");
        byte[] bytes=System.Security.Cryptography.RandomNumberGenerator.GetBytes(4*1024*1024);
        await a.Send(new("file","Alice","test.bin",Convert.ToBase64String(bytes)));
        var incoming=await file.Task.WaitAsync(TimeSpan.FromSeconds(15));
        if(!bytes.SequenceEqual(Convert.FromBase64String(incoming.Data!))) throw new Exception("File mismatch"); results.Add("PASS: 4 MiB file integrity");
        using var wrong=new RoomClient(); bool rejected=false; try { await wrong.Connect("127.0.0.1",server.Port,server.Fingerprint,"wrong","Eve"); } catch { rejected=true; } if(!rejected) throw new Exception("Wrong secret accepted"); results.Add("PASS: wrong room secret rejected");
        using var fake=new RoomClient(); rejected=false; try { await fake.Connect("127.0.0.1",server.Port,new string('0',64),server.Secret,"Eve"); } catch(AuthenticationException) { rejected=true; } if(!rejected) throw new Exception("Wrong certificate accepted"); results.Add("PASS: incorrect TLS fingerprint rejected");
        using(var tcp=new TcpClient()) {
            await tcp.ConnectAsync(IPAddress.Loopback,server.Port); using var ssl=new SslStream(tcp.GetStream(),false,(_,_,_,_)=>true);
            await ssl.AuthenticateAsClientAsync("SchoolScope"); using var wire=new Wire(tcp,ssl); await wire.Send(new("auth","Malformed",server.Secret)); await wire.Read();
            await ssl.WriteAsync(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(int.MaxValue)));
            using var deadline=new CancellationTokenSource(5000); var buffer=new byte[1]; if(await ssl.ReadAsync(buffer,deadline.Token)!=0) throw new Exception("Oversized frame accepted");
        }
        results.Add("PASS: oversized frame rejected before allocation");
        bool invalid=false; try { await Diagnostics.Website("file:///C:/Windows/win.ini"); } catch(ArgumentException) { invalid=true; } if(!invalid) throw new Exception("URL validation failed"); results.Add("PASS: non-HTTPS URL rejected");
        var network=await Diagnostics.Network(); if(!network.Contains("DNS:")) throw new Exception("No adapters collected"); results.Add("PASS: actual network inventory");
        var inventory=await Diagnostics.Inventory(); if(!inventory.Contains("УСТАНОВЛЕННЫЕ ПРОГРАММЫ")) throw new Exception("Inventory failed"); results.Add("PASS: actual system inventory");
        var apps=new[]{new InstalledApp("Alpha","1.2","Vendor"),new InstalledApp("Beta","3.4","Other")};
        if(Software.Filter(apps,"VENDOR").Count()!=1||Software.Filter(apps,"3.4").Single().Name!="Beta"||Software.Filter(apps,"missing").Any()) throw new Exception("Software search failed");
        if(Software.Read().Apps.Count==0) throw new Exception("Installed applications missing");
        results.Add("PASS: structured software inventory and name/version/publisher filter");
        if(LocalNetwork.Addresses().Count==0) throw new Exception("Automatic IPv4 missing");
        results.Add("PASS: automatic active IPv4 enumeration");
        if(!BlockInterpretation.Summarize("HTTP: 200 OK").Contains("содержимое не проверено")) throw new Exception("False success verdict");
        if(!BlockInterpretation.Summarize("HTTP: 403 Forbidden").Contains("сайта или фильтра")) throw new Exception("False filter attribution");
        if(!BlockInterpretation.Summarize("DNS: ошибка\nHTTP: 200 OK").Contains("Ответ получен")) throw new Exception("Proxy success lost");
        if(!BlockInterpretation.Summarize("TLS: RemoteCertificateChainErrors; HTTPS: failure").Contains("сертификата")) throw new Exception("TLS classification");
        if(!BlockInterpretation.Summarize("DNS: ошибка").Contains("не доказана")) throw new Exception("DNS classification");
        if(!BlockInterpretation.Summarize("HTTP: 302 Found").Contains("Перенаправление")) throw new Exception("Redirect classification");
        results.Add("PASS: cautious HTTP/DNS/TLS classification including proxy success");
        var blocked=FilterEvidence.Analyze("<html><style>.hidden{color:white}</style><body>Данная страница заблокирована<div style='color:white'>Причина: Игры; UserGate</div><script>alert('x')</script></body></html>");
        if(!blocked.Contains("Признак страницы запрета: найден")||!blocked.Contains("Причина: Игры")||!blocked.Contains("Упоминание продукта в HTML: UserGate")||blocked.Contains("alert('x')")) throw new Exception("Block HTML analysis failed");
        if(FilterEvidence.Analyze("<html>Добро пожаловать</html>").Contains("Признак страницы запрета: найден")) throw new Exception("Ordinary page misclassified");
        if(!BlockInterpretation.Summarize("HTTP: 200 OK\n"+blocked).Contains("Найден текст запрета")) throw new Exception("HTTP 200 block page missed");
        using(var response=new HttpResponseMessage(System.Net.HttpStatusCode.OK)) { response.Content=new StringContent("<p>Access denied. Reason: policy</p>",System.Text.Encoding.UTF8,"text/html"); if(!(await FilterEvidence.ReadPage(response)).Contains("Reason: policy")) throw new Exception("Response extraction failed"); }
        results.Add("PASS: hidden block reason, vendor evidence, scripts stripped, HTTP 200 denial, response extraction");
        File.WriteAllLines("self-test-result.txt",results);
    }
}



