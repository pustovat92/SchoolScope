using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace SchoolScope;
record Packet(string Kind, string Name, string Text, string? Data=null);
sealed class Wire : IDisposable
{
    public readonly TcpClient Tcp;
    public readonly SslStream Stream;
    readonly SemaphoreSlim gate=new(1);
    public Wire(TcpClient tcp, SslStream stream) { Tcp=tcp; Stream=stream; }
    public async Task Send(Packet packet) {
        byte[] data=JsonSerializer.SerializeToUtf8Bytes(packet,new JsonSerializerOptions { Encoder=System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
        if(data.Length>6_000_000) throw new IOException("Сообщение слишком велико.");
        await gate.WaitAsync(); try { using var timeout=new CancellationTokenSource(15000); await Stream.WriteAsync(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(data.Length)),timeout.Token); await Stream.WriteAsync(data,timeout.Token); } finally { gate.Release(); }
    }
    public async Task<Packet> Read(CancellationToken token=default) {
        byte[] size=new byte[4]; await Stream.ReadExactlyAsync(size,token); int length=IPAddress.NetworkToHostOrder(BitConverter.ToInt32(size));
        if(length<1||length>6_000_000) throw new IOException("Недопустимый размер пакета.");
        byte[] data=new byte[length]; using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token); deadline.CancelAfter(15000); await Stream.ReadExactlyAsync(data,deadline.Token);
        return JsonSerializer.Deserialize<Packet>(data)??throw new IOException("Пустой пакет.");
    }
    public void Dispose() { Stream.Dispose(); Tcp.Dispose(); }
}
sealed class RoomServer : IDisposable
{
    readonly TcpListener listener; readonly X509Certificate2 certificate; readonly CancellationTokenSource stop=new();
    readonly System.Collections.Concurrent.ConcurrentDictionary<Wire,byte> clients=new();
    readonly SemaphoreSlim slots=new(16); public string JoinCode { get; }=RoomDiscovery.NewCode(); public string Secret => RoomDiscovery.SecretFor(JoinCode);
    public string Fingerprint => certificate.GetCertHashString(HashAlgorithmName.SHA256);
    public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;
    public RoomServer(int port) {
        using var rsa=RSA.Create(2048); var request=new CertificateRequest("CN=SchoolScope room",rsa,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var generated=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(7));
        certificate=new X509Certificate2(generated.Export(X509ContentType.Pfx));
        listener=new TcpListener(IPAddress.Any,port); listener.Start(); _=Accept();
    }
    async Task Accept() {
        try { while(!stop.IsCancellationRequested) { var tcp=await listener.AcceptTcpClientAsync(stop.Token); if(!slots.Wait(0)) { tcp.Dispose(); continue; } _=Serve(tcp); } } catch(OperationCanceledException) {} catch(ObjectDisposedException) {} catch(SocketException) {}
    }
    async Task Serve(TcpClient tcp) {
        using var wire=new Wire(tcp,new SslStream(tcp.GetStream(),false));
        try {
            using var deadline=new CancellationTokenSource(10000);
            await wire.Stream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate=certificate,EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13 },deadline.Token);
            var auth=await wire.Read(deadline.Token);
            if(auth.Kind!="auth" || auth.Text!=Secret || string.IsNullOrWhiteSpace(auth.Name)||auth.Name.Length>40) return;
            clients.TryAdd(wire,0); await wire.Send(new("system","Комната","Подключено. Участники с приглашением получают все сообщения и файлы комнаты."));
            while(!stop.IsCancellationRequested) {
                var packet=await wire.Read(stop.Token);
                if(packet.Kind=="chat" && (packet.Text==null||packet.Text.Length>4000||packet.Data!=null)) break;
                if(packet.Kind=="file" && (packet.Text==null||packet.Text.Length>255||packet.Data==null||packet.Data.Length>5_592_408)) break;
                if(packet.Kind is not ("chat" or "file")) break;
                packet=packet with { Name=auth.Name };
                await Task.WhenAll(clients.Keys.Select(async peer=> { try { await peer.Send(packet); } catch { peer.Dispose(); } }));
            }
        } catch(Exception e) when(e is IOException or SocketException or AuthenticationException or OperationCanceledException or ObjectDisposedException or JsonException) {} finally { clients.TryRemove(wire,out _); slots.Release(); }
    }
    public void Dispose() { stop.Cancel(); listener.Stop(); foreach(var client in clients.Keys) client.Dispose(); /* Active TLS handshakes may still reference the certificate. */ }
}
sealed class RoomClient : IDisposable
{
    Wire? wire; public event Action<Packet>? Received;
    public async Task Connect(string host,int port,string fingerprint,string secret,string name) {
        var tcp=new TcpClient();
        try {
            using var timeout=new CancellationTokenSource(10000); await tcp.ConnectAsync(host,port,timeout.Token);
            var ssl=new SslStream(tcp.GetStream(),false,(_,cert,_,_)=>cert!=null && string.Equals(cert.GetCertHashString(HashAlgorithmName.SHA256),fingerprint,StringComparison.OrdinalIgnoreCase));
            wire=new Wire(tcp,ssl);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost="SchoolScope",EnabledSslProtocols=SslProtocols.Tls12|SslProtocols.Tls13 },timeout.Token);
            await wire.Send(new("auth",name,secret)); var welcome=await wire.Read(timeout.Token); if(welcome.Kind!="system") throw new IOException("Комната не подтвердила вход."); Received?.Invoke(welcome); _=ReadLoop(wire);
        } catch { wire?.Dispose(); tcp.Dispose(); throw; }
    }
    async Task ReadLoop(Wire source) { try { while(true) { var packet=await source.Read(); Received?.Invoke(packet); } } catch(Exception e) { Received?.Invoke(new("system","Соединение","Отключено: "+e.Message)); } }
    public Task Send(Packet packet) => wire?.Send(packet)??throw new InvalidOperationException("Сначала подключитесь к комнате.");
    public void Dispose() { wire?.Dispose(); wire=null; }
}




