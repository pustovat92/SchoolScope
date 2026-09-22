using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SchoolScope;
record LocalAddress(string Address,string Adapter,IPAddress Broadcast,int Rank)
{
    public override string ToString()=> $"{Address} · {Adapter}";
}
record RoomAdvertisement(string Name,int Port,string Fingerprint,string Nonce,string Proof);
record NearbyRoom(string Host,RoomAdvertisement Advertisement)
{
    public override string ToString()=> $"{Advertisement.Name} — {Host}";
}
static class LocalNetwork
{
    public static List<LocalAddress> Addresses() {
        var list=new List<LocalAddress>();
        foreach(var adapter in NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up&&n.NetworkInterfaceType!=NetworkInterfaceType.Loopback)) {
            try { var props=adapter.GetIPProperties(); foreach(var ip in props.UnicastAddresses.Where(a=>a.Address.AddressFamily==AddressFamily.InterNetwork)) {
                var a=ip.Address.GetAddressBytes(); var mask=ip.IPv4Mask.GetAddressBytes(); var broadcast=new IPAddress(a.Zip(mask,(x,y)=>(byte)(x|~y)).ToArray());
                var rank=(props.GatewayAddresses.Count>0?0:10)+(a[0]==169&&a[1]==254?20:0);
                list.Add(new(ip.Address.ToString(),adapter.Name,broadcast,rank));
            } } catch(NetworkInformationException) {}
        }
        return list.OrderBy(a=>a.Rank).ThenBy(a=>a.Adapter).ToList();
    }
}
sealed class RoomDiscovery : IDisposable
{
    public const int DiscoveryPort=45832;
    const string Alphabet="23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    readonly UdpClient udp; readonly CancellationTokenSource stop=new(); readonly RoomServer room; readonly string name;
    public static string NewCode()=>string.Join("-",Enumerable.Range(0,3).Select(_=>new string(Enumerable.Range(0,4).Select(_=>Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]).ToArray())));
    public static string Normalize(string code)=>code.Replace("-","").Replace(" ","").Trim().ToUpperInvariant();
    public static string SecretFor(string code) {
        code=Normalize(code); if(code.Length!=12||code.Any(c=>!Alphabet.Contains(c))) throw new ArgumentException("Введите 12 символов кода комнаты, например XXXX-XXXX-XXXX.");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("SchoolScope-room-v2:"+code)))[..48];
    }
    static string Proof(RoomAdvertisement ad,string code)=>Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(SecretFor(code)),Encoding.UTF8.GetBytes(JsonSerializer.Serialize(ad with { Proof="" }))));
    public static bool Verify(RoomAdvertisement ad,string code) {
        try { return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(ad.Proof),Convert.FromHexString(Proof(ad,code))); } catch(FormatException) { return false; }
    }
    public RoomDiscovery(RoomServer room,string name,int port=DiscoveryPort) { this.room=room; this.name=name; udp=new UdpClient(new IPEndPoint(IPAddress.Any,port)); _=Listen(); }
    public int Port=>((IPEndPoint)udp.Client.LocalEndPoint!).Port;
    async Task Listen() {
        try { while(!stop.IsCancellationRequested) {
            var request=await udp.ReceiveAsync(stop.Token); if(request.Buffer.Length!=48) continue;
            var text=Encoding.ASCII.GetString(request.Buffer); if(!text.StartsWith("SchoolScopeFind:")) continue;
            string nonce=text[16..]; if(nonce.Length!=32||nonce.Any(c=>!Uri.IsHexDigit(c))) continue;
            var ad=new RoomAdvertisement(name,room.Port,room.Fingerprint,nonce,""); ad=ad with { Proof=Proof(ad,room.JoinCode) };
            await udp.SendAsync(JsonSerializer.SerializeToUtf8Bytes(ad),request.RemoteEndPoint,stop.Token);
        } } catch(OperationCanceledException) {} catch(ObjectDisposedException) {} catch(SocketException) {}
    }
    public static async Task<List<NearbyRoom>> Find(int port=DiscoveryPort,IPAddress? target=null) {
        using var socket=new UdpClient(new IPEndPoint(IPAddress.Any,0)); socket.EnableBroadcast=true;
        string nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(16)); byte[] query=Encoding.ASCII.GetBytes("SchoolScopeFind:"+nonce);
        var targets=target!=null?new[]{target}:LocalNetwork.Addresses().Select(a=>a.Broadcast).Append(IPAddress.Broadcast).Append(IPAddress.Loopback).Distinct().ToArray();
        foreach(var ip in targets) { try { await socket.SendAsync(query,new IPEndPoint(ip,port)); } catch(SocketException) {} }
        using var timeout=new CancellationTokenSource(2500); var found=new Dictionary<string,NearbyRoom>();
        try { while(found.Count<64) { var reply=await socket.ReceiveAsync(timeout.Token); if(reply.Buffer.Length>2048) continue;
            try { var ad=JsonSerializer.Deserialize<RoomAdvertisement>(reply.Buffer); if(ad==null||ad.Nonce!=nonce||ad.Port is <1 or >65535||ad.Name==null||ad.Name.Length>80||ad.Fingerprint?.Length!=64||ad.Proof?.Length!=64) continue;
                string host=reply.RemoteEndPoint.Address.ToString(); var key=ad.Fingerprint+":"+ad.Port;
                if(!found.ContainsKey(key)||found[key].Host=="127.0.0.1") found[key]=new(host,ad);
            } catch(JsonException) {}
        } } catch(OperationCanceledException) {}
        return found.Values.ToList();
    }
    public void Dispose() { stop.Cancel(); udp.Dispose(); }
}
