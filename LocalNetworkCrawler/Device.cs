using System.Text.Json.Serialization;
using MacAddressVendorLookup;

namespace LocalNetworkCrawler;

/// <summary>
/// A Device class which contains data like IP, Hostname and MAC Address.
/// </summary>
[JsonSerializable(typeof(Device))]
public class Device
{
    /// <summary>
    /// IP Address of the device.
    /// </summary>
    [JsonPropertyName("IP")]
    public string Ip { get; }

    /// <summary>
    /// HostName of the device, or the IP Address if the HostName is not available.
    /// </summary>
    [JsonPropertyName("HostName")]
    public string HostName { get; }

    /// <summary>
    /// MAC Address of the device.
    /// </summary>
    [JsonPropertyName("MAC")]
    public string Mac { get; }

    /// <summary>
    /// Optional aliases for the HostName.
    /// </summary>
    [JsonPropertyName("HostAliases")]
    public string[] Aliases { get; }

    /// <summary>
    /// 
    /// </summary>
    [JsonPropertyName("VendorName")]
    public string Vendor { get; }

    /// <summary>
    /// Creates a new instance of the <see cref="Device"/> class.
    /// </summary>
    /// <param name="ip"></param>
    /// <param name="mac"></param>
    /// <param name="hostname"></param>
    /// <param name="aliases"></param>
    public Device(string ip, string mac, string hostname, string[] aliases)
    {
        Ip = ip;
        Mac = mac;
        HostName = hostname;
        Aliases = aliases;

        if (mac == NetworkCrawler.FALLBACK_BLANK_MAC_ADDRESS)
        {
            Vendor = "Unknown";
            return;
        }
        
        var vendorInfoProvider = new MacVendorBinaryReader();
        using (var resourceStream = MacAddressVendorLookup.ManufBinResource.GetStream().Result)
        {
            vendorInfoProvider.Init(resourceStream).Wait();
        }
        var addressMatcher = new AddressMatcher(vendorInfoProvider);
        var physicalMac = System.Net.NetworkInformation.PhysicalAddress.Parse(mac);
        var info = addressMatcher.FindInfo(physicalMac);

        Vendor = (info?.Organization) ?? "Unknown";
    }

    /// <summary>
    /// Creates a new instance of the <see cref="Device"/> class.
    /// </summary>
    /// <param name="ip"></param>
    /// <param name="mac"></param>
    /// <param name="hostname"></param>
    /// <param name="aliases"></param>
    /// <param name="vendor"></param>
    public Device(string ip, string mac, string hostname, string[] aliases, string vendor)
    {
        Ip = ip;
        Mac = mac;
        HostName = hostname;
        Aliases = aliases;
        Vendor = vendor;
    }
}
