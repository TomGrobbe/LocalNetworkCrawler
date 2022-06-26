using System.Text.Json;

namespace LocalNetworkCrawler;

static class Program
{
    /// <summary>
    /// LocalNetworkCrawler finds all devices on the local network and outputs it as a JSON string.
    /// </summary>
    /// /// <param name="noInput">(Optional) Makes the app exit immediately once finished without waiting for user input.</param>
    static void Main(bool noInput = false)
    {
        NetworkCrawler nc = new();
        
        var devices = nc.GetDevices();
        
        Console.WriteLine(JsonSerializer.Serialize(devices, new JsonSerializerOptions() { WriteIndented = true }));
        
        if (!noInput)
        {
            Console.WriteLine("Press any key to close this window . . .");
            Console.ReadKey();
        }
    }
}
