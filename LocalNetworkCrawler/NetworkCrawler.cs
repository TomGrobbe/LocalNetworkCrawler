using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace LocalNetworkCrawler;

internal class NetworkCrawler
{
    private const int PING_TIMEOUT_IN_SECONDS = 15;
    internal const string FALLBACK_BLANK_MAC_ADDRESS = "00-00-00-00-00-00";
    private static string currentMachineMacAddress = FALLBACK_BLANK_MAC_ADDRESS;

    /// <summary>
    /// Collection of IP's to keep track of completed ping requests.
    /// </summary>
    private ConcurrentDictionary<string, bool> Ips { get; } = new();

    /// <summary>
    /// Collection of all devices, this is used as a return value for <see cref="GetDevices"/>.
    /// </summary>
    private ConcurrentDictionary<string, Device> AllDevices { get; } = new();

    /// <summary>
    /// Temporary collection of IP's (keys) and MAC Addresses (values) found with ARP.
    /// </summary>
    private ConcurrentDictionary<string, string> Devices { get; } = new();

    /// <summary>
    /// Finds and returns a collection of <see cref="Device"/> found on the network.
    /// </summary>
    /// <returns>A <see cref="List{T}"/> of <see cref="Device"/>, sorted by IP Address (ascending).</returns>
    internal List<Device> GetDevices()
    {
        PreLoadDeviceList(GetLocalIPAddress());
        PingAllDevices();

        var devices = AllDevices.ToList().Select(kvp => kvp.Value).ToList();

        devices.Sort(SortDevices);

        return devices;
    }

    /// <summary>
    /// Sorts the devices list based on the last segment of each IP Address, 0-padded to the left.
    /// </summary>
    /// <param name="deviceA"></param>
    /// <param name="deviceB"></param>
    /// <returns></returns>
    private int SortDevices(Device deviceA, Device deviceB)
    {
        var compA = deviceA.Ip.Split('.').Last().PadLeft(3, '0');
        var compB = deviceB.Ip.Split('.').Last().PadLeft(3, '0');

        return compA.CompareTo(compB);
    }

    /// <summary>
    /// Finds the current default gateway.
    /// This function returns as soon as it finds the first valid IPv4 gateway address.
    /// Any additional network interfaces will be ignored.
    /// </summary>
    /// <returns>A <see cref="string"/> containing the first valid Default Gateway Address.</returns>
    private static string GetNetworkGateway()
    {
        string ip = string.Empty;

        foreach (NetworkInterface netInterface in NetworkInterface.GetAllNetworkInterfaces()
            .Where(nInterface => nInterface.OperationalStatus == OperationalStatus.Up))
        {
            foreach (GatewayIPAddressInformation ipInfo in netInterface.GetIPProperties().GatewayAddresses
                .Where(ipInfo => ipInfo.Address.IsIPv6LinkLocal == false))
            {
                currentMachineMacAddress = string.Join("-", netInterface.GetPhysicalAddress().ToString().SplitInParts(2));
                return ipInfo.Address.ToString();
            }
        }

        return ip;
    }

    /// <summary>
    /// Sends a ping to all IP addresses on the current network interface.<br/>
    /// <strong>Note</strong>: This function is blocking and will wait for all ping results to be processed.
    /// </summary>
    private void PingAllDevices()
    {
        string gatewayIp = GetNetworkGateway();

        //Extracting and pinging all other ip's.
        List<string> ipList = GetAllIpsWithinNetwork(gatewayIp);

        foreach (var ip in ipList)
        {
            Ips[ip] = false;
            Ping(ip, 4000);
        }

        // Backup timer in case any threads get stuck or pings don't trigger a completion event for some reason.
        var start = DateTime.Now;

        // Wait until all threads have stopped and all results are in.
        while (Ips.Any(kvp => kvp.Value == false))
        {
            if (DateTime.Now - start > TimeSpan.FromSeconds(PING_TIMEOUT_IN_SECONDS))
            {
                Console.Error.WriteLine(
                    $"Timeout when pinging hosts. Pending hosts: " +
                    string.Join(", ", Ips.Where(ip => ip.Value == false).Select(ip => ip.Key))
                );
                return;
            }
            Thread.Sleep(1);
        }
    }

    /// <summary>
    /// Calculates and returns a list of IP addresses for the current network.
    /// Eg. 192.168.2.1 ... 192.168.2.255
    /// </summary>
    /// <param name="gatewayIp"></param>
    /// <returns></returns>
    private static List<string> GetAllIpsWithinNetwork(string gatewayIp)
    {
        List<string> ipList = new();
        string[] array = gatewayIp.Split('.')[0..3];

        for (int i = 1; i <= 255; i++)
        {
            string pingIp = string.Join('.', array) + "." + i;

            if (string.IsNullOrEmpty(pingIp))
                continue;

            ipList.Add(pingIp);
        }
        return ipList;
    }

    /// <summary>
    /// Ping a host.
    /// </summary>
    /// <param name="host">IP Address</param>
    /// <param name="timeout">Timeout in milliseconds</param>
    private void Ping(string host, int timeout)
    {
        new Thread(delegate ()
        {
            Ping ping = new();

            ping.PingCompleted += new PingCompletedEventHandler(PingCompleted);

            ping.SendAsync(host, timeout, host);
        }).Start();
    }

    /// <summary>
    /// Eventhandler for when a thread created in <see cref="Ping"/> has finished it's PING to the specified host.
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="eventArgs"></param>
    /// <exception cref="ArgumentNullException"></exception>
    private void PingCompleted(object sender, PingCompletedEventArgs eventArgs)
    {
        string? ip = eventArgs.UserState as string;
        if (eventArgs.Reply != null && eventArgs.Reply.Status == IPStatus.Success && !string.IsNullOrEmpty(ip))
        {
            string hostname = GetHostName(ip, out string[] aliases) ?? "-";
            string macaddres = GetMacAddress(ip);

            AllDevices[ip] = new Device(ip, macaddres, hostname, aliases);
        }

        if (string.IsNullOrEmpty(ip))
            throw new NullReferenceException(string.Format("{0} is null!", nameof(ip)));

        Ips[ip] = true;
    }

    /// <summary>
    /// Gets the hostname and any optional aliases of the specified IP Address.
    /// </summary>
    /// <param name="ipAddress"></param>
    /// <param name="aliases"></param>
    /// <returns></returns>
    private static string? GetHostName(string ipAddress, out string[] aliases)
    {
        try
        {
            IPHostEntry entry = Dns.GetHostEntry(ipAddress);
            if (entry != null)
            {
                aliases = entry.Aliases;
                return entry.HostName;
            }
        }
        catch (SocketException ex)
        {
            Console.Error.WriteLine(ex.Message);
        }

        aliases = Array.Empty<string>();
        return null;
    }

    /// <summary>
    /// Returns the MAC Address for the specified IP Address.
    /// </summary>
    /// <param name="ipAddress"></param>
    /// <returns></returns>
    private string GetMacAddress(string ipAddress)
    {
        if (ipAddress == GetLocalIPAddress())
            return currentMachineMacAddress;

        return Devices.TryGetValue(ipAddress, out string? mac) && !string.IsNullOrEmpty(mac)
            ? mac.ToUpper() : FALLBACK_BLANK_MAC_ADDRESS;
    }

    /// <summary>
    /// Gets the current machine's local IP Address.
    /// </summary>
    /// <returns></returns>
    /// <exception cref="Exception"></exception>
    private static string GetLocalIPAddress()
    {
        var host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (var ip in host.AddressList)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                return ip.ToString();
            }
        }
        throw new Exception("No network adapters with an IPv4 address in the system!");
    }

    /// <summary>
    /// Run ARP for the provided interfaceTarget to cache a list of IP's and MAC Addresses.
    /// </summary>
    /// <param name="interfaceTarget"></param>
    private void PreLoadDeviceList(string interfaceTarget)
    {
        string output = GetDeviceListFromInterface(interfaceTarget);

        /* 
         * Remove all double spaces.
         * there are other ways to parse the output from ARP, but considering none of the row items contain spaces, it'll work.
         * eg. we go from:
         *      192.168.2.254         0f-0f-0f-0f-0f-0f     dynamic
         * to:
         *      192.168.2.254 0f-0f-0f-0f-0f-0f dynamic
         * Then we can simply split by a single space to get the IP and MAC Address.
        */
        while (output.Contains("  "))
        {
            output = output.Replace("  ", " ");
        }

        ParseDevicesFromInterface(output);
    }

    /// <summary>
    /// Execute ARP via a CMD process and return the std output.
    /// </summary>
    /// <param name="interfaceTarget"></param>
    /// <returns></returns>
    private static string GetDeviceListFromInterface(string interfaceTarget)
    {
        Process p = new();

        p.StartInfo.RedirectStandardOutput = true;
        p.StartInfo.UseShellExecute = false;

        p.StartInfo.FileName = "cmd";
        p.StartInfo.Arguments = "/C arp -a -N " + interfaceTarget;

        p.Start();

        string arpOutput = p.StandardOutput.ReadToEnd();

        p.WaitForExit();

        return arpOutput;
    }

    /// <summary>
    /// Parses the output from ARP and adds each IP and MAC Address to the <see cref="Devices"/> dictionary.
    /// </summary>
    /// <param name="interfaceSection"></param>
    private void ParseDevicesFromInterface(string interfaceSection)
    {
        foreach (var line in interfaceSection.Split(Environment.NewLine))
        {
            // Ignore empty lines
            if (string.IsNullOrWhiteSpace(line))
                continue;

            var lineSegments = line.Trim().Split(' ');

            // Ignore lines that don't have any spaces.
            if (lineSegments.Length == 0)
                continue;

            // If the first segment of the line doesn't have 3 dots, it's probably not an IP Address.
            // This check isn't perfect but it'll do for now.
            var count = lineSegments[0].Count((c) =>
            {
                return c.Equals('.');
            });

            // Skip rows that don't start with an IP (probably).
            if (count != 3)
                continue;

            var ip = lineSegments[0];
            var mac = lineSegments[1];

            Devices[ip] = mac;
        }
    }
}