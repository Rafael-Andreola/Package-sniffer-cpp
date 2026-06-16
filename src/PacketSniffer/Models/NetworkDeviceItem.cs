using System.Net.NetworkInformation;
using SharpPcap;

namespace PacketSniffer.Models
{
    internal class NetworkDeviceItem
    {
        public ICaptureDevice CaptureDevice { get; private set; }
        public NetworkInterface? NetworkInterface { get; private set; }
        public string Description => CaptureDevice.Description;

        private NetworkDeviceItem(ICaptureDevice captureDevice, NetworkInterface? networkInterface)
        {
            CaptureDevice = captureDevice;
            NetworkInterface = networkInterface;
        }

        public static NetworkDeviceItem Create(ICaptureDevice captureDevice, NetworkInterface? networkInterface)
        {
            return new NetworkDeviceItem(captureDevice, networkInterface);
        }
    }
}
