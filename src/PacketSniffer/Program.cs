using PacketSniffer.Forms;

namespace PacketSniffer
{
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new SelectInterfaceForm());
        }
    }
}
