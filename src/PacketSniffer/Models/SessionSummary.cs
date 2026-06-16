namespace PacketSniffer.Models
{
    public class SessionSummary
    {
        public int Tcp { get; private set; }
        public int Udp { get; private set; }
        public int Icmp { get; private set; }
        public int Others { get; private set; }
        public int Total { get; private set; }

        public void IncrementTcp()
        {
            Tcp++;
            Total++;
        }

        public void IncrementUdp()
        {
            Udp++;
            Total++;
        }

        public void IncrementIcmp()
        {
            Icmp++;
            Total++;
        }

        public void IncrementOthers()
        {
            Others++;
            Total++;
        }

        public void Reset() => Tcp = Udp = Icmp = Others = Total = 0;
    }
}