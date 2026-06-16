namespace PacketSniffer.Models
{
    public class NetworkRecord
    {
        public long Received { get; private set; }
        public long Sent { get; private set; }

        private NetworkRecord(long received, long sent)
        {
            Received = received;
            Sent = sent;
        }

        public static NetworkRecord Create(long received, long sent)
        {
            return new NetworkRecord(received, sent);
        }
    }
}
