using PacketSniffer.Enums;

namespace PacketSniffer.Models
{
    public class PacketRecord
    {
        public string Time { get; private set; }
        public Protocols Protocol { get; private set; }
        public string Source { get; private set; }
        public string Destination { get; private set; }
        public string Summary { get; private set; }
        public Dictionary<string, List<string>> Sections { get; private set; }

        private PacketRecord(
            Protocols protocol,
            string source,
            string destination,
            string summary,
            Dictionary<string, List<string>> sections)
        {
            Time = DateTime.Now.ToString("HH:mm:ss");
            Protocol = protocol;
            Source = source;
            Destination = destination;
            Summary = summary;
            Sections = sections;
        }

        public static PacketRecord Create(
            Protocols protocol,
            string source,
            string destination,
            string summary,
            Dictionary<string, List<string>> sections)
        {
            return new PacketRecord(
                protocol,
                source,
                destination,
                summary,
                sections);
        }
    }
}
