using SharpPcap;
using PacketSniffer.Builders;
using PacketSniffer.Core;
using PacketSniffer.Models;
using PacketSniffer.Resources;

namespace PacketSniffer.Forms
{
    public partial class SnifferForm : Form
    {
        private readonly ICaptureDevice _device;
        private readonly PacketProcessor _processor;
        private readonly List<PacketRecord> _rowDetails = [];

        private bool _isRunning;

        public SnifferForm(ICaptureDevice device)
        {
            InitializeComponent();
            _device = device;

            var seqTracker = new SeqTracker();
            _processor = new PacketProcessor(
                new TcpBuilder(seqTracker),
                new UdpBuilder(),
                new IcmpBuilder()
            );

            _processor.PacketParsed += OnPacketParsed;
        }

        private void startStopButton_Click(object sender, EventArgs e)
        {
            _isRunning = !_isRunning;

            if (_isRunning)
            {
                _processor.Reset();

                _device.OnPacketArrival += _processor.OnPacketArrival;
                _device.Open(DeviceModes.Promiscuous);
                _device.StartCapture();

                startStopButton.Text = SnifferLabels.StopButton;
            }
            else
            {
                _device.StopCapture();
                _device.OnPacketArrival -= _processor.OnPacketArrival;
                _device.Close();

                startStopButton.Text = SnifferLabels.StartButton;
            }
        }

        private void OnPacketParsed(PacketRecord entry)
        {
            if (InvokeRequired)
            {
                Invoke(() => AddRow(entry));
                return;
            }

            AddRow(entry);
        }

        private void AddRow(PacketRecord entry)
        {
            _rowDetails.Add(entry);
            logsGrid.Rows.Add(entry.Time, entry.Protocol, entry.Source, entry.Destination, entry.Summary);
        }

        private void logsGrid_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || e.RowIndex >= _rowDetails.Count)
                return;

            var entry = _rowDetails[e.RowIndex];

            detailsTreeView.Nodes.Clear();

            foreach (var (sectionName, fields) in entry.Sections)
            {
                var sectionNode = detailsTreeView.Nodes.Add(sectionName);

                foreach (var field in fields)
                    sectionNode.Nodes.Add(field);

                sectionNode.Expand();
            }
        }
    }
}