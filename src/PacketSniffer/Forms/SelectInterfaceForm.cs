using System.Net.NetworkInformation;
using SharpPcap;
using PacketSniffer.Models;
using PacketSniffer.Resources;

namespace PacketSniffer.Forms
{
    public partial class SelectInterfaceForm : Form
    {
        private readonly List<NetworkRecord> samples = [];

        private NetworkInterface? selectedNetworkInterface;
        private long lastBytesReceived;
        private long lastBytesSent;

        public SelectInterfaceForm()
        {
            InitializeComponent();

            EnableDoubleBuffering(usageChartPanel);

            LoadInterfaces();

            usageTimer.Interval = 250;
            usageTimer.Start();
        }

        private void LoadInterfaces()
        {
            var devices = CaptureDeviceList.Instance;
            var networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            foreach (var device in devices)
            {
                var networkInterface = networkInterfaces.FirstOrDefault(ni =>
                    device.Name.Contains(ni.Id, StringComparison.OrdinalIgnoreCase) ||
                    device.Description.Contains(ni.Description, StringComparison.OrdinalIgnoreCase) ||
                    ni.Description.Contains(device.Description, StringComparison.OrdinalIgnoreCase));

                interfacesComboBox.Items.Add(NetworkDeviceItem.Create(device, networkInterface));
            }

            interfacesComboBox.DisplayMember = nameof(NetworkDeviceItem.Description);

            if (interfacesComboBox.Items.Count > 0)
                interfacesComboBox.SelectedIndex = 0;
        }

        private void interfacesComboBox_SelectedIndexChanged(object sender, EventArgs e)
        {
            samples.Clear();

            if (interfacesComboBox.SelectedItem is not NetworkDeviceItem item)
                return;

            selectedNetworkInterface = item.NetworkInterface;

            if (selectedNetworkInterface != null)
            {
                var stats = selectedNetworkInterface.GetIPv4Statistics();
                lastBytesReceived = stats.BytesReceived;
                lastBytesSent = stats.BytesSent;
            }

            usageChartPanel.Invalidate();
        }

        private void usageTimer_Tick(object sender, EventArgs e)
        {
            if (selectedNetworkInterface == null)
                return;

            var stats = selectedNetworkInterface.GetIPv4Statistics();

            var receivedPerSecond = stats.BytesReceived - lastBytesReceived;
            var sentPerSecond = stats.BytesSent - lastBytesSent;

            lastBytesReceived = stats.BytesReceived;
            lastBytesSent = stats.BytesSent;

            samples.Add(NetworkRecord.Create(receivedPerSecond, sentPerSecond));

            if (samples.Count > 60)
                samples.RemoveAt(0);

            usageLabel.Text = string.Format(
                SnifferLabels.UsageSummary,
                SnifferLabels.Received,
                FormatBytes(receivedPerSecond),
                SnifferLabels.Sent,
                FormatBytes(sentPerSecond));

            usageChartPanel.Invalidate();
        }

        private void usageChartPanel_Paint(object sender, PaintEventArgs e)
        {
            var graphics = e.Graphics;

            graphics.SmoothingMode =
                System.Drawing.Drawing2D.SmoothingMode.AntiAlias;

            graphics.Clear(SystemColors.Window);

            if (samples.Count < 2)
                return;

            var maxValue = samples.Max(s => Math.Max(s.Received, s.Sent));

            if (maxValue <= 0)
                maxValue = 1;

            DrawLine(
                graphics,
                samples.Select(s => s.Received).ToList(),
                maxValue,
                Color.FromArgb(0, 220, 130));

            DrawLine(
                graphics,
                samples.Select(s => s.Sent).ToList(),
                maxValue,
                Color.FromArgb(0, 140, 255));
        }

        private void DrawLine(
            Graphics graphics,
            List<long> values,
            long maxValue,
            Color color)
        {
            var width = usageChartPanel.Width;
            var height = usageChartPanel.Height;

            var points = new List<PointF>();

            for (int i = 0; i < values.Count; i++)
            {
                var x = i * (width / 59f);

                var normalized = (float)values[i] / maxValue;

                var y = height - (normalized * (height - 10)) - 5;

                points.Add(new PointF(x, y));
            }

            using var pen = new Pen(color, 4f)
            {
                LineJoin = System.Drawing.Drawing2D.LineJoin.Round,
                StartCap = System.Drawing.Drawing2D.LineCap.Round,
                EndCap = System.Drawing.Drawing2D.LineCap.Round
            };

            graphics.DrawLines(pen, points.ToArray());
        }

        private static void EnableDoubleBuffering(Control control)
        {
            typeof(Control)
                .GetProperty("DoubleBuffered", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)
                ?.SetValue(control, true, null);
        }

        private void continueButton_Click(object sender, EventArgs e)
        {
            if (interfacesComboBox.SelectedItem is not NetworkDeviceItem item)
            {
                MessageBox.Show(SnifferExceptions.MissingInterfaceSelectionException);
                return;
            }

            var snifferForm = new SnifferForm(item.CaptureDevice);

            snifferForm.FormClosed += (s, args) => Close();

            snifferForm.Show();

            Hide();
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes >= 1024 * 1024)
                return $"{bytes / 1024d / 1024d:0.00} MB";

            if (bytes >= 1024)
                return $"{bytes / 1024d:0.00} KB";

            return $"{bytes} B";
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            usageTimer.Stop();
            usageTimer.Dispose();

            base.OnFormClosing(e);
        }
    }
}