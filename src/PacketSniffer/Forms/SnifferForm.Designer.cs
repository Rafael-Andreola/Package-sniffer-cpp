using PacketSniffer.Resources;

namespace PacketSniffer.Forms
{
    partial class SnifferForm
    {
        private System.ComponentModel.IContainer components = null;

        private Panel cardPanel;
        private Button startStopButton;
        private DataGridView logsGrid;
        private TreeView detailsTreeView;
        private Label detailsLabel;

        private DataGridViewTextBoxColumn TimeColumn;
        private DataGridViewTextBoxColumn ProtocolColumn;
        private DataGridViewTextBoxColumn SourceColumn;
        private DataGridViewTextBoxColumn DestinationColumn;
        private DataGridViewTextBoxColumn InfoColumn;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();

            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            DataGridViewCellStyle dataGridViewCellStyle1 = new DataGridViewCellStyle();
            DataGridViewCellStyle dataGridViewCellStyle2 = new DataGridViewCellStyle();
            DataGridViewCellStyle dataGridViewCellStyle3 = new DataGridViewCellStyle();
            cardPanel = new Panel();
            startStopButton = new Button();
            logsGrid = new DataGridView();
            TimeColumn = new DataGridViewTextBoxColumn();
            ProtocolColumn = new DataGridViewTextBoxColumn();
            SourceColumn = new DataGridViewTextBoxColumn();
            DestinationColumn = new DataGridViewTextBoxColumn();
            InfoColumn = new DataGridViewTextBoxColumn();
            detailsLabel = new Label();
            detailsTreeView = new TreeView();
            cardPanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)logsGrid).BeginInit();
            SuspendLayout();
            // 
            // cardPanel
            // 
            cardPanel.BackColor = Color.White;
            cardPanel.Controls.Add(startStopButton);
            cardPanel.Controls.Add(logsGrid);
            cardPanel.Controls.Add(detailsLabel);
            cardPanel.Controls.Add(detailsTreeView);
            cardPanel.Location = new Point(40, 35);
            cardPanel.Name = "cardPanel";
            cardPanel.Size = new Size(980, 650);
            cardPanel.TabIndex = 0;
            // 
            // startStopButton
            // 
            startStopButton.BackColor = Color.FromArgb(37, 99, 235);
            startStopButton.FlatAppearance.BorderSize = 0;
            startStopButton.FlatStyle = FlatStyle.Flat;
            startStopButton.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            startStopButton.ForeColor = Color.White;
            startStopButton.Location = new Point(815, 30);
            startStopButton.Name = "startStopButton";
            startStopButton.Size = new Size(130, 38);
            startStopButton.TabIndex = 0;
            startStopButton.Text = SnifferLabels.StartButton;
            startStopButton.UseVisualStyleBackColor = false;
            startStopButton.Click += startStopButton_Click;
            // 
            // logsGrid
            // 
            logsGrid.AllowUserToAddRows = false;
            logsGrid.AllowUserToDeleteRows = false;
            logsGrid.AllowUserToResizeRows = false;
            dataGridViewCellStyle1.BackColor = Color.FromArgb(249, 250, 251);
            logsGrid.AlternatingRowsDefaultCellStyle = dataGridViewCellStyle1;
            logsGrid.BackgroundColor = Color.White;
            logsGrid.BorderStyle = BorderStyle.None;
            logsGrid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            logsGrid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
            dataGridViewCellStyle2.Alignment = DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle2.BackColor = Color.FromArgb(249, 250, 251);
            dataGridViewCellStyle2.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            dataGridViewCellStyle2.ForeColor = Color.FromArgb(75, 85, 99);
            dataGridViewCellStyle2.SelectionBackColor = Color.FromArgb(249, 250, 251);
            dataGridViewCellStyle2.SelectionForeColor = Color.FromArgb(75, 85, 99);
            dataGridViewCellStyle2.WrapMode = DataGridViewTriState.True;
            logsGrid.ColumnHeadersDefaultCellStyle = dataGridViewCellStyle2;
            logsGrid.ColumnHeadersHeight = 38;
            logsGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
            logsGrid.Columns.AddRange(new DataGridViewColumn[] { TimeColumn, ProtocolColumn, SourceColumn, DestinationColumn, InfoColumn });
            dataGridViewCellStyle3.Alignment = DataGridViewContentAlignment.MiddleLeft;
            dataGridViewCellStyle3.BackColor = Color.White;
            dataGridViewCellStyle3.Font = new Font("Segoe UI", 9F);
            dataGridViewCellStyle3.ForeColor = Color.FromArgb(31, 41, 55);
            dataGridViewCellStyle3.SelectionBackColor = Color.FromArgb(219, 234, 254);
            dataGridViewCellStyle3.SelectionForeColor = Color.FromArgb(30, 64, 175);
            dataGridViewCellStyle3.WrapMode = DataGridViewTriState.False;
            logsGrid.DefaultCellStyle = dataGridViewCellStyle3;
            logsGrid.EnableHeadersVisualStyles = false;
            logsGrid.GridColor = Color.FromArgb(229, 231, 235);
            logsGrid.Location = new Point(30, 95);
            logsGrid.MultiSelect = false;
            logsGrid.Name = "logsGrid";
            logsGrid.ReadOnly = true;
            logsGrid.RowHeadersVisible = false;
            logsGrid.RowTemplate.Height = 34;
            logsGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            logsGrid.Size = new Size(915, 380);
            logsGrid.TabIndex = 1;
            logsGrid.CellClick += logsGrid_CellClick;
            // 
            // TimeColumn
            // 
            TimeColumn.HeaderText = SnifferLabels.Time;
            TimeColumn.Name = "TimeColumn";
            TimeColumn.ReadOnly = true;
            TimeColumn.Width = 110;
            // 
            // ProtocolColumn
            // 
            ProtocolColumn.HeaderText = SnifferLabels.Protocol;
            ProtocolColumn.Name = "ProtocolColumn";
            ProtocolColumn.ReadOnly = true;
            ProtocolColumn.Width = 120;
            // 
            // SourceColumn
            // 
            SourceColumn.HeaderText = SnifferLabels.IpSource;
            SourceColumn.Name = "SourceColumn";
            SourceColumn.ReadOnly = true;
            SourceColumn.Width = 170;
            // 
            // DestinationColumn
            // 
            DestinationColumn.HeaderText = SnifferLabels.IpDestination;
            DestinationColumn.Name = "DestinationColumn";
            DestinationColumn.ReadOnly = true;
            DestinationColumn.Width = 170;
            // 
            // InfoColumn
            // 
            InfoColumn.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            InfoColumn.HeaderText = SnifferLabels.Information;
            InfoColumn.Name = "InfoColumn";
            InfoColumn.ReadOnly = true;
            // 
            // detailsLabel
            // 
            detailsLabel.AutoSize = true;
            detailsLabel.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            detailsLabel.ForeColor = Color.FromArgb(75, 85, 99);
            detailsLabel.Location = new Point(30, 500);
            detailsLabel.Name = "detailsLabel";
            detailsLabel.Size = new Size(45, 15);
            detailsLabel.TabIndex = 2;
            detailsLabel.Text = SnifferLabels.Details;
            // 
            // detailsTreeView
            // 
            detailsTreeView.BackColor = Color.White;
            detailsTreeView.BorderStyle = BorderStyle.FixedSingle;
            detailsTreeView.Font = new Font("Consolas", 9.5F);
            detailsTreeView.ForeColor = Color.FromArgb(31, 41, 55);
            detailsTreeView.Location = new Point(30, 525);
            detailsTreeView.Name = "detailsTreeView";
            detailsTreeView.Size = new Size(915, 95);
            detailsTreeView.TabIndex = 2;
            // 
            // SnifferForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Color.FromArgb(243, 243, 243);
            ClientSize = new Size(1060, 720);
            Controls.Add(cardPanel);
            Font = new Font("Segoe UI", 9F);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Name = "SnifferForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = SnifferLabels.PacketSnifferTitle;
            cardPanel.ResumeLayout(false);
            cardPanel.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)logsGrid).EndInit();
            ResumeLayout(false);
        }
    }
}