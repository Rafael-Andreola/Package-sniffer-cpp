using PacketSniffer.Resources;

namespace PacketSniffer.Forms
{
    partial class SelectInterfaceForm
    {
        private System.ComponentModel.IContainer components = null;

        private Panel cardPanel;
        private Label titleLabel;
        private Label subtitleLabel;
        private ComboBox interfacesComboBox;
        private Button continueButton;
        private Panel usageChartPanel;
        private Label usageLabel;
        private System.Windows.Forms.Timer usageTimer;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
                components.Dispose();

            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            components = new System.ComponentModel.Container();
            cardPanel = new Panel();
            titleLabel = new Label();
            subtitleLabel = new Label();
            interfacesComboBox = new ComboBox();
            usageLabel = new Label();
            usageChartPanel = new Panel();
            continueButton = new Button();
            usageTimer = new System.Windows.Forms.Timer(components);
            cardPanel.SuspendLayout();
            SuspendLayout();
            // 
            // cardPanel
            // 
            cardPanel.BackColor = Color.FromArgb(255, 255, 255);
            cardPanel.Controls.Add(titleLabel);
            cardPanel.Controls.Add(subtitleLabel);
            cardPanel.Controls.Add(interfacesComboBox);
            cardPanel.Controls.Add(usageLabel);
            cardPanel.Controls.Add(usageChartPanel);
            cardPanel.Controls.Add(continueButton);
            cardPanel.Location = new Point(48, 38);
            cardPanel.Name = "cardPanel";
            cardPanel.Size = new Size(664, 344);
            cardPanel.TabIndex = 0;
            // 
            // titleLabel
            // 
            titleLabel.AutoSize = true;
            titleLabel.Font = new Font("Segoe UI Variable Display", 18F, FontStyle.Bold);
            titleLabel.ForeColor = Color.FromArgb(31, 31, 31);
            titleLabel.Location = new Point(34, 28);
            titleLabel.Name = "titleLabel";
            titleLabel.Size = new Size(207, 32);
            titleLabel.TabIndex = 0;
            titleLabel.Text = SnifferLabels.SelectInterfaceFormCardTitle;
            // 
            // subtitleLabel
            // 
            subtitleLabel.AutoSize = true;
            subtitleLabel.Font = new Font("Segoe UI", 9.75F);
            subtitleLabel.ForeColor = Color.FromArgb(96, 94, 92);
            subtitleLabel.Location = new Point(36, 66);
            subtitleLabel.Name = "subtitleLabel";
            subtitleLabel.Size = new Size(346, 17);
            subtitleLabel.TabIndex = 1;
            subtitleLabel.Text = SnifferLabels.SelectInterfaceFormCardSubtitle;
            // 
            // interfacesComboBox
            // 
            interfacesComboBox.BackColor = Color.White;
            interfacesComboBox.DropDownStyle = ComboBoxStyle.DropDownList;
            interfacesComboBox.FlatStyle = FlatStyle.System;
            interfacesComboBox.Font = new Font("Segoe UI", 9.5F);
            interfacesComboBox.Location = new Point(38, 106);
            interfacesComboBox.Name = "interfacesComboBox";
            interfacesComboBox.Size = new Size(588, 25);
            interfacesComboBox.TabIndex = 1;
            interfacesComboBox.SelectedIndexChanged += interfacesComboBox_SelectedIndexChanged;
            // 
            // usageLabel
            // 
            usageLabel.AutoSize = true;
            usageLabel.Font = new Font("Segoe UI", 9.25F, FontStyle.Bold);
            usageLabel.ForeColor = Color.FromArgb(50, 49, 48);
            usageLabel.Location = new Point(38, 154);
            usageLabel.Name = "usageLabel";
            usageLabel.Size = new Size(203, 17);
            usageLabel.TabIndex = 2;
            usageLabel.Text = string.Format(SnifferLabels.UsageSummary, SnifferLabels.Received, FormatBytes(0), SnifferLabels.Sent, FormatBytes(0));
            // 
            // usageChartPanel
            // 
            usageChartPanel.BackColor = Color.FromArgb(250, 250, 250);
            usageChartPanel.Location = new Point(38, 182);
            usageChartPanel.Name = "usageChartPanel";
            usageChartPanel.Size = new Size(588, 78);
            usageChartPanel.TabIndex = 2;
            usageChartPanel.Paint += usageChartPanel_Paint;
            // 
            // continueButton
            // 
            continueButton.BackColor = Color.FromArgb(37, 99, 235);
            continueButton.FlatAppearance.BorderSize = 0;
            continueButton.FlatAppearance.MouseDownBackColor = Color.FromArgb(0, 90, 158);
            continueButton.FlatAppearance.MouseOverBackColor = Color.FromArgb(16, 110, 190);
            continueButton.FlatStyle = FlatStyle.Flat;
            continueButton.Font = new Font("Segoe UI", 9.5F, FontStyle.Bold);
            continueButton.ForeColor = Color.White;
            continueButton.Location = new Point(38, 282);
            continueButton.Name = "continueButton";
            continueButton.Size = new Size(132, 38);
            continueButton.TabIndex = 3;
            continueButton.Text = SnifferLabels.ContinueButton;
            continueButton.UseVisualStyleBackColor = false;
            continueButton.Click += continueButton_Click;
            // 
            // usageTimer
            // 
            usageTimer.Tick += usageTimer_Tick;
            // 
            // SelectInterfaceForm
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            BackColor = Color.FromArgb(243, 243, 243);
            ClientSize = new Size(760, 420);
            Controls.Add(cardPanel);
            Font = new Font("Segoe UI", 9F);
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Name = "SelectInterfaceForm";
            StartPosition = FormStartPosition.CenterScreen;
            Text = SnifferLabels.PacketSnifferTitle;
            cardPanel.ResumeLayout(false);
            cardPanel.PerformLayout();
            ResumeLayout(false);
        }
    }
}