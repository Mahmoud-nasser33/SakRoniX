import wx
import subprocess
import threading
import os
import sys
import ipaddress
import re
from datetime import datetime
import shutil

class ToolSelectorDialog(wx.Dialog):
    def __init__(self, parent, tools, current_tool):
        super().__init__(parent, title="Select Tool", size=(300, 350))
        self.selected_tool = None
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)

        title_label = wx.StaticText(panel, label="Choose Security Tool")
        title_label.SetFont(wx.Font(14, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD))
        vbox.Add(title_label, 0, wx.ALL | wx.CENTER, 10)

        self.listbox = wx.ListBox(panel, choices=tools, style=wx.LB_SINGLE)
        if current_tool in tools:
            self.listbox.SetSelection(tools.index(current_tool))
        vbox.Add(self.listbox, 1, wx.EXPAND | wx.ALL, 10)

        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        btn_ok = wx.Button(panel, wx.ID_OK, label="Select")
        btn_cancel = wx.Button(panel, wx.ID_CANCEL, label="Cancel")
        btn_ok.SetDefault()
        btn_sizer.Add(btn_ok, 0, wx.ALL, 5)
        btn_sizer.Add(btn_cancel, 0, wx.ALL, 5)
        vbox.Add(btn_sizer, 0, wx.ALL | wx.CENTER, 10)

        panel.SetSizer(vbox)
        self.Bind(wx.EVT_BUTTON, self.on_ok, btn_ok)
        self.Bind(wx.EVT_LISTBOX_DCLICK, self.on_double_click)

    def on_double_click(self, event):
        self.on_ok(event)

    def on_ok(self, event):
        selection = self.listbox.GetSelection()
        if selection != wx.NOT_FOUND:
            self.selected_tool = self.listbox.GetString(selection)
            self.EndModal(wx.ID_OK)
        else:
            wx.MessageBox("Please select a tool.", "Error", wx.OK | wx.ICON_ERROR)

class SecurityToolGUI(wx.Frame):
    def __init__(self):
        super().__init__(None, title="SakRoniX", size=(1400, 1000))
        self.SetMinSize((1200, 800))
        
        # Initialize attributes
        self.running_process = None
        self.stop_flag = False
        self.current_command = None
        self.command_thread = None
        self.help_visible = True
        self.dark_mode = True
        
        # Colors
        self.neon_blue = "#00bfff"
        self.dark_bg = "#1e1e2e"
        self.light_text = "#ffffff"
        self.accent_color = "#ff6b6b"
        
        # Tool categories
        self.tool_categories = {
            "Network Scanning & Discovery": [
                "nmap", "masscan", "arp-scan", "fping", 
                "nbtscan", "snmp-check", "onesixtyone", "ike-scan"
            ],
            "Traffic Analysis & Packet Sniffing": [
                "tcpdump", "wireshark"
            ],
            "Packet Crafting & Injection": [
                "hping3"
            ],
            "Man-in-the-Middle & Sniffing": [
                "ettercap"
            ],
            "DNS/Whois": [
                "netcat", "dnsenum", "traceroute", "whois"
            ],
            "SSL/TLS": [
                "sslscan"
            ],
            "Password Cracking": [
                "ncrack"
            ],
            "Anonymity & Firewall Evasion": [
                "proxychains"
            ]
        }
        
        self.current_category = "Network Scanning & Discovery"
        self.current_tool = self.tool_categories[self.current_category][0]
        
        # Initialize UI
        self.init_ui()
        
    def init_ui(self):
        self.main_panel = wx.Panel(self)
        self.main_panel.SetBackgroundColour(self.dark_bg)
        self.main_sizer = wx.BoxSizer(wx.VERTICAL)

        self.create_header()
        self.create_main_interface()
        
        self.main_panel.SetSizer(self.main_sizer)
        self.Layout()
        
    def create_header(self):
        header_panel = wx.Panel(self.main_panel)
        header_panel.SetBackgroundColour("#1a1a1a")
        header_sizer = wx.BoxSizer(wx.HORIZONTAL)

        # Try to load logo image
        img_path = "falcon.png"
        if os.path.exists(img_path):
            try:
                img = wx.Image(img_path, wx.BITMAP_TYPE_ANY).Scale(60, 60)
                bmp = wx.StaticBitmap(header_panel, bitmap=wx.Bitmap(img))
                header_sizer.Add(bmp, 0, wx.ALL | wx.CENTER, 10)
            except Exception as e:
                print(f"Error loading image: {e}")
       
        title_sizer = wx.BoxSizer(wx.VERTICAL)
        title_label = wx.StaticText(header_panel, label="SakRoniX")
        title_label.SetForegroundColour("#ffaa00")
        title_label.SetFont(wx.Font(28, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_ITALIC, wx.FONTWEIGHT_BOLD, underline=True))
        title_sizer.Add(title_label, 0, wx.ALL, 2)

        creator_label = wx.StaticText(header_panel, label="Made By Mahmoud Sakr")
        creator_label.SetForegroundColour("#ffaa00")
        creator_label.SetFont(wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_SLANT, wx.FONTWEIGHT_BOLD))
        title_sizer.Add(creator_label, 0, wx.LEFT, 5)

        header_sizer.Add(title_sizer, 1, wx.ALL | wx.CENTER, 10)
        
        # Add theme toggle button
        self.theme_btn = wx.Button(header_panel, label="☀️ Light Mode")
        self.theme_btn.SetBackgroundColour("#444444")
        self.theme_btn.SetForegroundColour("#ffffff")
        self.theme_btn.Bind(wx.EVT_BUTTON, self.toggle_theme)
        header_sizer.Add(self.theme_btn, 0, wx.ALL | wx.CENTER, 10)
        
        header_panel.SetSizer(header_sizer)
        self.main_sizer.Add(header_panel, 0, wx.EXPAND | wx.ALL, 5)
        
    def toggle_theme(self, event):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            self.set_dark_theme()
            self.theme_btn.SetLabel("☀️ Light Mode")
        else:
            self.set_light_theme()
            self.theme_btn.SetLabel("🌙 Dark Mode")
        self.Refresh()
        
    def set_dark_theme(self):
        self.dark_bg = "#1e1e2e"
        self.light_text = "#ffffff"
        self.main_panel.SetBackgroundColour(self.dark_bg)
        self.output.SetBackgroundColour("#0c0c0c")
        self.output.SetForegroundColour("#00ff00")
        self.help_text.SetBackgroundColour("#2a2a2a")
        self.help_text.SetForegroundColour("#cccccc")
        
    def set_light_theme(self):
        self.dark_bg = "#f5f5f5"
        self.light_text = "#333333"
        self.main_panel.SetBackgroundColour(self.dark_bg)
        self.output.SetBackgroundColour("#ffffff")
        self.output.SetForegroundColour("#000000")
        self.help_text.SetBackgroundColour("#ffffff")
        self.help_text.SetForegroundColour("#333333")
        
    def create_main_interface(self):
        self.splitter = wx.SplitterWindow(self.main_panel, style=wx.SP_3D | wx.SP_LIVE_UPDATE)
        self.splitter.SetMinimumPaneSize(300)

        # Left panel with controls
        self.left_panel = wx.Panel(self.splitter)
        self.left_panel.SetBackgroundColour(self.dark_bg)
        self.left_sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.create_ping_section()
        self.create_tools_section()
        
        self.left_panel.SetSizer(self.left_sizer)
        
        # Right panel with output
        self.right_panel = wx.Panel(self.splitter)
        self.right_panel.SetBackgroundColour(self.dark_bg)
        self.right_sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.create_help_section()
        self.create_terminal_section()
        
        self.right_panel.SetSizer(self.right_sizer)
        
        self.splitter.SplitVertically(self.left_panel, self.right_panel)
        self.splitter.SetSashPosition(500)
        self.main_sizer.Add(self.splitter, 1, wx.EXPAND | wx.ALL, 5)
        
        # Load initial help content
        self.load_tool_arguments(self.current_tool)
        
    def create_ping_section(self):
        self.ping_args = {
            "-c": ("Count", "Number of packets to send"),
            "-i": ("Interval", "Interval between packets (seconds)"),
            "-t": ("TTL", "Time to live value"),
            "-s": ("Size", "Packet size in bytes"),
            "-W": ("Timeout", "Timeout in seconds")
        }
        
        self.ping_pane = wx.CollapsiblePane(self.left_panel, label="Ping", style=wx.CP_DEFAULT_STYLE | wx.CP_NO_TLW_RESIZE)
        self.Bind(wx.EVT_COLLAPSIBLEPANE_CHANGED, self.on_ping_pane_toggle, self.ping_pane)
        pane = self.ping_pane.GetPane()
        pane.SetBackgroundColour(self.dark_bg)
        self.ping_sizer_inner = wx.BoxSizer(wx.VERTICAL)

        # Target input
        target_sizer = wx.BoxSizer(wx.HORIZONTAL)
        target_label = wx.StaticText(pane, label="Target:")
        target_label.SetForegroundColour(self.light_text)
        target_sizer.Add(target_label, 0, wx.ALL | wx.CENTER, 5)
        
        self.ping_target_input = wx.TextCtrl(pane, style=wx.TE_PROCESS_ENTER)
        self.ping_target_input.SetBackgroundColour("#3a3a3a")
        self.ping_target_input.SetForegroundColour(self.light_text)
        self.ping_target_input.Bind(wx.EVT_TEXT_ENTER, self.on_ping_run)
        target_sizer.Add(self.ping_target_input, 1, wx.ALL | wx.EXPAND, 5)
        self.ping_sizer_inner.Add(target_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Ping arguments
        self.ping_arg_widgets = {}
        for arg, (label, desc) in self.ping_args.items():
            hbox = wx.BoxSizer(wx.HORIZONTAL)
            cb = wx.CheckBox(pane, label=f"{arg} ({label})")
            cb.SetForegroundColour(self.light_text)
            cb.Bind(wx.EVT_CHECKBOX, lambda e, desc=desc: self.update_help_text(desc))
            txt = wx.TextCtrl(pane, size=(80, -1))
            txt.SetBackgroundColour("#3a3a3a")
            txt.SetForegroundColour(self.light_text)
            txt.SetHint(desc)
            hbox.Add(cb, 0, wx.ALL | wx.CENTER, 5)
            hbox.Add(txt, 1, wx.ALL | wx.EXPAND, 5)
            self.ping_sizer_inner.Add(hbox, 0, wx.EXPAND)
            self.ping_arg_widgets[arg] = (cb, txt)

        # Buttons
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.ping_run_btn = wx.Button(pane, label="Run Ping")
        self.ping_run_btn.SetBackgroundColour("#ffaa00")
        self.ping_run_btn.SetForegroundColour("#000000")
        self.ping_run_btn.Bind(wx.EVT_BUTTON, self.on_ping_run)
        btn_sizer.Add(self.ping_run_btn, 0, wx.ALL, 5)

        self.ping_stop_btn = wx.Button(pane, label="Stop")
        self.ping_stop_btn.SetBackgroundColour("#ffaa00")
        self.ping_stop_btn.SetForegroundColour("#000000")
        self.ping_stop_btn.Bind(wx.EVT_BUTTON, self.on_stop_command)
        self.ping_stop_btn.Disable()
        btn_sizer.Add(self.ping_stop_btn, 0, wx.ALL, 5)

        self.ping_sizer_inner.Add(btn_sizer, 0, wx.ALL | wx.CENTER, 10)
        pane.SetSizer(self.ping_sizer_inner)
        self.left_sizer.Add(self.ping_pane, 0, wx.EXPAND | wx.ALL, 10)
        
    def create_tools_section(self):
        tools_box = wx.StaticBox(self.left_panel, label="Security Tools")
        tools_box.SetForegroundColour(self.light_text)
        self.tools_sizer = wx.StaticBoxSizer(tools_box, wx.VERTICAL)

        # Category selection
        category_sizer = wx.BoxSizer(wx.HORIZONTAL)
        category_label = wx.StaticText(self.left_panel, label="Category:")
        category_label.SetForegroundColour(self.light_text)
        category_sizer.Add(category_label, 0, wx.ALL | wx.CENTER, 5)

        self.category_choice = wx.Choice(self.left_panel, choices=list(self.tool_categories.keys()))
        self.category_choice.SetSelection(0)
        self.category_choice.Bind(wx.EVT_CHOICE, self.on_category_change)
        category_sizer.Add(self.category_choice, 1, wx.ALL | wx.EXPAND, 5)
        self.tools_sizer.Add(category_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Tool selection
        tool_select_sizer = wx.BoxSizer(wx.HORIZONTAL)
        tool_label = wx.StaticText(self.left_panel, label="Tool:")
        tool_label.SetForegroundColour(self.light_text)
        tool_select_sizer.Add(tool_label, 0, wx.ALL | wx.CENTER, 5)

        self.tool_choice = wx.Choice(self.left_panel, choices=self.tool_categories[self.current_category])
        self.tool_choice.SetSelection(0)
        self.tool_choice.Bind(wx.EVT_CHOICE, self.on_tool_change)
        tool_select_sizer.Add(self.tool_choice, 1, wx.ALL | wx.EXPAND, 5)
        self.tools_sizer.Add(tool_select_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Selected tool display
        selected_sizer = wx.BoxSizer(wx.HORIZONTAL)
        selected_label = wx.StaticText(self.left_panel, label="Selected Tool:")
        selected_label.SetForegroundColour(self.light_text)
        selected_sizer.Add(selected_label, 0, wx.ALL | wx.CENTER, 5)

        self.selected_tool_static = wx.StaticText(self.left_panel, label=self.current_tool)
        self.selected_tool_static.SetForegroundColour("#ffaa00")
        self.selected_tool_static.SetFont(wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD))
        selected_sizer.Add(self.selected_tool_static, 1, wx.ALL | wx.CENTER, 5)
        self.tools_sizer.Add(selected_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Target input
        target_sizer = wx.BoxSizer(wx.HORIZONTAL)
        target_label = wx.StaticText(self.left_panel, label="Target:")
        target_label.SetForegroundColour(self.light_text)
        target_sizer.Add(target_label, 0, wx.ALL | wx.CENTER, 5)

        self.tool_target_input = wx.TextCtrl(self.left_panel, style=wx.TE_PROCESS_ENTER)
        self.tool_target_input.SetBackgroundColour("#3a3a3a")
        self.tool_target_input.SetForegroundColour(self.light_text)
        self.tool_target_input.Bind(wx.EVT_TEXT_ENTER, self.on_tool_run)
        target_sizer.Add(self.tool_target_input, 1, wx.ALL | wx.EXPAND, 5)
        self.tools_sizer.Add(target_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Arguments panel
        self.args_panel = wx.ScrolledWindow(self.left_panel, style=wx.VSCROLL)
        self.args_panel.SetScrollRate(0, 20)
        self.args_panel.SetBackgroundColour("#2b2b2b")
        self.args_sizer = wx.BoxSizer(wx.VERTICAL)
        self.args_panel.SetSizer(self.args_sizer)
        self.tools_sizer.Add(self.args_panel, 1, wx.EXPAND | wx.ALL, 5)

        # Run/Stop buttons
        btn_sizer = wx.BoxSizer(wx.HORIZONTAL)
        self.tool_run_btn = wx.Button(self.left_panel, label="Run Tool")
        self.tool_run_btn.SetBackgroundColour("#ffaa00")
        self.tool_run_btn.SetForegroundColour("#000000")
        self.tool_run_btn.Bind(wx.EVT_BUTTON, self.on_tool_run)
        btn_sizer.Add(self.tool_run_btn, 0, wx.ALL, 5)

        self.tool_stop_btn = wx.Button(self.left_panel, label="Stop Tool")
        self.tool_stop_btn.SetBackgroundColour("#ffaa00")
        self.tool_stop_btn.SetForegroundColour("#000000")
        self.tool_stop_btn.Bind(wx.EVT_BUTTON, self.on_stop_command)
        self.tool_stop_btn.Disable()
        btn_sizer.Add(self.tool_stop_btn, 0, wx.ALL, 5)

        self.tools_sizer.Add(btn_sizer, 0, wx.ALL | wx.CENTER, 10)
        self.left_sizer.Add(self.tools_sizer, 1, wx.EXPAND | wx.ALL, 10)
        
    def create_help_section(self):
        help_box = wx.StaticBox(self.right_panel, label="Tool Documentation")
        help_box.SetForegroundColour("#ffaa00")
        self.help_sizer = wx.StaticBoxSizer(help_box, wx.VERTICAL)

        self.toggle_help_btn = wx.Button(self.right_panel, label="Hide Help")
        self.toggle_help_btn.SetBackgroundColour("#ffaa00")
        self.toggle_help_btn.SetForegroundColour("#000000")
        self.toggle_help_btn.Bind(wx.EVT_BUTTON, self.on_toggle_help)
        self.help_sizer.Add(self.toggle_help_btn, 0, wx.ALL | wx.CENTER, 5)

        self.help_text = wx.TextCtrl(self.right_panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_WORDWRAP | wx.TE_RICH)
        self.help_text.SetBackgroundColour("#2a2a2a")
        self.help_text.SetForegroundColour("#cccccc")
        self.help_text.SetFont(wx.Font(10, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL))
        
        # Set default help content
        self.default_help_content = """Welcome to SakRoniX Security Toolkit

This professional-grade tool provides a comprehensive interface for network security operations including:

• Network scanning and host discovery
• Vulnerability assessment
• Traffic analysis and packet inspection
• Security auditing and penetration testing

Key Features:
- Unified interface for multiple security tools
- Real-time command output
- Detailed documentation for each tool
- Customizable parameters
- Output logging and saving

To get started:
1. Select a tool category from the dropdown
2. Choose a specific security tool
3. Enter target information
4. Configure tool parameters
5. Execute and analyze results

Note: Always ensure you have proper authorization before performing security scans.
"""
        self.help_text.SetValue(self.default_help_content)
        self.help_sizer.Add(self.help_text, 1, wx.EXPAND | wx.ALL, 5)

        self.right_sizer.Add(self.help_sizer, 0, wx.EXPAND | wx.ALL, 5)
        
    def create_terminal_section(self):
        terminal_box = wx.StaticBox(self.right_panel, label="Command Output")
        terminal_box.SetForegroundColour("#ffaa00")
        self.terminal_sizer = wx.StaticBoxSizer(terminal_box, wx.VERTICAL)

        self.output = wx.TextCtrl(self.right_panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.HSCROLL | wx.TE_RICH2)
        self.output.SetBackgroundColour("#0c0c0c")
        self.output.SetForegroundColour("#00ff00")
        self.output.SetFont(wx.Font(10, wx.FONTFAMILY_TELETYPE, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL))
        self.terminal_sizer.Add(self.output, 1, wx.EXPAND | wx.ALL, 5)

        terminal_controls = wx.BoxSizer(wx.HORIZONTAL)
        self.clear_btn = wx.Button(self.right_panel, label="Clear Output")
        self.clear_btn.SetBackgroundColour("#ffaa00")
        self.clear_btn.SetForegroundColour("#000000")
        self.clear_btn.Bind(wx.EVT_BUTTON, lambda e: self.output.Clear())
        terminal_controls.Add(self.clear_btn, 0, wx.ALL, 5)

        self.save_btn = wx.Button(self.right_panel, label="Save Output")
        self.save_btn.SetBackgroundColour("#ffaa00")
        self.save_btn.SetForegroundColour("#000000")
        self.save_btn.Bind(wx.EVT_BUTTON, self.on_save_output)
        terminal_controls.Add(self.save_btn, 0, wx.ALL, 5)

        self.terminal_sizer.Add(terminal_controls, 0, wx.ALL | wx.CENTER, 5)
        self.right_sizer.Add(self.terminal_sizer, 1, wx.EXPAND | wx.ALL, 5)
    
    def validate_ip_address(self, ip_str):
        """Validate an IP address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    def validate_hostname(self, hostname):
        """Simple hostname validation."""
        if not hostname:
            return False
        if len(hostname) > 255:
            return False
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))
    
    def update_help_text(self, content):
        """Update the help text with formatted content"""
        self.help_text.SetValue(content)
    
    def on_ping_run(self, event):
        """Handle ping command execution"""
        target = self.ping_target_input.GetValue().strip()
        if not target:
            wx.MessageBox("Please enter a target to ping", "Error", wx.OK | wx.ICON_ERROR)
            return

        if not (self.validate_ip_address(target) or self.validate_hostname(target)):
            wx.MessageBox("Invalid IP address or hostname", "Error", wx.OK | wx.ICON_ERROR)
            return

        cmd = ["ping"]
        # Only add default count if no -c is checked (otherwise infinite)
        if sys.platform.startswith("win"):
            if not self.ping_arg_widgets["-c"][0].GetValue():
                cmd.extend(["-t"])  # Windows infinite (ping continues until stopped)
        else:
            if not self.ping_arg_widgets["-c"][0].GetValue():
                pass  # Unix ping by default is infinite

        # Add selected arguments
        for arg, (cb, txt) in self.ping_arg_widgets.items():
            if cb.GetValue():
                cmd.append(arg)
                if txt and txt.GetValue():
                    cmd.append(txt.GetValue())

        cmd.append(target)
        
        # Disable run button and enable stop button
        if self.running_process:
            self.on_stop_command(None)
        self.ping_stop_btn.Enable()
        
        # Execute the command
        self.execute_command_with_output(cmd, "PING")
    
    def on_tool_run(self, event):
        target = self.tool_target_input.GetValue().strip()

        is_local_scan = False
        if self.current_tool == "arp-scan":
            if "local_scan" in self.arg_widgets:
                is_local_scan = self.arg_widgets["local_scan"][0].GetValue()

        if not is_local_scan and self.current_tool != "fping" and self.current_tool != "dnsenum":
            if not target:
                wx.MessageBox("Please enter a target", "Error", wx.OK | wx.ICON_ERROR)
                return
            if not (self.validate_ip_address(target) or self.validate_hostname(target)):
                wx.MessageBox("Invalid IP address or hostname", "Error", wx.OK | wx.ICON_ERROR)
                return

        cmd = [self.current_tool]

        # Special case for netcat - put port after target
        if self.current_tool == "netcat":
            port = None
            if "-p" in self.arg_widgets:
                cb, txt = self.arg_widgets["-p"]
                if cb.GetValue() and txt.GetValue():
                    port = txt.GetValue()
            
            # Remove -p from command since we'll handle it specially
            for arg, (cb, txt) in self.arg_widgets.items():
                if arg == "-p":
                    continue
                if cb.GetValue():
                    cmd.append(arg)
                    if txt and txt.GetValue():
                        cmd.append(txt.GetValue())
            
            cmd.append(target)
            if port:
                cmd.append(port)

        # Special case for dnsenum - needs domain as target
        elif self.current_tool == "dnsenum":
            if not target:
                wx.MessageBox("Please enter a domain to enumerate", "Error", wx.OK | wx.ICON_ERROR)
                return
            
            # Add the domain first
            cmd.append(target)
            
            # Then add other arguments
            for arg, (cb, txt) in self.arg_widgets.items():
                if cb.GetValue():
                    cmd.append(arg)
                    if txt and txt.GetValue():
                        cmd.append(txt.GetValue())

        # Special case for fping
        elif self.current_tool == "fping":
            is_g_selected = False
            is_a_selected = False
            start_ip = ""
            end_ip = ""

            if "-g" in self.arg_widgets:
                is_g_selected = self.arg_widgets["-g"][0].GetValue()
                if is_g_selected:
                    start_ip = self.fping_start_ip_input.GetValue().strip()
                    end_ip = self.fping_end_ip_input.GetValue().strip()

                    if not (self.validate_ip_address(start_ip) and self.validate_ip_address(end_ip)):
                        wx.MessageBox("Please enter valid start and end IP addresses for fping -g option", "Error", wx.OK | wx.ICON_ERROR)
                        return

            if "-a" in self.arg_widgets:
                is_a_selected = self.arg_widgets["-a"][0].GetValue()

            if is_a_selected:
                cmd.append("-a")
            if is_g_selected:
                cmd.append("-g")
                cmd.append(start_ip)
                cmd.append(end_ip)
            else:
                if not target:
                    wx.MessageBox("Please enter a target", "Error", wx.OK | wx.ICON_ERROR)
                    return
                cmd.append(target)

            # Add other args
            for arg, (cb, txt) in self.arg_widgets.items():
                if arg in ["-a", "-g"]:
                    continue
                if cb.GetValue():
                    cmd.append(arg)
                    if txt and txt.GetValue():
                        cmd.append(txt.GetValue())

        # Normal case for other tools
        else:
            if self.current_tool == "arp-scan" and is_local_scan:
                cmd.append("-l")

            for arg, (cb, txt) in self.arg_widgets.items():
                if arg == "local_scan":
                    continue
                if cb.GetValue():
                    cmd.append(arg)
                    if txt and txt.GetValue():
                        cmd.append(txt.GetValue())

            if not is_local_scan:
                cmd.append(target)

        # Finally run the command
        self.tool_run_btn.Disable()
        self.tool_stop_btn.Enable()
        self.execute_command_with_output(cmd, self.current_tool.upper())
    
    def on_ping_pane_toggle(self, event):
        self.left_panel.Layout()
    
    def on_category_change(self, event):
        self.current_category = self.category_choice.GetStringSelection()
        tools = self.tool_categories[self.current_category]
        self.tool_choice.SetItems(tools)
        self.tool_choice.SetSelection(0)
        self.current_tool = tools[0]
        self.selected_tool_static.SetLabel(self.current_tool)
        self.load_tool_arguments(self.current_tool)
    
    def on_tool_change(self, event):
        self.current_tool = self.tool_choice.GetStringSelection()
        self.selected_tool_static.SetLabel(self.current_tool)
        self.load_tool_arguments(self.current_tool)
    
    def load_tool_arguments(self, tool):
        self.args_sizer.Clear(True)
        self.arg_widgets = {}

        # Detailed documentation for each tool
        tool_docs = {
            "nmap": """Network Mapper (Nmap) - Powerful Port Scanner and Network Discovery Tool

Nmap is the most popular network scanning tool used for:
- Discovering hosts and services on a computer network
- Port scanning (TCP, UDP, etc.)
- OS detection and version detection
- Scriptable interaction with the target

Common Uses:
1. Basic scan: nmap -sS 192.168.1.1
2. Version detection: nmap -sV 192.168.1.1
3. Full aggressive scan: nmap -A -T4 192.168.1.1
4. Port range scan: nmap -p 1-1000 192.168.1.1

Important Notes:
- -sS (SYN scan) is stealthy but requires root privileges
- -A enables OS detection, version detection, script scanning, and traceroute
- -T4 speeds up the scan (0-5 scale)
- Always get proper authorization before scanning networks

Common Arguments:  

1. -sS (TCP SYN Scan)
   • Stealthy port scanning method
   • Sends SYN packets without completing handshake
   • Requires root privileges
   • Example: nmap -sS 192.168.1.1

2. -sT (TCP Connect Scan)
   • Completes full TCP connection
   • No root needed but slower/more detectable
   • Example: nmap -sT 192.168.1.1

3. -sU (UDP Scan)
   • Scans UDP ports (often overlooked)
   • Much slower than TCP scans
   • Example: nmap -sU 192.168.1.1

=== Discovery Options ===
4. -sn (Ping Scan)
   • Discovers live hosts without port scanning
   • Example: nmap -sn 192.168.1.0/24

5. -Pn (Skip Host Discovery)
   • Treats all hosts as online
   • Bypasses firewalls blocking ping
   • Example: nmap -Pn 192.168.1.1

=== Service Detection ===
6. -sV (Service Version)
   • Probes open ports to detect services
   • Example: nmap -sV 192.168.1.1

7. -O (OS Detection)
   • Attempts to identify target OS
   • Requires root
   • Example: nmap -O 192.168.1.1

=== Advanced Techniques ===
8. -A (Aggressive Scan)
   • Enables OS detection, version detection, script scanning
   • Example: nmap -A 192.168.1.1

9. -T<0-5> (Timing Template)
   • Controls scan speed (higher = faster)
   • -T3 (default), -T4 (aggressive)
   • Example: nmap -T4 192.168.1.1

=== Port Specification ===
10. -p (Port Selection)
    • Single port: -p 80
    • Multiple ports: -p 80,443
    • Range: -p 1-1000
    • All ports: -p-
    • Example: nmap -p 22,80,443 192.168.1.1
""",
            "masscan": """Masscan - Ultra-Fast Internet-Scale Port Scanner

Masscan is an Internet-scale port scanner that can:
- Scan the entire Internet in under 6 minutes
- Handle millions of packets per second
- Output results in various formats

Common Uses:
1. Fast port scan: masscan -p80,443 192.168.1.1
2. Scan entire subnet: masscan 192.168.1.0/24 -p0-65535
3. Banner grabbing: masscan --banners -p80 192.168.1.1

Important Notes:
- Extremely fast - can overwhelm networks if not rate-limited
- Uses its own TCP/IP stack - may require special permissions
- --rate sets packets per second (10000 is default)
- --source-ip allows spoofing source IP (use carefully)

Common Arguments:

1. Scan single IP:
   masscan 192.168.1.1 -p80,443

2. Scan IP range:
   masscan 192.168.1.0/24 -p1-1000

3. Scan with banner grabbing:
   masscan 192.168.1.1 --banners -p80,443

Common Arguments:

--rate : Packets per second (default=10000)
   • Higher values = faster scan
   • Example: --rate 100000

--banners : Grab service banners
   • Attempts to get service identification
   • Example: masscan 192.168.1.1 --banners -p80

-e : Specify network interface
   • Example: -e eth0

--source-ip : Spoof source IP
   • Use with caution
   • Example: --source-ip 192.168.1.100

--open : Only show open ports
   • Filters out non-responsive ports
   • Example: --open



""",
            "arp-scan": """ARP-Scan - Discover Hosts Using ARP Packets

ARP-Scan is a tool for:
- Discovering live hosts on a local network
- Fingerprinting operating systems via ARP
- Gathering MAC addresses and vendors

Common Uses:
1. Local network scan: arp-scan -l
2. Interface selection: arp-scan -I eth0 192.168.1.0/24
3. Verbose output: arp-scan -v -l

Important Notes:
- Only works on local network segments
- Doesn't require root privileges on most systems
- -l flag scans your local network automatically
- Can detect some firewall configurations

Common Arguments:

-l : Local network scan (automatic detection)
   • Automatically determines local network
   • Example: arp-scan -l

-I : Specify network interface
   • Required for targeted scans
   • Example: -I eth0

-g : Generate ARP packets without scanning
   • Useful for testing
   • Example: -g

-v : Verbose output
   • Shows additional details
   • Example: -v

--retry : Number of retries (default=5)
   • Increase for unreliable networks
   • Example: --retry=10

--timeout : Timeout in milliseconds (default=1000)
   • Adjust for slow networks
   • Example: --timeout=500

=== Advanced Options ===
--localnet : Scan local network from interface IP
--destaddr : Use destination MAC address
--arpsha : Use source MAC address
--arptha : Use target MAC address
--backoff : Backoff time between packets

""",
            "fping": """FPing - Fast Parallel Ping Tool

FPing is a high-performance ping tool that:
- Pings multiple hosts in parallel
- Shows statistics for alive/unreachable hosts
- Supports IP ranges and input files

Common Uses:
1. Basic ping: fping 192.168.1.1
2. IP range scan: fping -g 192.168.1.1 192.168.1.254
3. Show only alive hosts: fping -a -g 192.168.1.1 192.168.1.254

Important Notes:
- Much faster than traditional ping for multiple hosts
- -g option allows scanning IP ranges
- -a shows only alive hosts
- -u shows only unreachable hosts

Common Arguments:

-g : Generate IP range to ping
   • Example: -g 192.168.1.1 192.168.1.10
   • Alternative CIDR: -g 192.168.1.0/24

-a : Show only alive hosts
   • Filters output
   • Example: fping -a -g 192.168.1.1 192.168.1.10

-u : Show only unreachable hosts
   • Inverse of -a
   • Example: fping -u -g 192.168.1.1 192.168.1.10

-c : Count of pings per host
   • Example: -c 5 (sends 5 pings)
   • Default: infinite (until stopped)

-q : Quiet mode (summary only)
   • Example: fping -q -g 192.168.1.1 192.168.1.10
""",
            "nbtscan": """NBTScan - NetBIOS Name Service Scanner

NBTScan is a tool for:
- Scanning IP networks for NetBIOS name information
- Discovering Windows hosts and shares
- Gathering NetBIOS name tables

Common Uses:
1. Basic scan: nbtscan 192.168.1.0/24
2. Verbose output: nbtscan -v 192.168.1.1
3. Fast scan: nbtscan -q -r 192.168.1.1-254

Important Notes:
- Primarily useful for Windows network discovery
- Can reveal shared resources and workgroup info
- -r option uses port 137 (NetBIOS name service)
- -v provides verbose output

Common Arguments:

-r : Use port 137 (default)
   • Standard NetBIOS port
   • Example: -r

-v : Verbose output
   • Shows additional details
   • Example: -v

-h : Human-readable format
   • Easier to read output
   • Example: -h

=== Example Commands ===
1. Basic scan:
   nbtscan 192.168.1.0/24

2. Verbose scan:
   nbtscan -v 192.168.1.1-100
""",
            "snmp-check": """SNMP-Check - SNMP Enumeration Tool

SNMP-Check gathers information from SNMP-enabled devices:
- Network device enumeration
- System information gathering
- Interface and routing table discovery

Common Uses:
1. Basic scan: snmp-check 192.168.1.1
2. Community string brute force: snmp-check -c public 192.168.1.1
3. Write test: snmp-check -w 192.168.1.1

Important Notes:
- Requires SNMP community strings (try 'public' or 'private')
- -v specifies SNMP version (1, 2c, or 3)
- -w tests write access to MIB objects
- Can reveal sensitive system information

Common Arguments: 

-c : Community string (default=public)
   • Example: -c private
   • Multiple: -c comm1,comm2,comm3

-p : SNMP port (default=161)
   • Example: -p 1610

-v : SNMP version (1|2c|3)
   • Example: -v 2c

-w : Write access test
   • Tests if community has write access
   • Example: -w

-t : Timeout in seconds (default=3)
   • Example: -t 5

""",
            "onesixtyone": """Onesixtyone - SNMP Community String Brute Forcer

Onesixtyone brute forces SNMP community strings:
- Fast scanning of multiple hosts
- Dictionary-based community string testing
- Efficient scanning of large networks

Common Uses:
1. Basic scan: onesixtyone 192.168.1.1
2. Dictionary attack: onesixtyone -c community.txt 192.168.1.1
3. Output results: onesixtyone -o results.txt 192.168.1.0/24

Important Notes:
- Used to discover SNMP community strings
- -c specifies community string dictionary file
- -i specifies target IP list file
- -o saves results to output file

Common Arguments:

-c : Community strings file (required)
   • One community per line
   • Example: -c wordlist.txt

-i : Input file with targets
   • Alternative to command-line targets
   • Example: -i targets.txt

-o : Output results to file
   • Saves discovered communities
   • Example: -o results.txt

-w : Wait time between packets (ms)
   • Default=1 (extremely fast)
   • Example: -w 10 (slower)

-d : Debug mode
   • Shows all attempts
   • Example: -d

""",
            "ike-scan": """IKE-Scan - VPN Scanner and Fingerprinting Tool

IKE-Scan discovers and fingerprints VPN servers:
- IKE/IPSec VPN server discovery
- Vendor fingerprinting
- Aggressive mode pre-shared key testing

Common Uses:
1. Basic scan: ike-scan 192.168.1.1
2. Aggressive mode: ike-scan -A 192.168.1.1
3. Vendor ID fingerprinting: ike-scan -M 192.168.1.1

Important Notes:
- Used to identify VPN gateways
- -A enables aggressive mode (PSK testing)
- -M shows vendor ID payloads
- Can detect VPN server vulnerabilities

Common Arguments:

-A : Aggressive mode (PSK testing)
   • Tests pre-shared key hashes
   • Example: -A

-M : Show vendor ID payloads
   • Fingerprints VPN vendor
   • Example: -M

-P : Save PSK hashes to file
   • For offline cracking
   • Example: -P psk.txt

--id : Set identification value
   • Example: --id=myvpn

--dhgroup : Specify DH group
   • Example: --dhgroup=2
""",
            "tcpdump": """TCPDump - Powerful Packet Sniffer

TCPDump is a command-line packet analyzer:
- Network traffic capture and analysis
- Filtering capabilities using BPF syntax
- Output to files for later analysis

Common Uses:
1. Basic capture: tcpdump -i eth0
2. Capture to file: tcpdump -w capture.pcap
3. Filter by host: tcpdump host 192.168.1.1
4. Filter by port: tcpdump port 80

Important Notes:
- Requires root privileges
- -i specifies network interface
- -w writes packets to file
- -r reads packets from file
- Can generate large capture files

Common Arguments:

-i <interface> : Specify network interface
   • -i eth0 (specific interface)
   • -i any (all interfaces)

-w <file> : Write raw packets to pcap file
   • -w traffic.pcap (binary format)

-r <file> : Read from saved capture file
   • -r traffic.pcap

-n : Disable DNS resolution (performance)
-nn : Disable DNS and port service names

-v : Verbosity levels
   • -v (basic)
   • -vv (more detail)
   • -vvv (maximum)

-s <snaplen> : Capture length (bytes)
   • -s 0 (full packets)
   • -s 1500 (standard MTU)

-c <count> : Exit after N packets
   • -c 100 (capture 100 packets)
""",
            "wireshark": """Wireshark - Graphical Network Protocol Analyzer

Wireshark is the world's foremost network protocol analyzer:
- Deep inspection of hundreds of protocols
- Live capture and offline analysis
- Rich display filter language

Common Uses:
1. Live capture: wireshark -i eth0
2. Read capture file: wireshark -r capture.pcap
3. Specific capture filter: wireshark -f "host 192.168.1.1"

Important Notes:
- Graphical interface provides powerful analysis
- -k starts capture immediately
- -Y applies display filter
- Can decode encrypted traffic with proper keys

Common Arguments:

-i <interface> : Specify capture interface
   • -i eth0
   • -i any (all interfaces)

-k : Start capturing immediately
   • wireshark -k -i eth0

-f <filter> : Apply capture filter
   • -f "host 192.168.1.1"
   • -f "tcp port 443"

-w <file> : Save to pcap file
   • -w capture.pcap

""",
            "hping3": """HPing3 - Network Packet Generator/Analyzer

HPing3 is a versatile packet crafting tool:
- Custom TCP/IP packet generation
- Firewall testing
- Advanced traceroute
- Network performance testing

Common Uses:
1. SYN flood test: hping3 -S -p 80 --flood 192.168.1.1
2. Firewall testing: hping3 -S -p 80 192.168.1.1
3. Advanced traceroute: hping3 --traceroute -S 192.168.1.1

Important Notes:
- Can be used for DoS testing (use carefully)
- --flood sends packets as fast as possible
- -S sends SYN packets
- -p specifies target port
- Requires root privileges for raw packets

Common Arguments:

-S : SYN flag (TCP handshake initiation)
-A : ACK flag (firewall testing)
-F : FIN flag (stealth scanning)
-P : PUSH flag
-U : URG flag

-p : Destination port
   • -p 80 (single port)
   • -p 1-100 (port range)

-c : Packet count
   • -c 100 (send 100 packets)

-i : Interval between packets (uX=microsec)
   • -i u1000 (1 packet/ms)
   • -i 1 (1 packet/sec)
""",
            "ettercap": """Ettercap - Comprehensive MITM Framework

Ettercap is a suite for MITM attacks:
- ARP poisoning
- DNS spoofing
- Credential sniffing
- Protocol dissection

Common Uses:
1. ARP poisoning: ettercap -T -M arp /192.168.1.1// /192.168.1.2//
2. DNS spoofing: ettercap -T -M arp -P dns_spoof /192.168.1.1//
3. Credential sniffing: ettercap -T -q -i eth0

Important Notes:
- Powerful tool that can disrupt networks
- -T uses text interface
- -M specifies MITM method
- -P loads plugins
- Use only on networks you own

Common Arguments:

-T : Text interface (CLI mode)
-Q : Super quiet mode (only results)
-i : Network interface
   • -i eth0

-M : MITM attack method
   • arp (ARP poisoning)
   • dhcp (DHCP spoofing)
   • icmp (ICMP redirection)

-P : Load plugin
   • dns_spoof (DNS spoofing)
   • remote_browser (browser hijacking)
""",
            "netcat": """Netcat - Network Swiss Army Knife

Netcat is a versatile networking utility:
- Read/write network connections
- Port scanning
- Banner grabbing
- File transfers

Common Uses:
1. Port scanning: nc -zv 192.168.1.1 20-80
2. Chat server: nc -l -p 1234
3. File transfer: nc -l -p 1234 > file.out (receiver)
   nc 192.168.1.1 1234 < file.in (sender)

Important Notes:
- Often called the "TCP/IP Swiss Army knife"
- -l listens for incoming connections
- -v enables verbose output
- -n skips DNS resolution
- -z scans without sending data

Common Arguments:

-l : Listen mode (server)
-v : Verbose output
-vv : Extra verbose
-n : Skip DNS resolution (faster)
-z : Zero-I/O mode (scanning)
-u : UDP mode (default is TCP)
-p : Source port specification
-w : Timeout in seconds
-e : Execute command (dangerous!)
""",
            "dnsenum": """DNSEnum - DNS Enumeration Tool

DNSEnum gathers DNS information:
- Host enumeration
- Zone transfers
- Reverse lookups
- Brute force subdomains

Common Uses:
1. Basic enumeration: dnsenum example.com
2. Subdomain brute force: dnsenum -f subdomains.txt example.com
3. Output results: dnsenum -o results.xml example.com

Important Notes:
- Useful for reconnaissance before penetration tests
- -f specifies subdomain dictionary file
- -t sets number of threads
- -r enables recursive enumeration
- Can trigger security alerts if used aggressively

Common Arguments:

--threads/-t : Worker threads (default=5)
   • -t 10 (faster scanning)

--recursion/-r : Recursive subdomain brute force
   • -r 2 (2 levels deep)

--dnsserver/-d : Specify DNS server
   • -d 8.8.8.8

--private/-p : Show private IPs in output
--subfile/-f : Subdomain wordlist file
   • -f subdomains.txt

--timeout/-T : WHOIS query timeout (sec)
   • -T 3
""",
            "traceroute": """Traceroute - Network Path Discovery Tool

Traceroute maps network paths:
- Shows route packets take to reach host
- Measures transit delays
- Identifies network bottlenecks

Common Uses:
1. Basic trace: traceroute 192.168.1.1
2. ICMP mode: traceroute -I 192.168.1.1
3. TCP SYN mode: traceroute -T 192.168.1.1

Important Notes:
- -I uses ICMP Echo requests
- -T uses TCP SYN packets
- -n disables DNS resolution
- -w sets wait time per hop
- Firewalls may block traceroute packets

Common Arguments:

-I : ICMP Echo (default on Linux)
-T : TCP SYN (useful for firewalled networks)
-U : UDP (traditional Unix method)
-P : Protocol (ICMP/TCP/UDP)

=== Key Parameters ===
-n : Skip DNS lookups (faster)
-f : First TTL hop number (default=1)
-m : Max TTL hops (default=30)
-w : Wait time per hop (seconds)
-q : Probes per hop (default=3)
-p : Destination port (for TCP/UDP)
""",
            "whois": """Whois - Domain Information Lookup

Whois queries domain registration records:
- Domain ownership details
- Registration dates
- Name server information
- Registrar contacts

Common Uses:
1. Basic query: whois example.com
2. Specific server: whois -h whois.verisign-grs.com example.com
3. Brief output: whois -q example.com

Important Notes:
- Useful for reconnaissance
- -h specifies whois server
- -p specifies port (usually 43)
- -a shows all available data
- Some domains may restrict whois data

Common Arguments:

-h : Specify WHOIS server
   • -h whois.verisign-grs.com

-p : Port number (default=43)
   • -p 4343

-a : Show all available data
   • -a example.com

-I : Force IP-based query
   • -I 8.8.8.8
""",
            "sslscan": """SSLScan - SSL/TLS Configuration Scanner

SSLScan checks SSL/TLS configuration:
- Supported protocols and ciphers
- Certificate information
- Vulnerability checks
- Heartbleed testing

Common Uses:
1. Basic scan: sslscan 192.168.1.1
2. TLS only: sslscan --tls 192.168.1.1
3. Check vulnerabilities: sslscan --bugs 192.168.1.1

Important Notes:
- Checks for weak ciphers and protocols
- --tls restricts to TLS only
- --bugs checks for known vulnerabilities
- --pk checks private key consistency
- Useful for hardening servers

Common Arguments:

--tls1 : Test TLS 1.0 only
--tls11 : Test TLS 1.1 only
--tls12 : Test TLS 1.2 only
--tls13 : Test TLS 1.3 only
--pk : Test private key strength
--bugs : Test for protocol vulnerabilities
--http : Send HTTP request after connecting
""",
            "ncrack": """Ncrack - Network Authentication Cracking Tool

Ncrack is a high-speed authentication cracker:
- Supports multiple protocols
- Parallelized attacks
- Flexible target specification
- Modular architecture

Common Uses:
1. SSH brute force: ncrack -U users.txt -P passwords.txt ssh://192.168.1.1
2. Multiple services: ncrack -U users.txt -P passwords.txt 192.168.1.1:21,22,23
3. Timing control: ncrack -T5 ssh://192.168.1.1

Important Notes:
- Powerful brute force tool - use responsibly
- -U specifies username list
- -P specifies password list
- -T controls timing (0-5)
- --pairwise tries user/password combinations

Common Arguments:

-U : Username/wordlist
   • -U admin
   • -U users.txt

-P : Password/wordlist
   • -P password123
   • -P rockyou.txt

-p : Port specification
   • -p 22:ssh,3389:rdp

--pairwise : Try user/pass combos sequentially
--stop-on-success : Stop after first valid creds
--rate : Attempts per second (default=100)
""",
            "proxychains": """ProxyChains - Proxy Tool for Anonymity

ProxyChains forces applications to use proxies:
- Supports multiple proxy types
- Chain multiple proxies
- DNS request proxying
- Flexible configuration

Common Uses:
1. Run through proxies: proxychains nmap -sT 192.168.1.1
2. Specify config: proxychains -f myconfig.conf curl ifconfig.me
3. Quiet mode: proxychains -q firefox

Important Notes:
- Requires configuration file (/etc/proxychains.conf)
- -f specifies alternative config file
- -q enables quiet mode
- --dynamic uses dynamic chain
- Useful for anonymity and bypassing restrictions

Common Arguments:

-q : Quiet mode (no output)
-f : Alternative config file
   • -f myproxy.conf

--dns : Remote DNS resolution
   • Bypasses local DNS cache
"""
        }

        # Argument definitions for each tool
        tool_args = {
            "nmap": {
                "-sS": "TCP SYN scan (stealth)",
                "-sV": "Version detection",
                "-A": "Aggressive (OS + scripts)",
                "-O": "OS detection",
                "-Pn": "Skip host discovery",
                "-T4": "Aggressive timing",
                "-sC": "Default scripts",
                "-v": "Verbose",
                "-p": "Port list (22,80,443)"
            },
            "masscan": {
                "-p": "Ports (80,443,1-1000)",
                "--rate": "Packets/sec",
                "-e": "Interface (eth0)",
                "--source-ip": "Source IP",
                "--open": "Only open ports",
                "--banners": "Grab banners"
            },
            "arp-scan": {
                "-I": "Interface (wlan0)",
                "-l": "Scan local net",
                "-g": "Generate list",
                "-r": "Retries",
                "-t": "Timeout"
            },
            "fping": {
                "-a": "Alive hosts",
                "-u": "Unreachable",
                "-g": "IP range",
                "-r": "Retries",
                "-t": "Timeout ms",
                "-c": "Ping count",
                "-q": "Quiet"
            },
            "nbtscan": {
                "-v": "Verbose",
                "-r": "Port 137",
                "-q": "Quiet",
                "-s": "Separator"
            },
            "snmp-check": {
                "-c": "Community string",
                "-p": "Port (161)",
                "-v": "Version",
                "-w": "Write test"
            },
            "onesixtyone": {
                "-c": "Community file",
                "-i": "Target file",
                "-o": "Output file",
                "-w": "Wait time"
            },
            "ike-scan": {
                "-M": "Main mode",
                "-A": "Aggressive",
                "-P": "Proprietary",
                "-v": "Verbose"
            },
            "tcpdump": {
                "-i": "Interface (eth0)",
                "-w": "Write to file",
                "-r": "Read from file",
                "-c": "Packet count",
                "-s": "Snap length",
                "-X": "Hex/ASCII output",
                "-A": "ASCII output",
                "-vv": "More verbose"
            },
            "wireshark": {
                "-i": "Interface (eth0)",
                "-k": "Start immediately",
                "-Y": "Display filter",
                "-w": "Write to file",
                "-r": "Read from file"
            },
            "hping3": {
                "-c": "Packet count",
                "--fast": "Fast mode",
                "--flood": "Flood mode",
                "-p": "Destination port",
                "-S": "SYN flag",
                "-A": "ACK flag",
                "--rand-source": "Random source IP",
                "-V": "Verbose"
            },
            "ettercap": {
                "-T": "Text interface",
                "-i": "Interface (eth0)",
                "-M": "MITM mode",
                "-q": "Quiet mode",
                "-P": "Plugin",
                "-w": "Write to file",
                "-r": "Read from file"
            },
            "netcat": {
                "-l": "Listen mode",
                "-v": "Verbose",
                "-n": "No DNS resolution",
                "-z": "Zero-I/O mode",
                "-w": "Timeout",
                "-p": "Port (put after target)"
            },
            "dnsenum": {
                "-t": "Threads",
                "-o": "Output file",
                "-r": "Recursive",
                "-f": "File with subdomains",
                "-d": "WHOIS lookups delay"
            },
            "traceroute": {
                "-I": "ICMP Echo",
                "-T": "TCP SYN",
                "-n": "No DNS resolution",
                "-w": "Wait time",
                "-m": "Max hops"
            },
            "whois": {
                "-h": "Server",
                "-p": "Port",
                "-a": "All sources",
                "-i": "Inverse lookup"
            },
            "sslscan": {
                "--targets": "Target file",
                "--tls": "TLS only",
                "--pk": "Check private key",
                "--bugs": "Check bugs",
                "--renegotiation": "Check renegotiation"
            },
            "ncrack": {
                "-U": "Username file",
                "-P": "Password file",
                "-p": "Port",
                "-T": "Timing template",
                "-v": "Verbose",
                "--pairwise": "Try user/pass combos"
            },
            "proxychains": {
                "-f": "Config file",
                "-q": "Quiet mode",
                "-d": "Don't proxy DNS",
                "--dynamic": "Dynamic chain"
            }
        }

        # Update help text with detailed documentation
        doc_content = tool_docs.get(tool, "No documentation available for this tool.")
        self.update_help_text(doc_content)

        # Special handling for certain tools
        if tool == "arp-scan":
            hbox = wx.BoxSizer(wx.HORIZONTAL)
            cb = wx.CheckBox(self.args_panel, label="Quick Local Network Scan")
            cb.SetForegroundColour("#00ff00")
            cb.SetToolTip("Scan your LAN using ARP packets.")
            cb.Bind(wx.EVT_CHECKBOX, lambda e: self.update_help_text(tool_docs.get(tool, "")))
            hbox.Add(cb, 0, wx.ALL | wx.CENTER, 5)
            hbox.AddStretchSpacer(1)
            self.args_sizer.Add(hbox, 0, wx.EXPAND | wx.ALL, 2)
            self.arg_widgets["local_scan"] = (cb, None)

        # Special case for fping
        if tool == "fping":
            fping_range_sizer = wx.BoxSizer(wx.HORIZONTAL)

            start_label = wx.StaticText(self.args_panel, label="Start IP:")
            start_label.SetForegroundColour(self.light_text)
            fping_range_sizer.Add(start_label, 0, wx.ALL | wx.CENTER, 5)

            self.fping_start_ip_input = wx.TextCtrl(self.args_panel, size=(120, -1))
            self.fping_start_ip_input.SetBackgroundColour("#3a3a3a")
            self.fping_start_ip_input.SetForegroundColour(self.light_text)
            fping_range_sizer.Add(self.fping_start_ip_input, 0, wx.ALL, 5)

            end_label = wx.StaticText(self.args_panel, label="End IP:")
            end_label.SetForegroundColour(self.light_text)
            fping_range_sizer.Add(end_label, 0, wx.ALL | wx.CENTER, 5)

            self.fping_end_ip_input = wx.TextCtrl(self.args_panel, size=(120, -1))
            self.fping_end_ip_input.SetBackgroundColour("#3a3a3a")
            self.fping_end_ip_input.SetForegroundColour(self.light_text)
            fping_range_sizer.Add(self.fping_end_ip_input, 0, wx.ALL, 5)

            self.args_sizer.Add(fping_range_sizer, 0, wx.EXPAND | wx.ALL, 5)

        # Create argument controls
        args = tool_args.get(tool, {})
        for arg, desc in args.items():
            hbox = wx.BoxSizer(wx.HORIZONTAL)
            cb = wx.CheckBox(self.args_panel, label=arg)
            cb.SetForegroundColour(self.light_text)
            cb.SetToolTip(desc)
            cb.Bind(wx.EVT_CHECKBOX, lambda e, doc=tool_docs.get(tool, ""): self.update_help_text(doc))
            hbox.Add(cb, 0, wx.ALL | wx.CENTER, 5)
            txt = None
            # Only add text control if the argument needs a value
            if arg in ["-p", "-i", "-c", "-w", "-r", "-t", "-s", "-v", "-o", "-d", "-h", "-P", "-U", "-T", "-m", "-Y", "-I", "-e", "--rate", "--source-ip", "--targets"]:
                txt = wx.TextCtrl(self.args_panel, size=(150, -1))
                txt.SetBackgroundColour("#3a3a3a")
                txt.SetForegroundColour(self.light_text)
                txt.SetHint(desc)
                txt.SetToolTip(desc)
                txt.Bind(wx.EVT_SET_FOCUS, lambda e, doc=tool_docs.get(tool, ""): self.update_help_text(doc))
                hbox.AddStretchSpacer(1)
                hbox.Add(txt, 0, wx.ALL | wx.EXPAND, 5)
            else:
                hbox.AddStretchSpacer(2)
            self.arg_widgets[arg] = (cb, txt)
            self.args_sizer.Add(hbox, 0, wx.EXPAND | wx.ALL, 2)

        self.args_panel.SetVirtualSize(self.args_sizer.GetMinSize())
        self.args_panel.Layout()
        self.left_panel.Layout()

        # Append tool info to terminal
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        wx.CallAfter(self.output.AppendText, f"\n[{timestamp}] Tool changed to: {tool}\n")
        wx.CallAfter(self.auto_scroll_output)
    
    def append_help_to_terminal(self, message):
        sep = "-" * 40
        wx.CallAfter(self.output.AppendText, f"\n{sep}\n[HELP] {message}\n{sep}\n")
        wx.CallAfter(self.auto_scroll_output)
    
    def auto_scroll_output(self):
        self.output.ShowPosition(self.output.GetLastPosition())
    
    def execute_command_with_output(self, cmd, tool_name):
        self.stop_flag = False
        if self.running_process:
            try:
                self.running_process.terminate()
            except:
                pass
            self.running_process = None
        self.current_command = tool_name
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sep = "=" * 60
        wx.CallAfter(self.output.AppendText, f"\n{sep}\n[RUNNING {tool_name}]\n[{timestamp}] Command: {' '.join(cmd)}\n{sep}\n\n")
        wx.CallAfter(self.auto_scroll_output)
        
        # Check if tool exists
        if not shutil.which(cmd[0]):
            wx.CallAfter(self.output.AppendText, f"\n[ERROR] Tool '{cmd[0]}' not found. Please install it.\n")
            wx.CallAfter(self.enable_run_buttons)
            return
            
        # Join the command list into a string for Windows compatibility
        if sys.platform.startswith("win"):
            cmd = " ".join(cmd)
            
        self.command_thread = threading.Thread(
            target=self.execute_command, 
            args=(cmd,),
            daemon=True
        )
        self.command_thread.start()
    
    def execute_command(self, cmd):
        try:
            self.running_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                shell=True if sys.platform.startswith("win") else False
            )
            
            while True:
                line = self.running_process.stdout.readline()
                if not line and self.running_process.poll() is not None:
                    break
                if self.stop_flag:
                    break
                if line:
                    wx.CallAfter(self.output.AppendText, line)
                    wx.CallAfter(self.auto_scroll_output)
                    wx.Yield()
                    
            return_code = self.running_process.poll()
            completion_text = f"\n--- Command completed (return code: {return_code}) ---\n\n"
            wx.CallAfter(self.output.AppendText, completion_text)
            wx.CallAfter(self.auto_scroll_output)
            
        except Exception as e:
            error_text = f"\n[Error] {e}\n\n"
            wx.CallAfter(self.output.AppendText, error_text)
        finally:
            self.running_process = None
            self.current_command = None
            wx.CallAfter(self.enable_run_buttons)
    
    def enable_run_buttons(self):
        """Re-enable run buttons after command completes"""
        if self.current_command == "PING":
            self.ping_run_btn.Enable()
            self.ping_stop_btn.Disable()
        else:
            self.tool_run_btn.Enable()
            self.tool_stop_btn.Disable()
    
    def on_stop_command(self, event):
        self.stop_flag = True
        if self.running_process:
            try:
                self.running_process.terminate()
                wx.CallAfter(self.output.AppendText, "\n[Command stopped by user]\n")
            except Exception as e:
                wx.CallAfter(self.output.AppendText, f"\n[Error stopping command: {e}]\n")
        self.enable_run_buttons()
    
    def on_toggle_help(self, event):
        if self.help_visible:
            self.help_text.Hide()
            self.toggle_help_btn.SetLabel("Show Help")
            self.help_visible = False
        else:
            self.help_text.Show()
            self.toggle_help_btn.SetLabel("Hide Help")
            self.help_visible = True
        self.right_panel.Layout()
    
    def on_save_output(self, event):
        with wx.FileDialog(self, "Save output as...", wildcard="Text files (*.txt)|*.txt",
                          style=wx.FD_SAVE | wx.FD_OVERWRITE_PROMPT) as fileDialog:
            if fileDialog.ShowModal() == wx.ID_CANCEL:
                return
            path = fileDialog.GetPath()
            try:
                with open(path, 'w', encoding='utf-8') as file:
                    file.write(self.output.GetValue())
                wx.MessageBox("Output saved successfully!", "Success", wx.OK | wx.ICON_INFORMATION)
            except Exception as e:
                wx.MessageBox(f"Failed to save file: {e}", "Error", wx.OK | wx.ICON_ERROR)

def main():
    app = wx.App(False)
    frame = SecurityToolGUI()
    frame.Show()
    app.MainLoop()

if __name__ == "__main__":
    main()
