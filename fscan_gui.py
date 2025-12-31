#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QGroupBox, QLabel, QLineEdit, QTextEdit, QPushButton, 
    QCheckBox, QSpinBox, QComboBox, QFileDialog, QScrollArea, QGridLayout,
    QFrame
)
from PyQt5.QtCore import Qt, QProcess, QSize
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

class FscanGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Fscan - 内网综合扫描工具")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 600)
        
        # 设置全局样式
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QGroupBox {
                font-weight: bold;
                border: 1px solid #e0e0e0;
                border-radius: 8px;
                margin-top: 10px;
                margin-bottom: 10px;
                padding: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                background-color: white;
                font-size: 14px;
            }
            QLabel {
                font-size: 12px;
                margin-right: 10px;
                min-width: 120px;
                text-align: right;
            }
            QLineEdit, QSpinBox, QComboBox {
                font-size: 12px;
                padding: 6px;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                min-width: 200px;
            }
            QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
                border-color: #4a90e2;
                outline: none;
            }
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                padding: 6px 16px;
                border-radius: 4px;
                font-size: 12px;
                margin-left: 5px;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QCheckBox {
                font-size: 12px;
                margin: 5px 0;
            }
            QSpinBox {
                max-width: 120px;
            }
            QComboBox {
                max-width: 200px;
            }
            QTabWidget::pane {
                border: 1px solid #e0e0e0;
                background-color: white;
                border-radius: 4px;
                padding: 10px;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-size: 13px;
                min-width: 80px;
                text-align: center;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #4a90e2;
                font-weight: bold;
            }
            QTextEdit {
                font-family: Consolas, Monaco, monospace;
                font-size: 11px;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
                padding: 10px;
                background-color: #fafafa;
            }
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QGridLayout {
                spacing: 10px;
                margin: 5px;
            }
        """)
        
        # 获取当前目录下的fscan可执行文件
        self.fscan_path = self.find_fscan_executable()
        
        # 初始化扫描进程
        self.scan_process = None
        
        # 初始化UI
        self.init_ui()
    
    def find_fscan_executable(self):
        """查找fscan可执行文件"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # 检查当前目录
        for file in os.listdir(current_dir):
            if file.startswith("fscan") and (file.endswith(".exe") or not "." in file):
                return os.path.join(current_dir, file)
        # 如果当前目录没有，尝试查找go构建后的文件
        return "fscan"  # 默认使用系统路径中的fscan
    
    def browse_fscan_path(self):
        """浏览选择fscan可执行文件路径"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择fscan可执行文件", ".", "Executable Files (*.exe);;All Files (*)")
        if file_path:
            self.fscan_path_edit.setText(file_path)
            self.fscan_path = file_path
    
    def init_ui(self):
        """初始化UI组件"""
        # 主窗口
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout(central_widget)
        
        # 顶部控制栏
        control_layout = QHBoxLayout()
        
        self.start_btn = QPushButton("开始扫描")
        self.start_btn.clicked.connect(self.start_scan)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("停止扫描")
        self.stop_btn.clicked.connect(self.stop_scan)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        self.reset_btn = QPushButton("重置配置")
        self.reset_btn.clicked.connect(self.reset_config)
        control_layout.addWidget(self.reset_btn)
        
        main_layout.addLayout(control_layout)
        
        # 中间内容区域
        content_layout = QHBoxLayout()
        
        # 左侧选项卡
        self.tabs = QTabWidget()
        content_layout.addWidget(self.tabs, 1)
        
        # 右侧输出区域
        output_group = QGroupBox("扫描结果")
        output_layout = QVBoxLayout(output_group)
        
        # 输出控制栏
        output_control_layout = QHBoxLayout()
        
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("搜索结果...")
        self.search_edit.setMinimumWidth(200)
        self.search_edit.textChanged.connect(self.search_output)
        output_control_layout.addWidget(self.search_edit)
        
        self.copy_btn = QPushButton("复制结果")
        self.copy_btn.clicked.connect(self.copy_output)
        output_control_layout.addWidget(self.copy_btn)
        
        self.clear_btn = QPushButton("清空结果")
        self.clear_btn.clicked.connect(self.clear_output)
        output_control_layout.addWidget(self.clear_btn)
        
        self.save_btn = QPushButton("保存结果")
        self.save_btn.clicked.connect(self.save_output)
        output_control_layout.addWidget(self.save_btn)
        
        output_layout.addLayout(output_control_layout)
        
        # 输出文本区域
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 10))
        output_layout.addWidget(self.output_text)
        
        content_layout.addWidget(output_group, 1)
        
        main_layout.addLayout(content_layout)
        
        # 添加选项卡
        self.add_tabs()
    
    def add_tabs(self):
        """添加各个选项卡"""
        # 主机扫描选项卡（整合目标配置和扫描控制）
        self.host_scan_tab = QWidget()
        self.tabs.addTab(self.host_scan_tab, "主机扫描")
        self.init_host_scan_tab()
        
        # Web扫描选项卡（整合Web扫描、POC测试和Web漏洞利用）
        self.web_scan_tab = QWidget()
        self.tabs.addTab(self.web_scan_tab, "Web扫描")
        self.init_web_scan_tab()
        
        # 系统漏洞利用选项卡（包含非Web相关漏洞利用）
        self.system_exploit_tab = QWidget()
        self.tabs.addTab(self.system_exploit_tab, "系统漏洞利用")
        self.init_system_exploit_tab()
        
        # 输出与显示选项卡
        self.output_tab = QWidget()
        self.tabs.addTab(self.output_tab, "输出与显示")
        self.init_output_tab()
        
        # 系统设置选项卡
        self.system_tab = QWidget()
        self.tabs.addTab(self.system_tab, "系统设置")
        self.init_system_tab()
    
    def init_host_scan_tab(self):
        """初始化主机扫描选项卡（整合目标配置和扫描控制）"""
        layout = QVBoxLayout(self.host_scan_tab)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # 目标地址
        group = QGroupBox("目标地址")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("目标地址 (-h):"), 0, 0)
        self.target_host = QLineEdit()
        grid.addWidget(self.target_host, 0, 1)
        
        grid.addWidget(QLabel("排除主机 (-eh):"), 1, 0)
        self.exclude_hosts = QLineEdit()
        grid.addWidget(self.exclude_hosts, 1, 1)
        
        scroll_layout.addWidget(group)
        
        # 端口配置
        group = QGroupBox("端口配置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("扫描端口 (-p):"), 0, 0)
        self.scan_ports = QLineEdit("21,22,80,443,3306,6379,8080,8443")
        grid.addWidget(self.scan_ports, 0, 1)
        
        grid.addWidget(QLabel("排除端口 (-ep):"), 1, 0)
        self.exclude_ports = QLineEdit()
        grid.addWidget(self.exclude_ports, 1, 1)
        
        grid.addWidget(QLabel("主机文件 (-hf):"), 2, 0)
        file_layout = QHBoxLayout()
        self.hosts_file = QLineEdit()
        file_layout.addWidget(self.hosts_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.hosts_file))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 2, 1)
        
        grid.addWidget(QLabel("端口文件 (-pf):"), 3, 0)
        file_layout = QHBoxLayout()
        self.ports_file = QLineEdit()
        file_layout.addWidget(self.ports_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.ports_file))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 3, 1)
        
        scroll_layout.addWidget(group)
        
        # 扫描模式
        group = QGroupBox("扫描模式")
        group_layout = QVBoxLayout(group)
        
        # 全选复选框
        self.all_scan_mode = QCheckBox("全选 (all)")
        self.all_scan_mode.setChecked(True)
        self.all_scan_mode.stateChanged.connect(self.toggle_all_scan_modes)
        group_layout.addWidget(self.all_scan_mode)
        
        # 扫描模式分类
        # 1. 网络服务
        network_group = QGroupBox("网络服务")
        network_layout = QVBoxLayout(network_group)
        
        self.network_modes = {
            "ftp": QCheckBox("FTP"),
            "ssh": QCheckBox("SSH"),
            "telnet": QCheckBox("Telnet"),
            "smb": QCheckBox("SMB"),
            "smb2": QCheckBox("SMB2"),
            "smbghost": QCheckBox("SMBGhost"),
            "smbinfo": QCheckBox("SMBInfo"),
            "rdp": QCheckBox("RDP"),
            "vnc": QCheckBox("VNC"),
            "smtp": QCheckBox("SMTP"),
            "snmp": QCheckBox("SNMP"),
            "rsync": QCheckBox("RSync"),
            "dps": QCheckBox("DPS"),
            "netbios": QCheckBox("NetBIOS")
        }
        
        for mode, checkbox in self.network_modes.items():
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(self.update_all_scan_mode)
            network_layout.addWidget(checkbox)
        
        group_layout.addWidget(network_group)
        
        # 2. 数据库服务
        db_group = QGroupBox("数据库服务")
        db_layout = QVBoxLayout(db_group)
        
        self.db_modes = {
            "mssql": QCheckBox("MSSQL"),
            "oracle": QCheckBox("Oracle"),
            "mysql": QCheckBox("MySQL"),
            "postgresql": QCheckBox("PostgreSQL"),
            "redis": QCheckBox("Redis"),
            "memcached": QCheckBox("Memcached"),
            "mongodb": QCheckBox("MongoDB"),
            "cassandra": QCheckBox("Cassandra"),
            "neo4j": QCheckBox("Neo4j")
        }
        
        for mode, checkbox in self.db_modes.items():
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(self.update_all_scan_mode)
            db_layout.addWidget(checkbox)
        
        group_layout.addWidget(db_group)
        
        # 3. 消息队列
        mq_group = QGroupBox("消息队列")
        mq_layout = QVBoxLayout(mq_group)
        
        self.mq_modes = {
            "rabbitmq": QCheckBox("RabbitMQ"),
            "kafka": QCheckBox("Kafka"),
            "activemq": QCheckBox("ActiveMQ")
        }
        
        for mode, checkbox in self.mq_modes.items():
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(self.update_all_scan_mode)
            mq_layout.addWidget(checkbox)
        
        group_layout.addWidget(mq_group)
        
        # 4. 漏洞检测
        vuln_group = QGroupBox("漏洞检测")
        vuln_layout = QVBoxLayout(vuln_group)
        
        self.vuln_modes = {
            "ms17010": QCheckBox("MS17-010"),
            "findnet": QCheckBox("FindNet"),
            "elasticsearch": QCheckBox("Elasticsearch")
        }
        
        for mode, checkbox in self.vuln_modes.items():
            checkbox.setChecked(True)
            checkbox.stateChanged.connect(self.update_all_scan_mode)
            vuln_layout.addWidget(checkbox)
        
        group_layout.addWidget(vuln_group)
        
        # 用于生成命令的隐藏扫描模式字段
        self.scan_mode = QLineEdit("all")
        self.scan_mode.setObjectName("scan_mode")
        self.scan_mode.setVisible(False)
        group_layout.addWidget(self.scan_mode)
        
        scroll_layout.addWidget(group)
        
        # 性能设置
        group = QGroupBox("性能设置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("扫描线程数 (-t):"), 0, 0)
        self.thread_num = QSpinBox()
        self.thread_num.setObjectName("thread_num")
        self.thread_num.setRange(1, 2000)
        self.thread_num.setValue(600)
        grid.addWidget(self.thread_num, 0, 1)
        
        grid.addWidget(QLabel("模块线程数 (-mt):"), 1, 0)
        self.module_thread_num = QSpinBox()
        self.module_thread_num.setObjectName("module_thread_num")
        self.module_thread_num.setRange(1, 100)
        self.module_thread_num.setValue(10)
        grid.addWidget(self.module_thread_num, 1, 1)
        
        grid.addWidget(QLabel("单次连接超时 (-time):"), 2, 0)
        self.timeout = QSpinBox()
        self.timeout.setObjectName("timeout")
        self.timeout.setRange(1, 30)
        self.timeout.setValue(3)
        self.timeout.setSuffix("秒")
        grid.addWidget(self.timeout, 2, 1)
        
        grid.addWidget(QLabel("全局超时时间 (-gt):"), 3, 0)
        self.global_timeout = QSpinBox()
        self.global_timeout.setObjectName("global_timeout")
        self.global_timeout.setRange(60, 3600)
        self.global_timeout.setValue(180)
        self.global_timeout.setSuffix("秒")
        grid.addWidget(self.global_timeout, 3, 1)
        
        grid.addWidget(QLabel("最大重试次数 (-retry):"), 4, 0)
        self.max_retries = QSpinBox()
        self.max_retries.setObjectName("max_retries")
        self.max_retries.setRange(1, 10)
        self.max_retries.setValue(3)
        grid.addWidget(self.max_retries, 4, 1)
        
        scroll_layout.addWidget(group)
        
        # 存活探测
        group = QGroupBox("存活探测")
        grid = QGridLayout(group)
        
        self.disable_ping = QCheckBox("禁用Ping (-np)")
        grid.addWidget(self.disable_ping, 0, 0)
        
        self.use_ping = QCheckBox("仅存活主机 (-ping)")
        grid.addWidget(self.use_ping, 1, 0)
        
        self.enable_fingerprint = QCheckBox("启用指纹识别 (-fingerprint)")
        grid.addWidget(self.enable_fingerprint, 2, 0)
        
        self.local_mode = QCheckBox("本地模式 (-local)")
        grid.addWidget(self.local_mode, 3, 0)
        
        scroll_layout.addWidget(group)
        
        # 认证与暴力破解（主机扫描）
        auth_group = QGroupBox("认证与暴力破解")
        auth_layout = QVBoxLayout(auth_group)
        
        # 初始化所有输入框组件
        self.host_username = QLineEdit()
        self.host_password = QLineEdit()
        self.host_password.setEchoMode(QLineEdit.Password)
        self.host_add_users = QLineEdit()
        self.host_add_passwords = QLineEdit()
        self.host_users_file = QLineEdit()
        self.host_passwords_file = QLineEdit()
        self.host_disable_brute = QCheckBox("禁用暴力破解 (-nobr)")
        self.host_hash_value = QLineEdit()
        self.host_hash_file = QLineEdit()
        self.host_domain = QLineEdit()
        self.host_ssh_key = QLineEdit()
        
        # 基本认证
        basic_auth_group = QGroupBox("基本认证")
        basic_auth_grid = QGridLayout(basic_auth_group)
        
        basic_auth_grid.addWidget(QLabel("默认用户名 (-user):"), 0, 0)
        basic_auth_grid.addWidget(self.host_username, 0, 1)
        
        basic_auth_grid.addWidget(QLabel("默认密码 (-pwd):"), 1, 0)
        basic_auth_grid.addWidget(self.host_password, 1, 1)
        
        basic_auth_grid.addWidget(QLabel("附加用户名 (-usera):"), 2, 0)
        basic_auth_grid.addWidget(self.host_add_users, 2, 1)
        
        basic_auth_grid.addWidget(QLabel("附加密码 (-pwda):"), 3, 0)
        basic_auth_grid.addWidget(self.host_add_passwords, 3, 1)
        
        auth_layout.addWidget(basic_auth_group)
        
        # 弱口令字典
        dict_group = QGroupBox("弱口令字典")
        dict_grid = QGridLayout(dict_group)
        
        dict_grid.addWidget(QLabel("用户名字典 (-userf):"), 0, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.host_users_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.host_users_file))
        file_layout.addWidget(browse_btn)
        dict_grid.addLayout(file_layout, 0, 1)
        
        dict_grid.addWidget(QLabel("密码字典 (-pwdf):"), 1, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.host_passwords_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.host_passwords_file))
        file_layout.addWidget(browse_btn)
        dict_grid.addLayout(file_layout, 1, 1)
        
        # 暴力破解控制
        dict_grid.addWidget(QLabel("暴力破解:"), 2, 0)
        brute_layout = QHBoxLayout()
        brute_layout.addWidget(self.host_disable_brute)
        dict_grid.addLayout(brute_layout, 2, 1)
        
        auth_layout.addWidget(dict_group)
        
        # Hash认证
        hash_auth_group = QGroupBox("Hash认证")
        hash_auth_grid = QGridLayout(hash_auth_group)
        
        hash_auth_grid.addWidget(QLabel("Hash值 (-hash):"), 0, 0)
        hash_auth_grid.addWidget(self.host_hash_value, 0, 1)
        
        hash_auth_grid.addWidget(QLabel("Hash文件 (-hashf):"), 1, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.host_hash_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.host_hash_file))
        file_layout.addWidget(browse_btn)
        hash_auth_grid.addLayout(file_layout, 1, 1)
        
        auth_layout.addWidget(hash_auth_group)
        
        # 高级认证
        advanced_auth_group = QGroupBox("高级认证")
        advanced_auth_grid = QGridLayout(advanced_auth_group)
        
        advanced_auth_grid.addWidget(QLabel("域名 (-domain):"), 0, 0)
        advanced_auth_grid.addWidget(self.host_domain, 0, 1)
        
        advanced_auth_grid.addWidget(QLabel("SSH密钥路径 (-sshkey):"), 1, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.host_ssh_key)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.host_ssh_key))
        file_layout.addWidget(browse_btn)
        advanced_auth_grid.addLayout(file_layout, 1, 1)
        
        auth_layout.addWidget(advanced_auth_group)
        
        scroll_layout.addWidget(auth_group)
        
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
    
    def toggle_all_scan_modes(self, state):
        """切换所有扫描模式的选中状态"""
        checked = state == Qt.Checked
        
        # 更新所有分类的复选框
        for modes_dict in [self.network_modes, self.db_modes, self.mq_modes, self.vuln_modes]:
            for checkbox in modes_dict.values():
                checkbox.setChecked(checked)
    
    def update_all_scan_mode(self):
        """当单个扫描模式变化时更新全选复选框状态"""
        # 检查所有分类的复选框是否都被选中
        all_checked = True
        for modes_dict in [self.network_modes, self.db_modes, self.mq_modes, self.vuln_modes]:
            for checkbox in modes_dict.values():
                if not checkbox.isChecked():
                    all_checked = False
                    break
            if not all_checked:
                break
        
        self.all_scan_mode.setChecked(all_checked)
        
    def get_selected_scan_modes(self):
        """获取选中的扫描模式列表"""
        selected_modes = []
        
        # 检查所有分类的复选框
        for modes_dict in [self.network_modes, self.db_modes, self.mq_modes, self.vuln_modes]:
            for mode, checkbox in modes_dict.items():
                if checkbox.isChecked():
                    selected_modes.append(mode)
        
        if not selected_modes:
            return ""
        elif len(selected_modes) == sum(len(d) for d in [self.network_modes, self.db_modes, self.mq_modes, self.vuln_modes]):
            return "all"
        else:
            return ",".join(selected_modes)
    
    def init_web_scan_tab(self):
        """初始化Web扫描选项卡（整合Web扫描、POC测试和Web漏洞利用）"""
        layout = QVBoxLayout(self.web_scan_tab)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Web目标
        group = QGroupBox("Web目标")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("目标URL (-u):"), 0, 0)
        self.target_url = QLineEdit()
        grid.addWidget(self.target_url, 0, 1)
        
        grid.addWidget(QLabel("URL文件 (-uf):"), 1, 0)
        file_layout = QHBoxLayout()
        self.urls_file = QLineEdit()
        file_layout.addWidget(self.urls_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.urls_file))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 1, 1)
        
        grid.addWidget(QLabel("Cookie (-cookie):"), 2, 0)
        self.cookie = QLineEdit()
        grid.addWidget(self.cookie, 2, 1)
        
        scroll_layout.addWidget(group)
        
        # Web设置
        group = QGroupBox("Web设置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Web超时时间 (-wt):"), 0, 0)
        self.web_timeout = QSpinBox()
        self.web_timeout.setRange(1, 30)
        self.web_timeout.setValue(5)
        self.web_timeout.setSuffix("秒")
        grid.addWidget(self.web_timeout, 0, 1)
        
        grid.addWidget(QLabel("HTTP代理 (-proxy):"), 1, 0)
        self.http_proxy = QLineEdit()
        grid.addWidget(self.http_proxy, 1, 1)
        
        grid.addWidget(QLabel("Socks5代理 (-socks5):"), 2, 0)
        self.socks5_proxy = QLineEdit()
        grid.addWidget(self.socks5_proxy, 2, 1)
        
        scroll_layout.addWidget(group)
        
        # POC测试
        group = QGroupBox("Web POC测试")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("POC路径 (-pocpath):"), 0, 0)
        file_layout = QHBoxLayout()
        self.poc_path = QLineEdit()
        file_layout.addWidget(self.poc_path)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.poc_path, directory=True))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 0, 1)
        
        grid.addWidget(QLabel("POC名称 (-pocname):"), 1, 0)
        self.poc_name = QLineEdit()
        grid.addWidget(self.poc_name, 1, 1)
        
        self.disable_poc = QCheckBox("禁用POC扫描 (-nopoc)")
        grid.addWidget(self.disable_poc, 2, 0, 1, 2)
        
        self.poc_full = QCheckBox("完整扫描 (-full)")
        grid.addWidget(self.poc_full, 3, 0)
        
        self.dns_log = QCheckBox("启用DNS日志 (-dns)")
        grid.addWidget(self.dns_log, 3, 1)
        
        grid.addWidget(QLabel("POC数量限制 (-num):"), 4, 0)
        self.poc_num = QSpinBox()
        self.poc_num.setRange(1, 100)
        self.poc_num.setValue(20)
        grid.addWidget(self.poc_num, 4, 1)
        
        scroll_layout.addWidget(group)
        
        # 认证与暴力破解（Web扫描）
        auth_group = QGroupBox("认证与暴力破解")
        auth_layout = QVBoxLayout(auth_group)
        
        # 基本认证
        basic_auth_group = QGroupBox("基本认证")
        basic_auth_grid = QGridLayout(basic_auth_group)
        
        self.web_username = QLineEdit()
        self.web_password = QLineEdit()
        self.web_password.setEchoMode(QLineEdit.Password)
        self.web_add_users = QLineEdit()
        self.web_add_passwords = QLineEdit()
        
        basic_auth_grid.addWidget(QLabel("默认用户名 (-user):"), 0, 0)
        basic_auth_grid.addWidget(self.web_username, 0, 1)
        
        basic_auth_grid.addWidget(QLabel("默认密码 (-pwd):"), 1, 0)
        basic_auth_grid.addWidget(self.web_password, 1, 1)
        
        basic_auth_grid.addWidget(QLabel("附加用户名 (-usera):"), 2, 0)
        basic_auth_grid.addWidget(self.web_add_users, 2, 1)
        
        basic_auth_grid.addWidget(QLabel("附加密码 (-pwda):"), 3, 0)
        basic_auth_grid.addWidget(self.web_add_passwords, 3, 1)
        
        auth_layout.addWidget(basic_auth_group)
        
        # 弱口令字典
        dict_group = QGroupBox("弱口令字典")
        dict_grid = QGridLayout(dict_group)
        
        self.web_users_file = QLineEdit()
        self.web_passwords_file = QLineEdit()
        self.web_disable_brute = QCheckBox("禁用暴力破解 (-nobr)")
        
        dict_grid.addWidget(QLabel("用户名字典 (-userf):"), 0, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.web_users_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.web_users_file))
        file_layout.addWidget(browse_btn)
        dict_grid.addLayout(file_layout, 0, 1)
        
        dict_grid.addWidget(QLabel("密码字典 (-pwdf):"), 1, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.web_passwords_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.web_passwords_file))
        file_layout.addWidget(browse_btn)
        dict_grid.addLayout(file_layout, 1, 1)
        
        # 暴力破解控制
        dict_grid.addWidget(QLabel("暴力破解:"), 2, 0)
        brute_layout = QHBoxLayout()
        brute_layout.addWidget(self.web_disable_brute)
        dict_grid.addLayout(brute_layout, 2, 1)
        
        auth_layout.addWidget(dict_group)
        
        # Hash认证
        hash_auth_group = QGroupBox("Hash认证")
        hash_auth_grid = QGridLayout(hash_auth_group)
        
        self.web_hash_value = QLineEdit()
        self.web_hash_file = QLineEdit()
        
        hash_auth_grid.addWidget(QLabel("Hash值 (-hash):"), 0, 0)
        hash_auth_grid.addWidget(self.web_hash_value, 0, 1)
        
        hash_auth_grid.addWidget(QLabel("Hash文件 (-hashf):"), 1, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.web_hash_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.web_hash_file))
        file_layout.addWidget(browse_btn)
        hash_auth_grid.addLayout(file_layout, 1, 1)
        
        auth_layout.addWidget(hash_auth_group)
        
        # 高级认证
        advanced_auth_group = QGroupBox("高级认证")
        advanced_auth_grid = QGridLayout(advanced_auth_group)
        
        self.web_domain = QLineEdit()
        self.web_ssh_key = QLineEdit()
        
        advanced_auth_grid.addWidget(QLabel("域名 (-domain):"), 0, 0)
        advanced_auth_grid.addWidget(self.web_domain, 0, 1)
        
        advanced_auth_grid.addWidget(QLabel("SSH密钥路径 (-sshkey):"), 1, 0)
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.web_ssh_key)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.web_ssh_key))
        file_layout.addWidget(browse_btn)
        advanced_auth_grid.addLayout(file_layout, 1, 1)
        
        auth_layout.addWidget(advanced_auth_group)
        
        scroll_layout.addWidget(auth_group)
        
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
    
    def init_system_exploit_tab(self):
        """初始化系统漏洞利用选项卡（包含非Web相关漏洞利用）"""
        layout = QVBoxLayout(self.system_exploit_tab)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # Redis利用
        group = QGroupBox("Redis利用")
        grid = QGridLayout(group)
        
        self.disable_redis = QCheckBox("禁用Redis扫描 (-noredis)")
        grid.addWidget(self.disable_redis, 0, 0, 1, 2)
        
        grid.addWidget(QLabel("Redis文件 (-rf):"), 1, 0)
        self.redis_file = QLineEdit()
        grid.addWidget(self.redis_file, 1, 1)
        
        grid.addWidget(QLabel("Redis反弹Shell (-rs):"), 2, 0)
        self.redis_shell = QLineEdit()
        grid.addWidget(self.redis_shell, 2, 1)
        
        grid.addWidget(QLabel("Redis写入路径 (-rwp):"), 3, 0)
        self.redis_write_path = QLineEdit()
        grid.addWidget(self.redis_write_path, 3, 1)
        
        grid.addWidget(QLabel("Redis写入内容 (-rwc):"), 4, 0)
        self.redis_write_content = QLineEdit()
        grid.addWidget(self.redis_write_content, 4, 1)
        
        grid.addWidget(QLabel("Redis写入文件 (-rwf):"), 5, 0)
        file_layout = QHBoxLayout()
        self.redis_write_file = QLineEdit()
        file_layout.addWidget(self.redis_write_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.redis_write_file))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 5, 1)
        
        scroll_layout.addWidget(group)
        
        # 其他系统漏洞利用
        group = QGroupBox("其他系统漏洞利用")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("Shellcode (-sc):"), 0, 0)
        self.shellcode = QLineEdit()
        grid.addWidget(self.shellcode, 0, 1)
        
        scroll_layout.addWidget(group)
        
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
    
    def init_system_tab(self):
        """初始化系统设置选项卡"""
        layout = QVBoxLayout(self.system_tab)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # API设置
        group = QGroupBox("API设置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("API地址 (-api):"), 0, 0)
        self.api_addr = QLineEdit()
        grid.addWidget(self.api_addr, 0, 1)
        
        grid.addWidget(QLabel("API密钥 (-secret):"), 1, 0)
        self.secret_key = QLineEdit()
        self.secret_key.setEchoMode(QLineEdit.Password)
        grid.addWidget(self.secret_key, 1, 1)
        
        scroll_layout.addWidget(group)
        
        # 语言设置
        group = QGroupBox("语言设置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("语言 (-lang):"), 0, 0)
        self.language = QComboBox()
        self.language.addItems(["zh", "en"])
        grid.addWidget(self.language, 0, 1)
        
        scroll_layout.addWidget(group)
        
        # 工具路径设置
        group = QGroupBox("工具路径设置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("fscan可执行文件路径:"), 0, 0)
        file_layout = QHBoxLayout()
        self.fscan_path_edit = QLineEdit(self.fscan_path)
        file_layout.addWidget(self.fscan_path_edit)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.browse_fscan_path)
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 0, 1)
        
        scroll_layout.addWidget(group)
        
        # 关于信息
        group = QGroupBox("关于")
        grid = QGridLayout(group)
        
        about_label = QLabel("Fscan GUI v1.0\n基于PyQt5开发\n支持fscan所有功能")
        about_label.setAlignment(Qt.AlignCenter)
        grid.addWidget(about_label, 0, 0, 1, 2)
        
        scroll_layout.addWidget(group)
        
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
    
    def init_output_tab(self):
        """初始化输出与显示选项卡"""
        layout = QVBoxLayout(self.output_tab)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # 输出设置
        group = QGroupBox("输出设置")
        grid = QGridLayout(group)
        
        grid.addWidget(QLabel("输出文件 (-o):"), 0, 0)
        self.output_file = QLineEdit("result.txt")
        grid.addWidget(self.output_file, 0, 1)
        
        grid.addWidget(QLabel("输出格式 (-f):"), 1, 0)
        self.output_format = QComboBox()
        self.output_format.addItems(["txt", "json"])
        grid.addWidget(self.output_format, 1, 1)
        
        self.disable_save = QCheckBox("禁用结果保存 (-no)")
        grid.addWidget(self.disable_save, 2, 0)
        
        scroll_layout.addWidget(group)
        
        # 显示设置
        group = QGroupBox("显示设置")
        grid = QGridLayout(group)
        
        self.silent_mode = QCheckBox("静默模式 (-silent)")
        grid.addWidget(self.silent_mode, 0, 0)
        
        self.no_color = QCheckBox("禁用彩色输出 (-nocolor)")
        grid.addWidget(self.no_color, 1, 0)
        
        grid.addWidget(QLabel("日志级别 (-log):"), 2, 0)
        self.log_level = QComboBox()
        self.log_level.addItems(["success", "info", "warning", "error"])
        grid.addWidget(self.log_level, 2, 1)
        
        self.show_progress = QCheckBox("显示进度条 (-pg)")
        grid.addWidget(self.show_progress, 3, 0)
        
        self.show_scan_plan = QCheckBox("显示扫描计划 (-sp)")
        grid.addWidget(self.show_scan_plan, 4, 0)
        
        self.slow_log = QCheckBox("慢速日志输出 (-slow)")
        grid.addWidget(self.slow_log, 5, 0)
        
        scroll_layout.addWidget(group)
        
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
    
    def browse_file(self, line_edit, directory=False):
        """浏览文件或目录"""
        if directory:
            path = QFileDialog.getExistingDirectory(self, "选择目录")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path:
            line_edit.setText(path)
    
    def build_command(self):
        """构建fscan命令"""
        cmd = [self.fscan_path]
        
        # 目标配置
        if self.target_host.text():
            cmd.extend(["-h", self.target_host.text()])
        if self.exclude_hosts.text():
            cmd.extend(["-eh", self.exclude_hosts.text()])
        if self.scan_ports.text():
            cmd.extend(["-p", self.scan_ports.text()])
        if self.exclude_ports.text():
            cmd.extend(["-ep", self.exclude_ports.text()])
        if self.hosts_file.text():
            cmd.extend(["-hf", self.hosts_file.text()])
        if self.ports_file.text():
            cmd.extend(["-pf", self.ports_file.text()])
        
        # 扫描控制
        scan_mode = self.get_selected_scan_modes()
        if scan_mode:
            cmd.extend(["-m", scan_mode])
        cmd.extend(["-t", str(self.thread_num.value())])
        cmd.extend(["-mt", str(self.module_thread_num.value())])
        cmd.extend(["-time", str(self.timeout.value())])
        cmd.extend(["-gt", str(self.global_timeout.value())])
        if self.disable_ping.isChecked():
            cmd.append("-np")
        if self.use_ping.isChecked():
            cmd.append("-ping")
        if self.enable_fingerprint.isChecked():
            cmd.append("-fingerprint")
        if self.local_mode.isChecked():
            cmd.append("-local")
        
        # 认证与凭据 - 使用主机扫描的认证信息
        if self.host_username.text():
            cmd.extend(["-user", self.host_username.text()])
        if self.host_password.text():
            cmd.extend(["-pwd", self.host_password.text()])
        if self.host_add_users.text():
            cmd.extend(["-usera", self.host_add_users.text()])
        if self.host_add_passwords.text():
            cmd.extend(["-pwda", self.host_add_passwords.text()])
        if self.host_users_file.text():
            cmd.extend(["-userf", self.host_users_file.text()])
        if self.host_passwords_file.text():
            cmd.extend(["-pwdf", self.host_passwords_file.text()])
        if self.host_hash_value.text():
            cmd.extend(["-hash", self.host_hash_value.text()])
        if self.host_hash_file.text():
            cmd.extend(["-hashf", self.host_hash_file.text()])
        if self.host_domain.text():
            cmd.extend(["-domain", self.host_domain.text()])
        if self.host_ssh_key.text():
            cmd.extend(["-sshkey", self.host_ssh_key.text()])
        
        # Web扫描
        if self.target_url.text():
            cmd.extend(["-u", self.target_url.text()])
        if self.urls_file.text():
            cmd.extend(["-uf", self.urls_file.text()])
        if self.cookie.text():
            cmd.extend(["-cookie", self.cookie.text()])
        cmd.extend(["-wt", str(self.web_timeout.value())])
        if self.http_proxy.text():
            cmd.extend(["-proxy", self.http_proxy.text()])
        if self.socks5_proxy.text():
            cmd.extend(["-socks5", self.socks5_proxy.text()])
        
        # Web认证 - 如果有Web认证信息，使用Web认证信息
        if self.target_url.text() or self.urls_file.text():
            if self.web_username.text():
                cmd.extend(["-user", self.web_username.text()])
            if self.web_password.text():
                cmd.extend(["-pwd", self.web_password.text()])
            if self.web_add_users.text():
                cmd.extend(["-usera", self.web_add_users.text()])
            if self.web_add_passwords.text():
                cmd.extend(["-pwda", self.web_add_passwords.text()])
            if self.web_users_file.text():
                cmd.extend(["-userf", self.web_users_file.text()])
            if self.web_passwords_file.text():
                cmd.extend(["-pwdf", self.web_passwords_file.text()])
            if self.web_hash_value.text():
                cmd.extend(["-hash", self.web_hash_value.text()])
            if self.web_hash_file.text():
                cmd.extend(["-hashf", self.web_hash_file.text()])
            if self.web_domain.text():
                cmd.extend(["-domain", self.web_domain.text()])
            if self.web_ssh_key.text():
                cmd.extend(["-sshkey", self.web_ssh_key.text()])
        
        # POC测试
        if self.poc_path.text():
            cmd.extend(["-pocpath", self.poc_path.text()])
        if self.poc_name.text():
            cmd.extend(["-pocname", self.poc_name.text()])
        if self.disable_poc.isChecked():
            cmd.append("-nopoc")
        if self.poc_full.isChecked():
            cmd.append("-full")
        if self.dns_log.isChecked():
            cmd.append("-dns")
        cmd.extend(["-num", str(self.poc_num.value())])
        
        # Redis利用
        if self.redis_file.text():
            cmd.extend(["-rf", self.redis_file.text()])
        if self.redis_shell.text():
            cmd.extend(["-rs", self.redis_shell.text()])
        if self.disable_redis.isChecked():
            cmd.append("-noredis")
        if self.redis_write_path.text():
            cmd.extend(["-rwp", self.redis_write_path.text()])
        if self.redis_write_content.text():
            cmd.extend(["-rwc", self.redis_write_content.text()])
        if self.redis_write_file.text():
            cmd.extend(["-rwf", self.redis_write_file.text()])
        
        # 暴力破解 - 使用主机扫描的暴力破解设置，Web扫描也使用相同设置
        if self.host_disable_brute.isChecked() or self.web_disable_brute.isChecked():
            cmd.append("-nobr")
        cmd.extend(["-retry", str(self.max_retries.value())])
        
        # 输出与显示
        if self.output_file.text():
            cmd.extend(["-o", self.output_file.text()])
        cmd.extend(["-f", self.output_format.currentText()])
        if self.disable_save.isChecked():
            cmd.append("-no")
        if self.silent_mode.isChecked():
            cmd.append("-silent")
        if self.no_color.isChecked():
            cmd.append("-nocolor")
        cmd.extend(["-log", self.log_level.currentText()])
        if self.show_progress.isChecked():
            cmd.append("-pg")
        if self.show_scan_plan.isChecked():
            cmd.append("-sp")
        if self.slow_log.isChecked():
            cmd.append("-slow")
        
        # 其他参数
        if self.shellcode.text():
            cmd.extend(["-sc", self.shellcode.text()])
        cmd.extend(["-lang", self.language.currentText()])
        if self.api_addr.text():
            cmd.extend(["-api", self.api_addr.text()])
        if self.secret_key.text():
            cmd.extend(["-secret", self.secret_key.text()])
        
        return cmd
    
    def start_scan(self):
        """开始扫描"""
        # 构建命令
        cmd = self.build_command()
        self.output_text.append(f"执行命令: {' '.join(cmd)}")
        
        # 创建并启动进程
        self.scan_process = QProcess()
        self.scan_process.setProcessChannelMode(QProcess.MergedChannels)
        self.scan_process.readyReadStandardOutput.connect(self.read_output)
        self.scan_process.finished.connect(self.scan_finished)
        self.scan_process.errorOccurred.connect(self.process_error)
        
        # 启动进程
        self.scan_process.start(cmd[0], cmd[1:])
        
        # 更新按钮状态
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
    
    def stop_scan(self):
        """停止扫描"""
        if self.scan_process and self.scan_process.state() == QProcess.Running:
            self.scan_process.kill()
    
    def reset_config(self):
        """重置配置"""
        # 重置所有输入控件
        for tab_index in range(self.tabs.count()):
            tab = self.tabs.widget(tab_index)
            for widget in tab.findChildren((QLineEdit, QSpinBox, QComboBox, QCheckBox)):
                if isinstance(widget, QLineEdit):
                    widget.clear()
                elif isinstance(widget, QSpinBox):
                    # 恢复默认值
                    widget_name = widget.objectName()
                    if widget_name == "thread_num":
                        widget.setValue(600)
                    elif widget_name == "module_thread_num":
                        widget.setValue(10)
                    elif widget_name == "timeout":
                        widget.setValue(3)
                    elif widget_name == "global_timeout":
                        widget.setValue(180)
                    elif widget_name == "web_timeout":
                        widget.setValue(5)
                    elif widget_name == "poc_num":
                        widget.setValue(20)
                    elif widget_name == "max_retries":
                        widget.setValue(3)
                elif isinstance(widget, QComboBox):
                    widget.setCurrentIndex(0)
                elif isinstance(widget, QCheckBox):
                    widget.setChecked(False)
        
        # 恢复一些默认值
        self.scan_ports.setText("21,22,80,443,3306,6379,8080,8443")
        self.output_file.setText("result.txt")
        self.scan_mode.setText("all")
        self.search_edit.clear()
        
        # 清除输出
        self.output_text.clear()
    
    def read_output(self):
        """读取进程输出"""
        if self.scan_process:
            output = self.scan_process.readAllStandardOutput().data().decode()
            self.output_text.append(output)
            # 自动滚动到底部
            self.output_text.moveCursor(self.output_text.textCursor().End)
    
    def scan_finished(self, exit_code, exit_status):
        """扫描完成"""
        self.output_text.append(f"\n扫描完成，退出码: {exit_code}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def process_error(self, error):
        """处理进程错误"""
        self.output_text.append(f"\n进程错误: {error}")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
    
    def search_output(self, text):
        """搜索输出结果"""
        if not text:
            self.output_text.moveCursor(self.output_text.textCursor().Start)
            return
        
        cursor = self.output_text.textCursor()
        cursor.movePosition(self.output_text.textCursor().Start)
        
        found = self.output_text.find(text, cursor)
        if found:
            self.output_text.setTextCursor(cursor)
    
    def copy_output(self):
        """复制输出结果"""
        self.output_text.selectAll()
        self.output_text.copy()
    
    def clear_output(self):
        """清空输出结果"""
        self.output_text.clear()
    
    def save_output(self):
        """保存输出结果"""
        file_path, _ = QFileDialog.getSaveFileName(self, "保存结果", "fscan_result.txt", "Text Files (*.txt);;All Files (*)")
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(self.output_text.toPlainText())

if __name__ == "__main__":
    import traceback
    try:
        app = QApplication(sys.argv)
        gui = FscanGUI()
        gui.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")
