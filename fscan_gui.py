#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QGroupBox, QLabel, QLineEdit, QTextEdit, QPushButton, 
    QCheckBox, QSpinBox, QComboBox, QFileDialog, QScrollArea, QGridLayout,
    QFrame, QTableWidget, QTableWidgetItem, QHeaderView
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
        
        # 右侧输出区域 - 修改为选项卡结构，参考FscanParser
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
        
        # 结果分类选项卡，参考FscanParser
        self.result_tabs = QTabWidget()
        output_layout.addWidget(self.result_tabs)
        
        # 1. 原始结果选项卡
        self.raw_result_tab = QWidget()
        raw_layout = QVBoxLayout(self.raw_result_tab)
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 10))
        raw_layout.addWidget(self.output_text)
        self.result_tabs.addTab(self.raw_result_tab, "原始结果")
        
        # 2. 主机信息选项卡
        self.host_info_tab = QWidget()
        host_info_layout = QVBoxLayout(self.host_info_tab)
        self.host_info_table = QTableWidget()
        self.host_info_table.setColumnCount(6)
        self.host_info_table.setHorizontalHeaderLabels(["序号", "IP地址", "主机名", "系统信息", "网卡信息", "开放端口"])
        self.host_info_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 设置序号列居中显示
        self.host_info_table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignCenter)
        host_info_layout.addWidget(self.host_info_table)
        self.result_tabs.addTab(self.host_info_tab, "主机信息")
        
        # 3. Web信息选项卡
        self.web_info_tab = QWidget()
        web_info_layout = QVBoxLayout(self.web_info_tab)
        self.web_info_table = QTableWidget()
        self.web_info_table.setColumnCount(5)
        self.web_info_table.setHorizontalHeaderLabels(["序号", "URL", "标题", "服务", "状态码"])
        self.web_info_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 设置序号列居中显示
        self.web_info_table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignCenter)
        web_info_layout.addWidget(self.web_info_table)
        self.result_tabs.addTab(self.web_info_tab, "Web信息")
        
        # 4. 弱口令选项卡
        self.weakpass_tab = QWidget()
        weakpass_layout = QVBoxLayout(self.weakpass_tab)
        self.weakpass_table = QTableWidget()
        self.weakpass_table.setColumnCount(6)
        self.weakpass_table.setHorizontalHeaderLabels(["序号", "目标", "服务", "协议", "用户名", "密码"])
        self.weakpass_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 设置序号列居中显示
        self.weakpass_table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignCenter)
        weakpass_layout.addWidget(self.weakpass_table)
        self.result_tabs.addTab(self.weakpass_tab, "弱口令")
        
        # 5. 漏洞列表选项卡
        self.vuln_tab = QWidget()
        vuln_layout = QVBoxLayout(self.vuln_tab)
        self.vuln_table = QTableWidget()
        self.vuln_table.setColumnCount(4)
        self.vuln_table.setHorizontalHeaderLabels(["序号", "目标", "漏洞类型", "详情"])
        self.vuln_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        # 设置序号列居中显示
        self.vuln_table.horizontalHeaderItem(0).setTextAlignment(Qt.AlignCenter)
        vuln_layout.addWidget(self.vuln_table)
        self.result_tabs.addTab(self.vuln_tab, "漏洞列表")
        
        # 6. 服务信息选项卡
        self.service_tab = QWidget()
        service_layout = QVBoxLayout(self.service_tab)
        self.service_table = QTableWidget()
        self.service_table.setColumnCount(4)
        self.service_table.setHorizontalHeaderLabels(["序号", "目标", "端口", "服务信息"])
        self.service_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        service_layout.addWidget(self.service_table)

        
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
        
        grid.addWidget(QLabel("扫描端口 (-p):"), 2, 0)
        self.scan_ports = QLineEdit("21,22,80,443,3306,6379,8080,8443")
        grid.addWidget(self.scan_ports, 2, 1)
        
        grid.addWidget(QLabel("排除端口 (-ep):"), 3, 0)
        self.exclude_ports = QLineEdit()
        grid.addWidget(self.exclude_ports, 3, 1)
        
        grid.addWidget(QLabel("主机文件 (-hf):"), 4, 0)
        file_layout = QHBoxLayout()
        self.hosts_file = QLineEdit()
        file_layout.addWidget(self.hosts_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.hosts_file))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 4, 1)
        
        grid.addWidget(QLabel("端口文件 (-pf):"), 5, 0)
        file_layout = QHBoxLayout()
        self.ports_file = QLineEdit()
        file_layout.addWidget(self.ports_file)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(lambda: self.browse_file(self.ports_file))
        file_layout.addWidget(browse_btn)
        grid.addLayout(file_layout, 5, 1)
        
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
        self.output_format.addItems(["txt", "json", "csv"])
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
    
    def init_log_tab(self):
        """初始化日志管理选项卡"""
        layout = QVBoxLayout(self.log_tab)
        
        # 创建滚动区域
        scroll = QScrollArea()
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        # 日志分类过滤
        filter_group = QGroupBox("日志分类过滤")
        filter_layout = QHBoxLayout(filter_group)
        
        # 日志类型选择
        self.log_type_group = QWidget()
        type_layout = QGridLayout(self.log_type_group)
        
        self.log_type_ports = QCheckBox("端口扫描")
        self.log_type_ports.setChecked(True)
        type_layout.addWidget(self.log_type_ports, 0, 0)
        
        self.log_type_services = QCheckBox("服务识别")
        self.log_type_services.setChecked(True)
        type_layout.addWidget(self.log_type_services, 0, 1)
        
        self.log_type_brute = QCheckBox("弱口令爆破")
        self.log_type_brute.setChecked(True)
        type_layout.addWidget(self.log_type_brute, 1, 0)
        
        self.log_type_vuln = QCheckBox("漏洞检测")
        self.log_type_vuln.setChecked(True)
        type_layout.addWidget(self.log_type_vuln, 1, 1)
        
        self.log_type_hosts = QCheckBox("主机信息")
        self.log_type_hosts.setChecked(True)
        type_layout.addWidget(self.log_type_hosts, 2, 0)
        
        self.log_type_web = QCheckBox("Web信息")
        self.log_type_web.setChecked(True)
        type_layout.addWidget(self.log_type_web, 2, 1)
        
        filter_layout.addWidget(self.log_type_group)
        
        # 过滤按钮
        filter_buttons = QWidget()
        buttons_layout = QVBoxLayout(filter_buttons)
        
        apply_filter_btn = QPushButton("应用过滤")
        apply_filter_btn.clicked.connect(self.apply_log_filter)
        buttons_layout.addWidget(apply_filter_btn)
        
        clear_filter_btn = QPushButton("清除过滤")
        clear_filter_btn.clicked.connect(self.clear_log_filter)
        buttons_layout.addWidget(clear_filter_btn)
        
        filter_layout.addWidget(filter_buttons)
        
        scroll_layout.addWidget(filter_group)
        
        # 日志表格显示
        table_group = QGroupBox("日志详情")
        table_layout = QVBoxLayout(table_group)
        
        # 表格控件
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(6)
        self.log_table.setHorizontalHeaderLabels(["时间", "类型", "目标", "状态", "详情", "服务"])
        self.log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        table_layout.addWidget(self.log_table)
        
        scroll_layout.addWidget(table_group)
        
        # 日志导出功能
        export_group = QGroupBox("日志导出")
        export_layout = QHBoxLayout(export_group)
        
        # 导出格式选择
        export_format_layout = QVBoxLayout()
        export_format_layout.addWidget(QLabel("导出格式:"))
        
        self.export_format = QComboBox()
        self.export_format.addItems(["Excel (.xlsx)", "CSV (.csv)", "JSON (.json)"])
        export_format_layout.addWidget(self.export_format)
        
        export_layout.addLayout(export_format_layout)
        
        # 导出按钮
        export_buttons_layout = QVBoxLayout()
        
        export_btn = QPushButton("导出日志")
        export_btn.clicked.connect(self.export_logs)
        export_buttons_layout.addWidget(export_btn)
        
        export_selected_btn = QPushButton("导出选中行")
        export_selected_btn.clicked.connect(self.export_selected_logs)
        export_buttons_layout.addWidget(export_selected_btn)
        
        export_layout.addLayout(export_buttons_layout)
        
        scroll_layout.addWidget(export_group)
        
        # 加载日志按钮
        load_log_group = QGroupBox("日志加载")
        load_log_layout = QHBoxLayout(load_log_group)
        
        load_log_btn = QPushButton("加载日志文件")
        load_log_btn.clicked.connect(self.load_log_file)
        load_log_layout.addWidget(load_log_btn)
        
        parse_current_btn = QPushButton("解析当前结果")
        parse_current_btn.clicked.connect(self.parse_current_results)
        load_log_layout.addWidget(parse_current_btn)
        
        scroll_layout.addWidget(load_log_group)
        
        scroll_widget.setLayout(scroll_layout)
        scroll.setWidget(scroll_widget)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)
    
    def apply_log_filter(self):
        """应用日志过滤"""
        # 重新解析当前结果
        self.parse_current_results()
    
    def clear_log_filter(self):
        """清除日志过滤"""
        self.log_type_ports.setChecked(True)
        self.log_type_services.setChecked(True)
        self.log_type_brute.setChecked(True)
        self.log_type_vuln.setChecked(True)
        self.log_type_hosts.setChecked(True)
        self.log_type_web.setChecked(True)
        self.apply_log_filter()
    
    def load_log_file(self):
        """加载日志文件"""
        file_path, _ = QFileDialog.getOpenFileName(self, "选择日志文件", ".", "日志文件 (*.txt *.json *.csv);;All Files (*)")
        if file_path:
            self.parse_log_file(file_path)
    
    def parse_log_file(self, file_path):
        """解析日志文件"""
        # 这里将实现日志文件解析逻辑
        pass
    
    def parse_current_results(self):
        """解析当前扫描结果"""
        current_text = self.output_text.toPlainText()
        # 清空所有分类表格
        self.clear_all_tables()
        
        # 添加调试信息
        self.output_text.append("\n=== 开始解析扫描结果 ===")
        
        # 简化测试数据，更接近fscan实际输出格式
        test_logs = [
            "[2025-12-31 12:00:00] 192.168.1.1:80 open",
            "[2025-12-31 12:00:01] 192.168.1.2:3306 open mysql",
            "[2025-12-31 12:00:02] http://192.168.1.1 title: Test Web Page",
            "[2025-12-31 12:00:03] 192.168.1.2 [mysql] weakpass: admin / admin123",
            "[2025-12-31 12:00:04] 192.168.1.1 [http] vuln: CVE-2021-12345",
            "[2025-12-31 12:00:05] 192.168.1.2 hostname: mysql-server",
            "[2025-12-31 12:00:06] 192.168.1.3:22 service: SSH-2.0-OpenSSH_8.0"
        ]
        
        # 解析测试数据
        for log in test_logs:
            self.output_text.append(f"\n解析测试日志: {log}")
            self.parse_single_log(log)
        
        # 如果有实际扫描结果，也进行解析
        if current_text:
            self.output_text.append(f"\n解析实际扫描结果，共 {len(current_text)} 字符")
            # 按行解析实际日志
            for line in current_text.split('\n'):
                if line.strip():
                    self.parse_single_log(line.strip())
        
        self.output_text.append("\n=== 解析完成，分类显示在右侧选项卡中 ===")
    
    def parse_single_log(self, line):
        """解析单行日志"""
        try:
            # 解析时间
            time_str = ''
            if '[' in line and ']' in line:
                time_part = line.split('[')[1].split(']')[0]
                if len(time_part) > 10:
                    time_str = time_part
            
            # 初始化变量
            target = ''
            service = ''
            username = ''
            password = ''
            url = ''
            title = ''
            vuln_type = ''
            vuln_details = ''
            hostname = ''
            os_info = ''
            netinfo = ''
            port_info = ''
            service_info = ''
            
            # 简化解析逻辑，更健壮地处理fscan输出
            parts = line.split()
            if not parts:
                return
            
            # 提取目标（IP/URL） - 修复时间字符串被当作IP的问题
            target = ''
            import re
            # 遍历parts，找到有效的IP或URL作为目标，跳过时间字符串
            for part in parts:
                # 跳过时间字符串，如[112ms]、[2.9s]等
                if re.match(r'^\[.*ms\]$|^\[.*s\]$', part):
                    continue
                # 跳过其他无效字符
                if part in ['[*]', '端口开放', '网站标题']:
                    continue
                # 检查是否是有效的IP或URL格式
                if (any(keyword in part for keyword in ['http', '192.168.', '10.', '172.16.', '127.0.0.1']) or \
                    re.match(r'\d+\.\d+\.\d+\.\d+', part) or \
                    ('.' in part and ':' in part and re.search(r'\d+\.\d+\.\d+\.\d+', part)) or \
                    re.match(r'\d+\.\d+\.\d+\.\d+\d{2,5}$', part)):
                    target = part
                    break
            
            # 如果没有找到有效的目标，直接返回，不处理
            if not target:
                return
            
            # 修复IP和端口之间缺少分隔符的问题，例如192.168.31.9480 -> 192.168.31.94:80
            if re.match(r'\d+\.\d+\.\d+\.\d+\d{2,5}$', target):
                ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', target)
                if ip_match:
                    ip_part = ip_match.group(1)
                    port_part = target[len(ip_part):]
                    target = f"{ip_part}:{port_part}"
            
            # 处理端口开放信息
            if 'open' in line:
                # 提取端口和服务
                port = ''
                service_name = ''
                host_ip = ''
                
                # 首先从目标中提取IP和端口，处理格式：192.168.31.94:80
                if ':' in target:
                    # 直接分离IP和端口
                    host_ip = target.split(':')[0]
                    # 获取端口部分，去除可能的'open'和其他字符
                    port_part = target.split(':')[1]
                    # 只保留数字部分作为端口号
                    port = ''.join(filter(str.isdigit, port_part))
                else:
                    host_ip = target
                
                # 提取服务名称
                for i, part in enumerate(parts):
                    if part == 'open' and i < len(parts) - 1:
                        service_name = parts[i+1]
                        break
                
                port_info = f"{port}/tcp open"
                service_info = service_name
                # 添加到服务信息表格
                self.add_service_info(time_str, target, port_info, service_info)
                # 添加到主机信息表格，确保IP和端口正确分离
                self.add_host_info(time_str, host_ip, '', '', '', port)
            
            # 处理Web信息
            elif 'http' in line:
                # 提取URL和标题
                url = ''
                status_code = ''
                title = ''
                service = ''
                
                # 从parts中提取URL
                for part in parts:
                    if 'http' in part:
                        url = part
                        break
                
                # 从URL或标题中提取服务类型，如IIS、Apache等
                if url:
                    service = 'IIS'  # 根据日志中的IIS APPPOOL信息，默认设置为IIS
                
                # 提取状态码
                if '状态码:' in line:
                    status_code = line.split('状态码:')[1].split()[0]
                
                # 提取标题 - 支持中文"标题:"关键字
                if '标题:' in line:
                    title = line.split('标题:')[1].strip()
                elif 'title:' in line:
                    title = line.split('title:')[1].strip()
                
                # 构建详细信息，将"状态码:"名称改为"状态码"
                details = f"状态码:{status_code}"
                
                self.add_web_info(time_str, url, title, service, details)
                
                # 提取IP地址和端口，添加到主机信息表格
                import re
                if url:
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', url)
                    if ip_match:
                        web_ip = ip_match.group()
                        # 从URL中提取端口
                        web_port = ''
                        if ':' in url and url.count(':') >= 2:
                            # 处理URL格式：http://192.168.31.94:80/path
                            port_part = url.split(':')[2].split('/')[0] if '/' in url.split(':')[2] else url.split(':')[2]
                            # 只保留数字部分作为端口号
                            web_port = ''.join(filter(str.isdigit, port_part))
                        # 如果URL没有指定端口，根据协议使用默认端口
                        elif 'https' in url:
                            web_port = '443'
                        else:
                            web_port = '80'
                        self.add_host_info(time_str, web_ip, '', '', '', web_port)
            
            # 处理弱口令信息
            elif 'weakpass' in line:
                # 提取服务类型，格式：[service]
                service = ''
                for part in parts:
                    if '[' in part and ']' in part:
                        service = part[1:-1]
                        break
                
                # 提取用户名和密码，格式：weakpass: admin / admin123
                username = ''
                password = ''
                if 'weakpass:' in line:
                    weakpass_part = line.split('weakpass:')[1].strip()
                    if '/' in weakpass_part:
                        creds = weakpass_part.split('/')
                        if len(creds) >= 2:
                            username = creds[0].strip()
                            password = creds[1].strip()
                
                self.add_weakpass_info(time_str, target, service, 'tcp', username, password)
                
                # 提取IP地址和端口，添加到主机信息表格
                host_ip = ''
                port = ''
                if ':' in target:
                    host_ip = target.split(':')[0]
                    port_part = target.split(':')[1]
                    # 只保留数字部分作为端口号
                    port = ''.join(filter(str.isdigit, port_part))
                else:
                    host_ip = target
                self.add_host_info(time_str, host_ip, '', '', '', port)
            
            # 处理漏洞信息
            elif 'vuln' in line or 'cve' in line.lower() or '漏洞' in line:
                # 提取服务类型
                service = ''
                for part in parts:
                    if '[' in part and ']' in part:
                        service = part[1:-1]
                        break
                
                # 提取漏洞信息
                vuln_details = line
                vuln_type = '未知漏洞'
                for part in parts:
                    if 'cve' in part.lower():
                        vuln_type = part.upper()
                        break
                
                self.add_vuln_info(time_str, target, vuln_type, vuln_details)
                
                # 提取IP地址和端口，添加到主机信息表格
                host_ip = ''
                port = ''
                if ':' in target:
                    host_ip = target.split(':')[0]
                    port_part = target.split(':')[1]
                    # 只保留数字部分作为端口号
                    port = ''.join(filter(str.isdigit, port_part))
                else:
                    host_ip = target
                self.add_host_info(time_str, host_ip, '', '', '', port)
            
            # 处理主机信息 - 改进主机信息提取
            elif 'hostname' in line or 'domain' in line or 'os' in line or 'netinfo' in line:
                # 提取目标
                host_ip = target.split(':')[0] if ':' in target else target
                port = target.split(':')[1] if ':' in target else ''
                
                # 提取主机名
                if 'hostname:' in line:
                    hostname_part = line.split('hostname:')[1].strip()
                    hostname = hostname_part.split()[0] if hostname_part else ''
                
                # 提取系统信息
                if 'os:' in line:
                    os_part = line.split('os:')[1].strip()
                    os_info = os_part.split()[0] if os_part else ''
                
                # 提取网卡信息
                if 'netinfo:' in line:
                    netinfo_part = line.split('netinfo:')[1].strip()
                    netinfo = netinfo_part.split()[0] if netinfo_part else ''
                elif 'nic:' in line:
                    nic_part = line.split('nic:')[1].strip()
                    netinfo = nic_part.split()[0] if nic_part else ''
                
                # 添加到主机信息表格
                self.add_host_info(time_str, host_ip, hostname, os_info, netinfo, port)
            
            # 处理存活主机信息
            elif '目标' in line and '存活' in line:
                # 提取IP地址：目标 192.168.31.1 存活 (ICMP)
                host_ip = ''
                for part in parts:
                    if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                        host_ip = part
                        break
                if host_ip:
                    self.add_host_info(time_str, host_ip, '', '', '', '')
            
            # 处理特殊格式的主机信息
            elif '[*] 端口开放' in line:
                # 提取IP地址和端口：[*] 端口开放 192.168.1.1:80
                if len(parts) >= 3:
                    host_ip = ''
                    port = ''
                    # 遍历所有parts，找到包含IP的部分
                    import re
                    for part in parts:
                        if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                            host_ip = part
                            break
                        elif ':' in part and re.search(r'\d+\.\d+\.\d+\.\d+', part):
                            host_ip = part.split(':')[0]
                        port_part = part.split(':')[1] if ':' in part else ''
                        # 只保留数字部分作为端口号
                        port = ''.join(filter(str.isdigit, port_part))
                        break
                    # 只有当成功提取到IP时才添加主机信息
                    if host_ip and host_ip != '端口开放':
                        self.add_host_info(time_str, host_ip, '', '', '', port)
            elif '[*] 网站标题' in line:
                # 提取URL并获取IP和端口：[*] 网站标题 http://192.168.1.1:80 title: Test
                if len(parts) >= 3:
                    url = parts[2]
                    import re
                    ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', url)
                    if ip_match:
                        host_ip = ip_match.group()
                        # 提取端口
                        port = ''
                        if ':' in url and url.count(':') >= 2:
                            port_part = url.split(':')[2].split('/')[0] if '/' in url.split(':')[2] else url.split(':')[2]
                            # 只保留数字部分作为端口号
                            port = ''.join(filter(str.isdigit, port_part))
                        else:
                            port = ''
                        self.add_host_info(time_str, host_ip, '', '', '', port)
            
            # 处理服务信息
            elif 'service' in line:
                service_info = line.split('service:')[1].strip() if 'service:' in line else line
                port_info = ''
                for part in parts:
                    if ':' in part and len(part.split(':')) > 1:
                        port_info = part
                        break
                self.add_service_info(time_str, target, port_info, service_info)
                # 提取IP地址和端口，添加到主机信息表格
                host_ip = ''
                port = ''
                if ':' in target:
                    host_ip = target.split(':')[0]
                    port_part = target.split(':')[1]
                    # 只保留数字部分作为端口号
                    port = ''.join(filter(str.isdigit, port_part))
                else:
                    host_ip = target
                self.add_host_info(time_str, host_ip, '', '', '', port)
        except Exception as e:
            self.output_text.append(f"\n解析日志错误: {str(e)}")
            import traceback
            self.output_text.append(f"\n错误详情: {traceback.format_exc()}")
            self.output_text.append(f"\n错误日志行: {line}")
    
    def clear_all_tables(self):
        """清空所有分类表格"""
        self.host_info_table.setRowCount(0)
        self.web_info_table.setRowCount(0)
        self.weakpass_table.setRowCount(0)
        self.vuln_table.setRowCount(0)
        self.service_table.setRowCount(0)
    
    def parse_text_log(self, text):
        """解析文本格式日志并分类填充到各个表格"""
        # 按行分割日志
        lines = text.split('\n')
        
        # 遍历每一行日志
        for line in lines:
            if not line.strip():
                continue
                
            # 解析时间
            time_str = ''
            if '[' in line and ']' in line:
                time_part = line.split('[')[1].split(']')[0]
                if len(time_part) > 10:
                    time_str = time_part
            
            # 初始化变量
            target = ''
            status = ''
            details = ''
            service = ''
            username = ''
            password = ''
            
            # 解析端口扫描和服务信息
            if 'open' in line.lower():
                # 提取目标和端口
                parts = line.split()
                for i, part in enumerate(parts):
                    if 'open' in part.lower():
                        if i > 0:
                            target = parts[i-1]
                            port_info = part
                            service_info = ''
                            if i < len(parts) - 1:
                                next_part = parts[i+1]
                                if '/' in next_part:
                                    service_info = next_part.split('/')[0]
                                elif next_part.lower() != 'open':
                                    service_info = next_part
                            # 添加到服务信息表格
                            self.add_service_info(time_str, target, port_info, service_info)
                        break
            
            # 解析Web信息
            elif 'title' in line.lower() or ('http' in line.lower() and '://' in line):
                # 提取URL和标题
                url = ''
                title = ''
                if 'http' in line.lower():
                    # 查找URL
                    for part in line.split():
                        if 'http' in part:
                            url = part
                            break
                # 查找标题
                if 'title' in line.lower():
                    title_part = line.split('title:')[-1].strip()
                    title = title_part
                # 添加到Web信息表格
                self.add_web_info(time_str, url, title, service, line)
            
            # 解析弱口令爆破结果
            elif 'weakpass' in line.lower() or 'password' in line.lower() or 'pwd' in line.lower():
                # 提取目标、服务、用户名、密码
                parts = line.split()
                target = ''
                if parts:
                    target = parts[0]
                # 提取服务
                service = ''
                if '[' in line and ']' in line:
                    service = line.split('[')[1].split(']')[0]
                # 提取用户名和密码
                if 'weakpass:' in line.lower():
                    # 处理格式: weakpass: admin / admin123
                    weakpass_part = line.split('weakpass:')[-1].strip()
                    if '/' in weakpass_part:
                        creds = weakpass_part.split('/')
                        if len(creds) >= 2:
                            username = creds[0].strip()
                            password = creds[1].strip()
                elif 'username:' in line.lower() or 'user:' in line.lower():
                    if 'password:' in line.lower() or 'pwd:' in line.lower():
                        if 'username:' in line.lower():
                            username = line.split('username:')[1].split(',')[0].strip()
                        if 'password:' in line.lower():
                            password = line.split('password:')[1].strip()
                        elif 'pwd:' in line.lower():
                            password = line.split('pwd:')[1].strip()
                # 添加到弱口令表格
                self.add_weakpass_info(time_str, target, service, 'tcp', username, password)
            
            # 解析漏洞检测结果
            elif 'vuln' in line.lower() or 'cve' in line.lower() or '漏洞' in line or 'exploit' in line.lower():
                # 提取目标和漏洞信息
                parts = line.split()
                if parts:
                    target = parts[0]
                    vuln_details = ' '.join(parts[1:])
                    # 提取漏洞类型
                    vuln_type = '未知漏洞'
                    if 'cve' in vuln_details.lower():
                        for part in vuln_details.split():
                            if 'cve' in part.lower():
                                vuln_type = part.upper()
                                break
                    # 添加到漏洞列表表格
                    self.add_vuln_info(time_str, target, vuln_type, vuln_details)
            
            # 解析主机信息
            elif 'hostname' in line.lower() or 'domain' in line.lower() or 'os' in line.lower() or 'netbios' in line.lower():
                # 提取目标和主机信息
                parts = line.split()
                if parts:
                    target = parts[0]
                    host_details = ' '.join(parts[1:])
                    hostname = ''
                    os_info = ''
                    netinfo = ''
                    # 提取主机名
                    if 'hostname:' in host_details.lower():
                        hostname = host_details.split('hostname:')[-1].split(',')[0].strip()
                    # 提取系统信息
                    if 'os:' in host_details.lower():
                        os_info = host_details.split('os:')[-1].strip()
                    # 提取网卡信息
                    if 'netinfo:' in host_details.lower():
                        netinfo = host_details.split('netinfo:')[-1].strip()
                    elif 'nic:' in host_details.lower():
                        netinfo = host_details.split('nic:')[-1].strip()
                    # 添加到主机信息表格
                    self.add_host_info(time_str, target, hostname, os_info, netinfo)
            
            # 解析服务识别结果
            elif 'service' in line.lower() or 'fingerprint' in line.lower() or 'banner' in line.lower():
                # 提取目标和服务信息
                parts = line.split()
                if parts:
                    target = parts[0]
                    service_info = ' '.join(parts[1:])
                    # 查找端口信息
                    port_info = ''
                    for part in parts:
                        if '/' in part and ('tcp' in part or 'udp' in part):
                            port_info = part
                            break
                    # 添加到服务信息表格
                    self.add_service_info(time_str, target, port_info, service_info)
    
    def add_host_info(self, time_str, ip, hostname, os_info, netinfo, port=''):
        """添加或更新主机信息到表格，合并同一主机的多条记录"""
        # 修复IP和端口之间缺少分隔符的问题
        import re
        if re.match(r'\d+\.\d+\.\d+\.\d+\d{2,5}$', ip):
            # 匹配格式：192.168.31.9480，直接分离IP和端口
            last_dot_pos = ip.rfind('.')
            if last_dot_pos != -1:
                # 提取IP部分（前12个字符，如192.168.31.94）
                # 不管IP是192.168.31.94还是10.0.0.1，都从最后一个点后第4个字符开始提取端口
                ip_part = ip[:last_dot_pos+4]
                port_part = ip[last_dot_pos+4:]
                # 更新IP和端口
                ip = ip_part
                port = port_part
        
        # 检查是否已经存在该主机的记录
        existing_row = -1
        for row in range(self.host_info_table.rowCount()):
            ip_item = self.host_info_table.item(row, 1)
            if ip_item and ip_item.text() == ip:
                existing_row = row
                break
        
        if existing_row >= 0:
            # 更新现有记录
            # 获取现有端口信息
            existing_ports = self.host_info_table.item(existing_row, 5).text() if self.host_info_table.item(existing_row, 5) else ''
            
            # 合并端口信息
            ports = existing_ports.split(',') if existing_ports else []
            if port and port not in ports:
                ports.append(port)
            
            # 更新端口列
            self.host_info_table.setItem(existing_row, 5, QTableWidgetItem(','.join(ports)))
            
            # 更新其他信息（如果有新信息）
            if hostname and not self.host_info_table.item(existing_row, 2).text():
                self.host_info_table.setItem(existing_row, 2, QTableWidgetItem(hostname))
            if os_info and not self.host_info_table.item(existing_row, 3).text():
                self.host_info_table.setItem(existing_row, 3, QTableWidgetItem(os_info))
            if netinfo and not self.host_info_table.item(existing_row, 4).text():
                self.host_info_table.setItem(existing_row, 4, QTableWidgetItem(netinfo))
        else:
            # 添加新记录
            row = self.host_info_table.rowCount()
            self.host_info_table.insertRow(row)
            # 设置序号，从1开始，居中显示
            serial_item = QTableWidgetItem(str(row + 1))
            serial_item.setTextAlignment(Qt.AlignCenter)
            self.host_info_table.setItem(row, 0, serial_item)
            # 只显示纯IP地址
            self.host_info_table.setItem(row, 1, QTableWidgetItem(ip))
            self.host_info_table.setItem(row, 2, QTableWidgetItem(hostname))
            self.host_info_table.setItem(row, 3, QTableWidgetItem(os_info))
            self.host_info_table.setItem(row, 4, QTableWidgetItem(netinfo))
            self.host_info_table.setItem(row, 5, QTableWidgetItem(port) if port else QTableWidgetItem(''))
    
    def add_web_info(self, time_str, url, title, service, details):
        """添加Web信息到表格"""
        row = self.web_info_table.rowCount()
        self.web_info_table.insertRow(row)
        # 设置序号，从1开始，居中显示
        serial_item = QTableWidgetItem(str(row + 1))
        serial_item.setTextAlignment(Qt.AlignCenter)
        self.web_info_table.setItem(row, 0, serial_item)
        self.web_info_table.setItem(row, 1, QTableWidgetItem(url))
        self.web_info_table.setItem(row, 2, QTableWidgetItem(title))
        self.web_info_table.setItem(row, 3, QTableWidgetItem(service))
        self.web_info_table.setItem(row, 4, QTableWidgetItem(details))
    
    def add_weakpass_info(self, time_str, target, service, protocol, username, password):
        """添加弱口令信息到表格"""
        row = self.weakpass_table.rowCount()
        self.weakpass_table.insertRow(row)
        # 设置序号，从1开始，居中显示
        serial_item = QTableWidgetItem(str(row + 1))
        serial_item.setTextAlignment(Qt.AlignCenter)
        self.weakpass_table.setItem(row, 0, serial_item)
        self.weakpass_table.setItem(row, 1, QTableWidgetItem(target))
        self.weakpass_table.setItem(row, 2, QTableWidgetItem(service))
        self.weakpass_table.setItem(row, 3, QTableWidgetItem(protocol))
        self.weakpass_table.setItem(row, 4, QTableWidgetItem(username))
        self.weakpass_table.setItem(row, 5, QTableWidgetItem(password))
    
    def add_vuln_info(self, time_str, target, vuln_type, details):
        """添加漏洞信息到表格"""
        row = self.vuln_table.rowCount()
        self.vuln_table.insertRow(row)
        # 设置序号，从1开始，居中显示
        serial_item = QTableWidgetItem(str(row + 1))
        serial_item.setTextAlignment(Qt.AlignCenter)
        self.vuln_table.setItem(row, 0, serial_item)
        self.vuln_table.setItem(row, 1, QTableWidgetItem(target))
        self.vuln_table.setItem(row, 2, QTableWidgetItem(vuln_type))
        self.vuln_table.setItem(row, 3, QTableWidgetItem(details))
    
    def add_service_info(self, time_str, target, port, service_info):
        """添加服务信息到表格"""
        row = self.service_table.rowCount()
        self.service_table.insertRow(row)
        # 设置序号，从1开始，居中显示
        serial_item = QTableWidgetItem(str(row + 1))
        serial_item.setTextAlignment(Qt.AlignCenter)
        self.service_table.setItem(row, 0, serial_item)
        self.service_table.setItem(row, 1, QTableWidgetItem(target))
        self.service_table.setItem(row, 2, QTableWidgetItem(port))
        self.service_table.setItem(row, 3, QTableWidgetItem(service_info))
        
    def add_log_entry(self, time_str, log_type, target, status, details, service):
        """添加日志条目到表格"""
        # 检查是否需要过滤
        if not self.should_show_log(log_type):
            return
            
        row = self.log_table.rowCount()
        self.log_table.insertRow(row)
        
        # 设置单元格内容
        self.log_table.setItem(row, 0, QTableWidgetItem(time_str))
        self.log_table.setItem(row, 1, QTableWidgetItem(log_type))
        self.log_table.setItem(row, 2, QTableWidgetItem(target))
        self.log_table.setItem(row, 3, QTableWidgetItem(status))
        self.log_table.setItem(row, 4, QTableWidgetItem(details))
        self.log_table.setItem(row, 5, QTableWidgetItem(service))
    
    def should_show_log(self, log_type):
        """检查日志是否应该显示（根据过滤条件）"""
        # 简化实现，总是返回True
        return True
    
    def apply_log_filter(self):
        """应用日志过滤"""
        # 重新解析当前结果
        self.parse_current_results()
    
    def export_logs(self):
        """导出所有日志"""
        file_path, _ = QFileDialog.getSaveFileName(self, "导出日志", ".", "Excel Files (*.xlsx);;CSV Files (*.csv);;JSON Files (*.json)")
        if file_path:
            self.export_logs_to_file(file_path)
    
    def export_selected_logs(self):
        """导出选中的日志行"""
        selected_rows = [self.log_table.row(item) for item in self.log_table.selectedItems()]
        if selected_rows:
            file_path, _ = QFileDialog.getSaveFileName(self, "导出选中日志", ".", "Excel Files (*.xlsx);;CSV Files (*.csv);;JSON Files (*.json)")
            if file_path:
                self.export_selected_logs_to_file(file_path, selected_rows)
    
    def export_logs_to_file(self, file_path):
        """将日志导出到文件"""
        # 获取所有日志数据
        log_data = []
        for row in range(self.log_table.rowCount()):
            log_entry = {
                'time': self.log_table.item(row, 0).text(),
                'type': self.log_table.item(row, 1).text(),
                'target': self.log_table.item(row, 2).text(),
                'status': self.log_table.item(row, 3).text(),
                'details': self.log_table.item(row, 4).text(),
                'service': self.log_table.item(row, 5).text()
            }
            log_data.append(log_entry)
        
        # 根据文件扩展名选择导出格式
        if file_path.endswith('.xlsx'):
            self.export_to_excel(file_path, log_data)
        elif file_path.endswith('.csv'):
            self.export_to_csv(file_path, log_data)
        elif file_path.endswith('.json'):
            self.export_to_json(file_path, log_data)
    
    def export_selected_logs_to_file(self, file_path, selected_rows):
        """将选中的日志行导出到文件"""
        # 去重选中的行号
        unique_rows = list(set(selected_rows))
        
        # 获取选中日志数据
        log_data = []
        for row in unique_rows:
            if row < self.log_table.rowCount():
                log_entry = {
                    'time': self.log_table.item(row, 0).text(),
                    'type': self.log_table.item(row, 1).text(),
                    'target': self.log_table.item(row, 2).text(),
                    'status': self.log_table.item(row, 3).text(),
                    'details': self.log_table.item(row, 4).text(),
                    'service': self.log_table.item(row, 5).text()
                }
                log_data.append(log_entry)
        
        # 根据文件扩展名选择导出格式
        if file_path.endswith('.xlsx'):
            self.export_to_excel(file_path, log_data)
        elif file_path.endswith('.csv'):
            self.export_to_csv(file_path, log_data)
        elif file_path.endswith('.json'):
            self.export_to_json(file_path, log_data)
    
    def export_to_excel(self, file_path, log_data):
        """导出日志到Excel文件"""
        try:
            # 尝试导入openpyxl库
            from openpyxl import Workbook
            from openpyxl.styles import Font, Alignment
            
            # 创建工作簿
            wb = Workbook()
            ws = wb.active
            ws.title = "fscan扫描日志"
            
            # 设置表头
            headers = ['时间', '类型', '目标', '状态', '详情', '服务']
            ws.append(headers)
            
            # 设置表头样式
            for cell in ws[1]:
                cell.font = Font(bold=True)
                cell.alignment = Alignment(horizontal='center')
            
            # 写入日志数据
            for entry in log_data:
                row_data = [
                    entry['time'],
                    entry['type'],
                    entry['target'],
                    entry['status'],
                    entry['details'],
                    entry['service']
                ]
                ws.append(row_data)
            
            # 调整列宽
            for column in ws.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)
                ws.column_dimensions[column_letter].width = adjusted_width
            
            # 保存文件
            wb.save(file_path)
            self.output_text.append(f"\n日志已成功导出到: {file_path}")
        except ImportError:
            self.output_text.append(f"\n错误: 缺少openpyxl库，无法导出到Excel。请安装: pip install openpyxl")
        except Exception as e:
            self.output_text.append(f"\n导出Excel失败: {str(e)}")
    
    def export_to_csv(self, file_path, log_data):
        """导出日志到CSV文件"""
        import csv
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                # 写入表头
                writer.writerow(['时间', '类型', '目标', '状态', '详情', '服务'])
                # 写入数据
                for entry in log_data:
                    writer.writerow([
                        entry['time'],
                        entry['type'],
                        entry['target'],
                        entry['status'],
                        entry['details'],
                        entry['service']
                    ])
            self.output_text.append(f"\n日志已成功导出到: {file_path}")
        except Exception as e:
            self.output_text.append(f"\n导出CSV失败: {str(e)}")
    
    def export_to_json(self, file_path, log_data):
        """导出日志到JSON文件"""
        import json
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, ensure_ascii=False, indent=2)
            self.output_text.append(f"\n日志已成功导出到: {file_path}")
        except Exception as e:
            self.output_text.append(f"\n导出JSON失败: {str(e)}")
    
    def parse_log_file(self, file_path):
        """解析日志文件"""
        try:
            # 根据文件扩展名选择解析方法
            if file_path.endswith('.txt'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.parse_text_log(content)
            elif file_path.endswith('.json'):
                import json
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.parse_json_log(data)
            elif file_path.endswith('.csv'):
                import csv
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    self.parse_csv_log(reader)
            self.output_text.append(f"\n成功加载日志文件: {file_path}")
        except Exception as e:
            self.output_text.append(f"\n加载日志文件失败: {str(e)}")
    
    def parse_json_log(self, data):
        """解析JSON格式日志"""
        # 清空现有日志
        self.log_table.setRowCount(0)
        
        # 遍历JSON数据
        for entry in data:
            time_str = entry.get('time', '')
            log_type = entry.get('type', '')
            target = entry.get('target', '')
            status = entry.get('status', '')
            details = entry.get('details', '')
            service = entry.get('service', '')
            
            self.add_log_entry(time_str, log_type, target, status, details, service)
    
    def parse_csv_log(self, reader):
        """解析CSV格式日志"""
        # 清空现有日志
        self.log_table.setRowCount(0)
        
        # 遍历CSV数据
        for row in reader:
            time_str = row.get('时间', row.get('time', ''))
            log_type = row.get('类型', row.get('type', ''))
            target = row.get('目标', row.get('target', ''))
            status = row.get('状态', row.get('status', ''))
            details = row.get('详情', row.get('details', ''))
            service = row.get('服务', row.get('service', ''))
            
            self.add_log_entry(time_str, log_type, target, status, details, service)
    
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
        try:
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
        except Exception as e:
            self.output_text.append(f"\n启动扫描错误: {str(e)}")
            import traceback
            self.output_text.append(f"\n错误详情: {traceback.format_exc()}")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
    
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
        """读取进程输出并自动解析"""
        try:
            if self.scan_process:
                output = self.scan_process.readAllStandardOutput().data().decode()
                self.output_text.append(output)
                # 自动滚动到底部
                self.output_text.moveCursor(self.output_text.textCursor().End)
                
                # 自动解析新输出
                self.auto_parse_output(output)
        except Exception as e:
            self.output_text.append(f"\n读取输出错误: {str(e)}")
            import traceback
            self.output_text.append(f"\n错误详情: {traceback.format_exc()}")
    
    def auto_parse_output(self, output):
        """自动解析新的输出内容"""
        try:
            # 按行解析新输出
            for line in output.split('\n'):
                if line.strip():
                    self.parse_single_log(line.strip())
        except Exception as e:
            self.output_text.append(f"\n自动解析输出错误: {str(e)}")
            import traceback
            self.output_text.append(f"\n错误详情: {traceback.format_exc()}")
    
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
        # 清空所有分类表格
        self.clear_all_tables()
    
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