#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import subprocess
import shutil
import winreg
import psutil
import time
import logging
import hashlib
import json
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from datetime import datetime
import base64

class FlashVirusCleaner:
    def __init__(self):
        self.logger = self._setup_logging()
        self.requires_admin = True
        
        # CleanFlash安装程序数据
        self.cleanflash_data = None
        self.cleanflash_path = None
        
        # 病毒进程名（针对FlashCenter和FlashHelperService相关）
        self.virus_processes = [
            "FlashHelperService.exe",
            "FCBrowser.exe",
            "FCBrowserManager.exe",
            "FCGameManager.exe",
            "FCLogin.exe",
            "FCPlay.exe",
            "FlashCenter.exe",
            "FlashCenterSvc.exe",
            "FlashRepair.exe",
            "FlashTool.exe"
        ]
        
        # 病毒服务名
        self.virus_services = [
            "Flash Helper Service",
            "FlashCenter Service"
        ]
        
        # 病毒相关目录（包含FlashCenter/FlashHelperService相关）
        self.virus_directories = [
            r"C:\\Program Files (x86)\\FlashCenter",
            r"C:\\Program Files\\FlashCenter",
            r"C:\\Users\\{}\\AppData\\Local\\FlashCenter",
            r"C:\\Users\\{}\\AppData\\Roaming\\FlashCenter"
        ]
        
        # 病毒相关文件（包含FlashCenter/FlashHelperService相关）
        self.virus_files = [
            # FlashHelperService.exe 在 System32 和 SysWOW64 目录
            r"C:\\Windows\\System32\\Macromed\\Flash\\FlashHelperService.exe",
            r"C:\\Windows\\SysWOW64\\Macromed\\Flash\\FlashHelperService.exe",
            # 其他病毒文件在 FlashCenter 目录
            r"C:\\Program Files\\FlashCenter\\FlashCenter.exe",
            r"C:\\Program Files\\FlashCenter\\FlashCenterSvc.exe",
            r"C:\\Program Files\\FlashCenter\\FCBrowser.exe",
            r"C:\\Program Files\\FlashCenter\\FCBrowserManager.exe",
            r"C:\\Program Files\\FlashCenter\\FCGameManager.exe",
            r"C:\\Program Files\\FlashCenter\\FCLogin.exe",
            r"C:\\Program Files\\FlashCenter\\FCPlay.exe",
            r"C:\\Program Files\\FlashCenter\\FlashRepair.exe",
            r"C:\\Program Files\\FlashCenter\\FlashTool.exe",
            r"C:\\Program Files\\FlashCenter\\FlashCenterUninst.exe",
            # 64位系统32位软件的情况
            r"C:\\Program Files (x86)\\FlashCenter\\FlashCenter.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FlashCenterSvc.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FCBrowser.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FCBrowserManager.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FCGameManager.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FCLogin.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FCPlay.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FlashRepair.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FlashTool.exe",
            r"C:\\Program Files (x86)\\FlashCenter\\FlashCenterUninst.exe"
        ]
        
        # 查找"Flash中心.lnk"快捷方式
        self.virus_shortcuts = ["Flash中心.lnk"]
        
        # 针对FlashCenter/FlashHelperService的注册表项
        self.virus_registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\\CurrentControlSet\\Services"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\FlashCenter"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\FlashCenter")
        ]
        
        # 清理统计
        self.cleanup_stats = {
            "processes_killed": 0,
            "services_deleted": 0,
            "files_deleted": 0,
            "directories_deleted": 0,
            "shortcuts_deleted": 0,
            "registry_cleaned": 0,
            "programs_uninstalled": 0,
            "remaining_threats": 0
        }
        
    def _setup_logging(self) -> logging.Logger:
        """设置详细的日志记录"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = f'FF新鲜事专杀_{timestamp}.log'
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_filename, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        return logging.getLogger(__name__)
    
    def check_admin_privileges(self) -> bool:
        """检查管理员权限"""
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
    
    def request_admin_privileges(self):
        """请求管理员权限"""
        if not self.check_admin_privileges():
            import ctypes
            if ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) > 32:
                sys.exit()
            else:
                messagebox.showerror("权限错误", "需要管理员权限才能完全清除病毒！\n请右键点击此程序，选择'以管理员身份运行'")
                sys.exit(1)
    
    def calculate_file_hash(self, file_path: str) -> str:
        """计算文件MD5哈希值"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.error(f"计算文件哈希失败: {file_path}, 错误: {e}")
            return ""
    
    def scan_system_for_virus(self) -> dict:
        """全面扫描系统中的病毒文件"""
        self.logger.info("开始全面系统扫描...")
        scan_results = {
            "processes": [],
            "services": [],
            "files": [],
            "directories": [],
            "shortcuts": [],
            "registry": []
        }
        # 扫描进程
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'] in self.virus_processes:
                    scan_results["processes"].append({
                        "name": proc.info['name'],
                        "pid": proc.info['pid'],
                        "path": proc.info['exe']
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        # 扫描服务
        try:
            result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                for service in self.virus_services:
                    if service in result.stdout:
                        scan_results["services"].append(service)
        except Exception as e:
            self.logger.error(f"扫描服务失败: {e}")
        # 扫描文件
        for file_path in self.virus_files:
            if os.path.exists(file_path):
                scan_results["files"].append(file_path)
        # 扫描目录
        for dir_path in self.virus_directories:
            if "{}" in dir_path:
                dir_path = dir_path.format(os.getenv('USERNAME'))
            if os.path.exists(dir_path):
                scan_results["directories"].append(dir_path)
        # 扫描快捷方式
        desktop_paths = [
            os.path.join(os.path.expanduser("~"), "Desktop"),
            os.path.join(os.path.expanduser("~"), "桌面")
        ]
        for desktop_path in desktop_paths:
            if os.path.exists(desktop_path):
                for shortcut in self.virus_shortcuts:
                    shortcut_path = os.path.join(desktop_path, shortcut)
                    if os.path.exists(shortcut_path):
                        scan_results["shortcuts"].append(shortcut_path)
        # 扫描注册表
        for hkey, subkey in self.virus_registry_keys:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if any(virus_key.lower() in name.lower() or virus_key.lower() in str(value).lower() 
                                   for virus_key in ["flashcenter", "flashhelper"]):
                                scan_results["registry"].append(f"{subkey}\\{name}")
                            i += 1
                        except WindowsError:
                            break
            except Exception as e:
                self.logger.debug(f"扫描注册表失败: {subkey}, 错误: {e}")
        return scan_results
    
    def display_scan_results(self, scan_results: dict):
        """显示扫描结果"""
        self.logger.info("\n" + "="*60)
        self.logger.info("系统扫描结果")
        self.logger.info("="*60)
        
        total_threats = 0
        for category, items in scan_results.items():
            count = len(items)
            total_threats += count
            self.logger.info(f"{category.capitalize()}: {count} 个威胁")
            
            if items:
                for item in items[:5]:  # 只显示前5个
                    if isinstance(item, dict):
                        self.logger.info(f"  - {item['name']} (PID: {item['pid']})")
                    else:
                        self.logger.info(f"  - {item}")
                
                if len(items) > 5:
                    self.logger.info(f"  ... 还有 {len(items) - 5} 个")
        
        self.logger.info(f"\n总计发现: {total_threats} 个威胁")
        self.logger.info("="*60)
        
        # 即使只检测到一个病毒文件也要继续查杀
        if total_threats > 0:
            self.logger.info("发现病毒威胁，开始全面清理...")
        else:
            self.logger.info("未发现病毒威胁，系统安全！")
        
        return total_threats > 0
    
    def kill_virus_processes(self) -> int:
        """终止病毒进程"""
        self.logger.info("\n正在终止病毒进程...")
        killed_count = 0
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'] in self.virus_processes:
                    self.logger.info(f"发现病毒进程: {proc.info['name']} (PID: {proc.info['pid']})")
                    try:
                        proc.terminate()
                        proc.wait(timeout=5)
                        killed_count += 1
                        self.logger.info(f"成功终止进程: {proc.info['name']}")
                    except psutil.TimeoutExpired:
                        proc.kill()
                        killed_count += 1
                        self.logger.info(f"强制终止进程: {proc.info['name']}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        self.cleanup_stats["processes_killed"] = killed_count
        return killed_count
    
    def delete_virus_services(self) -> int:
        """删除病毒服务"""
        self.logger.info("\n正在删除病毒服务...")
        deleted_count = 0
        for service_name in self.virus_services:
            try:
                self.logger.info(f"正在停止服务: {service_name}")
                subprocess.run(['sc', 'stop', service_name], 
                             capture_output=True, text=True, timeout=10)
                self.logger.info(f"正在删除服务: {service_name}")
                result = subprocess.run(['sc', 'delete', service_name], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    deleted_count += 1
                    self.logger.info(f"成功删除服务: {service_name}")
                else:
                    self.logger.warning(f"删除服务失败: {service_name}")
            except Exception as e:
                self.logger.error(f"删除服务时出错: {service_name}, 错误: {e}")
        self.cleanup_stats["services_deleted"] = deleted_count
        return deleted_count
    
    def delete_virus_files(self) -> int:
        """删除病毒文件"""
        self.logger.info("\n正在删除病毒文件...")
        deleted_count = 0
        for file_path in self.virus_files:
            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                    deleted_count += 1
                    self.logger.info(f"删除病毒文件: {file_path}")
                except Exception as e:
                    self.logger.error(f"删除文件失败: {file_path}, 错误: {e}")
        self.cleanup_stats["files_deleted"] = deleted_count
        return deleted_count
    
    def cleanup_virus_directories(self) -> int:
        """清理病毒目录"""
        self.logger.info("\n正在清理病毒目录...")
        deleted_count = 0
        
        # 确保删除整个FlashCenter目录
        flashcenter_dirs = [
            r"C:\Program Files\FlashCenter",
            r"C:\Program Files (x86)\FlashCenter"
        ]
        
        for dir_path in flashcenter_dirs:
            if os.path.exists(dir_path):
                try:
                    shutil.rmtree(dir_path)
                    deleted_count += 1
                    self.logger.info(f"删除病毒目录: {dir_path}")
                except Exception as e:
                    self.logger.error(f"删除目录失败: {dir_path}, 错误: {e}")
        
        # 删除用户目录中的FlashCenter
        for dir_path in self.virus_directories:
            if "{}" in dir_path:
                dir_path = dir_path.format(os.getenv('USERNAME'))
            if os.path.exists(dir_path):
                try:
                    shutil.rmtree(dir_path)
                    deleted_count += 1
                    self.logger.info(f"删除病毒目录: {dir_path}")
                except Exception as e:
                    self.logger.error(f"删除目录失败: {dir_path}, 错误: {e}")
        
        self.cleanup_stats["directories_deleted"] = deleted_count
        return deleted_count
    
    def remove_virus_shortcuts(self) -> int:
        """删除病毒快捷方式"""
        self.logger.info("\n正在删除病毒快捷方式...")
        deleted_count = 0
        desktop_paths = [
            os.path.join(os.path.expanduser("~"), "Desktop"),
            os.path.join(os.path.expanduser("~"), "桌面")
        ]
        for desktop_path in desktop_paths:
            if os.path.exists(desktop_path):
                for shortcut in self.virus_shortcuts:
                    shortcut_path = os.path.join(desktop_path, shortcut)
                    if os.path.exists(shortcut_path):
                        try:
                            os.remove(shortcut_path)
                            deleted_count += 1
                            self.logger.info(f"删除快捷方式: {shortcut_path}")
                        except Exception as e:
                            self.logger.error(f"删除快捷方式失败: {shortcut_path}, 错误: {e}")
        self.cleanup_stats["shortcuts_deleted"] = deleted_count
        return deleted_count
    
    def clean_virus_registry(self) -> int:
        """清理病毒注册表项"""
        self.logger.info("\n正在清理病毒注册表项...")
        cleaned_count = 0
        virus_keywords = ["flashcenter", "flashhelper"]
        for hkey, subkey in self.virus_registry_keys:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            if any(keyword in name.lower() or keyword in str(value).lower() 
                                   for keyword in virus_keywords):
                                try:
                                    winreg.DeleteValue(key, name)
                                    cleaned_count += 1
                                    self.logger.info(f"删除注册表值: {subkey}\\{name}")
                                except Exception as e:
                                    self.logger.error(f"删除注册表值失败: {subkey}\\{name}, 错误: {e}")
                            i += 1
                        except WindowsError:
                            break
            except Exception as e:
                self.logger.debug(f"访问注册表失败: {subkey}, 错误: {e}")
        self.cleanup_stats["registry_cleaned"] = cleaned_count
        return cleaned_count
    
    def uninstall_virus_programs(self) -> int:
        """卸载病毒程序 - 只针对FlashCenter/FlashHelperService"""
        self.logger.info("\n正在卸载病毒程序...")
        uninstalled_count = 0
        try:
            # 只查找名称包含FlashCenter或FlashHelperService的程序
            result = subprocess.run(
                ['wmic', 'product', 'get', 'name,identifyingnumber,installLocation'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:
                    if line.strip() and ("FlashCenter" in line or "FlashHelperService" in line):
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            product_id = parts[-1]
                            product_name = ' '.join(parts[:-1])
                            self.logger.info(f"发现病毒程序: {product_name}")
                            # 删除程序文件
                            try:
                                location_result = subprocess.run(
                                    ['wmic', 'product', 'where', f'identifyingnumber="{product_id}"', 'get', 'installLocation'],
                                    capture_output=True, text=True, timeout=10
                                )
                                if location_result.returncode == 0:
                                    install_location = location_result.stdout.strip().split('\n')[1].strip()
                                    if install_location and os.path.exists(install_location):
                                        self.logger.info(f"删除程序文件: {install_location}")
                                        try:
                                            shutil.rmtree(install_location)
                                            self.logger.info(f"成功删除程序文件: {install_location}")
                                        except Exception as e:
                                            self.logger.warning(f"删除程序文件失败: {install_location}, 错误: {e}")
                            except Exception as e:
                                self.logger.warning(f"获取程序安装路径失败: {product_name}, 错误: {e}")
                            # 删除控制面板条目
                            try:
                                self._remove_uninstall_registry_entry(product_id, product_name)
                                uninstalled_count += 1
                                self.logger.info(f"成功清理程序条目: {product_name}")
                            except Exception as e:
                                self.logger.warning(f"清理程序条目失败: {product_name}, 错误: {e}")
        except Exception as e:
            self.logger.error(f"卸载程序时出错: {e}")
        self.cleanup_stats["programs_uninstalled"] = uninstalled_count
        return uninstalled_count
    
    def _remove_uninstall_registry_entry(self, product_id: str, product_name: str):
        """直接从注册表删除卸载条目，不触发卸载程序"""
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
        ]
        
        for hkey, subkey in registry_paths:
            try:
                with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_ALL_ACCESS) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            # 检查是否是目标程序
                            if (product_id in str(value) or 
                                product_name.lower() in name.lower() or 
                                any(keyword in name.lower() for keyword in ["flashcenter", "flashhelper"])):
                                try:
                                    winreg.DeleteValue(key, name)
                                    self.logger.info(f"删除注册表卸载条目: {subkey}\\{name}")
                                except Exception as e:
                                    self.logger.warning(f"删除注册表条目失败: {subkey}\\{name}, 错误: {e}")
                            i += 1
                        except WindowsError:
                            break
            except Exception as e:
                self.logger.debug(f"访问注册表失败: {subkey}, 错误: {e}")
    
    def create_system_restore_point(self):
        """创建系统还原点"""
        try:
            self.logger.info("正在创建系统还原点...")
            subprocess.run([
                'wmic.exe', '/Namespace:\\\\root\\default', 'Path', 'SystemRestore', 
                'Call', 'CreateRestorePoint', '"FF新鲜事病毒清除前"', '100', '7'
            ], capture_output=True, timeout=60)
            self.logger.info("系统还原点创建成功")
        except Exception as e:
            self.logger.error(f"创建系统还原点失败: {e}")
    
    def find_cleanflash_installer(self):
        """查找CleanFlash安装程序"""
        try:
            # 查找程序目录下的CleanFlash安装程序
            program_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            cleanflash_path = os.path.join(program_dir, "CleanFlash_34.0.0.325_Installer.exe")
            
            if os.path.exists(cleanflash_path):
                self.cleanflash_path = cleanflash_path
                self.logger.info(f"找到CleanFlash安装程序: {cleanflash_path}")
                return True
            else:
                self.logger.warning("未找到CleanFlash安装程序文件，请确保CleanFlash_34.0.0.325_Installer.exe在程序目录下")
                return False
        except Exception as e:
            self.logger.error(f"查找CleanFlash安装程序失败: {e}")
            return False
    
    def generate_cleanup_report(self):
        """生成清理报告"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
FF新鲜事病毒清理报告
生成时间: {timestamp}
==========================================

清理统计:
- 终止的进程: {self.cleanup_stats['processes_killed']} 个
- 删除的服务: {self.cleanup_stats['services_deleted']} 个  
- 删除的文件: {self.cleanup_stats['files_deleted']} 个
- 删除的目录: {self.cleanup_stats['directories_deleted']} 个
- 删除的快捷方式: {self.cleanup_stats['shortcuts_deleted']} 个
- 清理的注册表项: {self.cleanup_stats['registry_cleaned']} 个
- 卸载的程序: {self.cleanup_stats['programs_uninstalled']} 个

建议:
1. 重启计算机以确保清理完全生效
2. 检查系统是否还有异常弹窗
3. 如果问题仍然存在，请手动检查剩余文件

清理完成！
"""
        
        # 保存报告到文件
        report_filename = f'FF新鲜事清理报告_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.logger.info(report)
        self.logger.info(f"详细报告已保存到: {report_filename}")

class FlashVirusCleanerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("FF新鲜事专杀工具")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        try:
            self.root.iconbitmap("icon.ico")
        except Exception as e:
            pass  # 如果找不到icon.ico则忽略
        # 启动时弹窗温馨提示
        self.show_welcome_message()
        # 初始化清理器
        self.cleaner = FlashVirusCleaner()
        # 查找CleanFlash安装程序
        self.cleaner.find_cleanflash_installer()
        # 创建界面
        self.create_widgets()
        # 设置日志重定向
        self.setup_log_redirect()
        
    def create_widgets(self):
        """创建GUI组件"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # 标题
        title_label = ttk.Label(main_frame, text="FF新鲜事专杀工具", font=("Microsoft YaHei", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # 警告信息
        warning_frame = ttk.LabelFrame(main_frame, text="重要警告", padding="10")
        warning_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        warning_text = """⚠️  使用前请务必：
• 备份重要数据
• 以管理员权限运行此程序
• 确保没有重要程序正在运行"""
        
        warning_label = ttk.Label(warning_frame, text=warning_text, foreground="red", font=("Microsoft YaHei", 11))
        warning_label.pack()
        
        # 控制按钮框架
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # 开始查杀按钮
        self.start_button = ttk.Button(button_frame, text="开始查杀", 
                                      command=self.start_cleanup, style="Accent.TButton")
        self.start_button.pack(fill=tk.X, pady=(0, 10))
        
        # 停止按钮
        self.stop_button = ttk.Button(button_frame, text="停止", 
                                     command=self.stop_cleanup, state=tk.DISABLED)
        self.stop_button.pack(fill=tk.X, pady=(0, 10))
        
        # 进度条
        self.progress = ttk.Progressbar(button_frame, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, 10))
        
        # 状态标签
        self.status_label = ttk.Label(button_frame, text="准备就绪", 
                                     font=("Microsoft YaHei", 10))
        self.status_label.pack(pady=(0, 10))
        
        # 统计信息框架
        stats_frame = ttk.LabelFrame(button_frame, text="清理统计", padding="5")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.stats_text = tk.StringVar(value="等待开始...")
        stats_label = ttk.Label(stats_frame, textvariable=self.stats_text, 
                               font=("Microsoft YaHei", 9))
        stats_label.pack()
        
        # 日志显示区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="5")
        log_frame.grid(row=2, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 日志文本框
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20, width=60, 
                                                 font=("Microsoft YaHei", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 底部按钮框架
        bottom_frame = ttk.Frame(main_frame)
        bottom_frame.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        # 清空日志按钮
        clear_button = ttk.Button(bottom_frame, text="清空日志", 
                                 command=self.clear_log)
        clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # 保存日志按钮
        save_button = ttk.Button(bottom_frame, text="保存日志", 
                                command=self.save_log)
        save_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # 退出按钮
        exit_button = ttk.Button(bottom_frame, text="退出", 
                                command=self.root.quit)
        exit_button.pack(side=tk.RIGHT)
        
    def setup_log_redirect(self):
        """设置日志重定向到GUI"""
        class TextHandler(logging.Handler):
            def __init__(self, text_widget):
                logging.Handler.__init__(self)
                self.text_widget = text_widget
                
            def emit(self, record):
                msg = self.format(record)
                def append():
                    self.text_widget.insert(tk.END, msg + '\n')
                    self.text_widget.see(tk.END)
                self.text_widget.after(0, append)
        
        # 创建文本处理器
        text_handler = TextHandler(self.log_text)
        text_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        
        # 添加到logger
        self.cleaner.logger.addHandler(text_handler)
        
    def update_status(self, message):
        """更新状态信息"""
        self.status_label.config(text=message)
        self.root.update_idletasks()
        
    def update_stats(self):
        """更新统计信息"""
        stats = self.cleaner.cleanup_stats
        stats_str = f"""进程终止: {stats['processes_killed']} 个
服务删除: {stats['services_deleted']} 个
文件删除: {stats['files_deleted']} 个
目录删除: {stats['directories_deleted']} 个
快捷方式: {stats['shortcuts_deleted']} 个
注册表项: {stats['registry_cleaned']} 个
程序卸载: {stats['programs_uninstalled']} 个"""
        self.stats_text.set(stats_str)
        
    def start_cleanup(self):
        """开始清理流程"""
        # 检查管理员权限
        if not self.cleaner.check_admin_privileges():
            messagebox.showerror("权限错误", "需要管理员权限才能完全清除病毒！\n请右键点击此程序，选择'以管理员身份运行'")
            return
        
        # 确认对话框
        result = messagebox.askyesno("确认操作", 
                                   "此工具将删除FF新鲜事相关文件。\n\n"
                                   "确认要继续吗？\n\n"
                                   "建议在运行前备份重要数据。")
        if not result:
            return
        
        # 禁用开始按钮，启用停止按钮
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # 开始进度条
        self.progress.start()
        
        # 在新线程中运行清理
        self.cleanup_thread = threading.Thread(target=self.run_cleanup_thread)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        
    def run_cleanup_thread(self):
        """在新线程中运行清理"""
        try:
            self.update_status("正在创建系统还原点...")
            try:
                self.cleaner.create_system_restore_point()
            except Exception as e:
                self.cleaner.logger.error(f"创建系统还原点失败: {e}")
            
            self.update_status("正在扫描系统...")
            try:
                scan_results = self.cleaner.scan_system_for_virus()
            except Exception as e:
                self.cleaner.logger.error(f"扫描系统失败: {e}")
                scan_results = {"processes":[],"services":[],"files":[],"directories":[],"shortcuts":[],"registry":[]}
            try:
                has_threats = self.cleaner.display_scan_results(scan_results)
            except Exception as e:
                self.cleaner.logger.error(f"显示扫描结果失败: {e}")
                has_threats = True  # 继续查杀
            
            if not has_threats:
                self.update_status("未发现病毒威胁，系统安全！")
                messagebox.showinfo("扫描完成", "未发现病毒威胁，系统安全！")
                return
            
            # 执行清理步骤，每一步都try/except，保证不中断
            steps = [
                ("终止病毒进程", self.cleaner.kill_virus_processes),
                ("删除病毒服务", self.cleaner.delete_virus_services),
                ("删除病毒文件", self.cleaner.delete_virus_files),
                ("清理病毒目录", self.cleaner.cleanup_virus_directories),
                ("删除快捷方式", self.cleaner.remove_virus_shortcuts),
                ("清理注册表", self.cleaner.clean_virus_registry),
                ("安全卸载程序", self.cleaner.uninstall_virus_programs)
            ]
            for step_name, step_func in steps:
                self.update_status(f"正在{step_name}...")
                try:
                    step_func()
                except Exception as e:
                    self.cleaner.logger.error(f"{step_name}失败: {e}")
                self.update_stats()
            # 生成报告
            self.update_status("正在生成清理报告...")
            try:
                self.cleaner.generate_cleanup_report()
            except Exception as e:
                self.cleaner.logger.error(f"生成清理报告失败: {e}")
            self.update_status("清理完成！")
            
            # 弹出安装CleanFlash的提示
            install_message = (
                "接下来会为您安装开源的纯净版Flash：Clean Flash Player，请在稍后点击勾选□I am  aware that Adobe Flash Player is no longer supported……\n"
                "然后点击AGREE按钮，根据需求勾选你要安装的Flash版本或全选安装（推荐全选安装！）\n"
                "PPAPI是谷歌浏览器和Chromium内核浏览器使用的版本，NPAPI是火狐浏览器使用的版本，OCX是IE浏览器和IE内核浏览器使用的版本\n"
                "安装成功后请重启电脑，您的电脑上将拥有一个纯净的Flash版本，不会再有任何FF新鲜事和Flash中心了！"
            )
            
            result = messagebox.askyesno("安装CleanFlash", install_message)
            if result:
                # 执行CleanFlash安装程序
                self.update_status("正在启动CleanFlash安装程序...")
                try:
                    if self.cleaner.cleanflash_path and os.path.exists(self.cleaner.cleanflash_path):
                        subprocess.Popen([self.cleaner.cleanflash_path], shell=True)
                        self.cleaner.logger.info("CleanFlash安装程序已启动")
                    else:
                        messagebox.showerror("错误", "未找到CleanFlash安装程序，请确保CleanFlash_34.0.0.325_Installer.exe在程序目录下")
                        self.cleaner.logger.error("未找到CleanFlash安装程序")
                except Exception as e:
                    error_msg = f"启动CleanFlash安装程序失败: {e}"
                    messagebox.showerror("错误", error_msg)
                    self.cleaner.logger.error(error_msg)
            
            messagebox.showinfo("清理完成", "FF新鲜事病毒清理完成！\n建议重启计算机以确保清理完全生效。")
            
        except Exception as e:
            error_msg = f"清理过程中发生错误: {e}"
            self.cleaner.logger.error(error_msg)
            messagebox.showerror("错误", error_msg)
        finally:
            # 恢复按钮状态
            self.root.after(0, self.cleanup_finished)
            
    def cleanup_finished(self):
        """清理完成后的处理"""
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.update_status("准备就绪")
        
    def stop_cleanup(self):
        """停止清理"""
        if hasattr(self, 'cleanup_thread') and self.cleanup_thread.is_alive():
            result = messagebox.askyesno("确认停止", "确定要停止清理过程吗？")
            if result:
                self.update_status("正在停止...")
                self.cleanup_finished()
                
    def clear_log(self):
        """清空日志"""
        self.log_text.delete(1.0, tk.END)
        
    def save_log(self):
        """保存日志"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"FF新鲜事专杀日志_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get(1.0, tk.END))
                
            messagebox.showinfo("保存成功", f"日志已保存到: {filename}")
        except Exception as e:
            messagebox.showerror("保存失败", f"保存日志失败: {e}")
            
    def run(self):
        """运行GUI"""
        self.root.mainloop()

    def show_welcome_message(self):
        message = (
            "温馨提示：为达到最佳查杀效果，本软件会扫描用户的内存（RAM）和硬盘（HardDisk），扫描过程只会在本地运行，本软件不会也完全不需要连接互联网。\n"
            "不会收集任何用户数据和信息，不会上传任何数据。本软件在GitHub平台上开放全部源代码，任何人都可以查看、审阅、修改、删减、转发、逆向、再编译本软件。\n"
            "亦可商业化使用、销售、或基于本软件开发其它软件，本软件是完全免费、开源的Copyleft自由软件，遵循GPLv3协议。"
        )
        messagebox.showinfo("温馨提示", message)

def main():
    """主函数"""
    app = FlashVirusCleanerGUI()
    app.run()

if __name__ == "__main__":
    main() 