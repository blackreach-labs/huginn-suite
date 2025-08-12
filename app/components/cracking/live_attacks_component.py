# app/components/cracking/live_attacks_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QProgressBar)
from PyQt6.QtCore import pyqtSignal, QThread, QTimer
from PyQt6.QtGui import QFont
import random

class LiveAttackWorker(QThread):
    output_signal = pyqtSignal(str)
    progress_signal = pyqtSignal(int)
    stats_signal = pyqtSignal(dict)
    finished_signal = pyqtSignal()

    def __init__(self, attack_config):
        super().__init__()
        self.attack_config = attack_config
        self.running = True

    def run(self):
        try:
            self.output_signal.emit(f"[START] {self.attack_config['tool']} {self.attack_config['mode']} attack started")
            
            total_hashes = random.randint(5, 15)
            cracked = 0
            
            for i in range(100):  # Simulate progress
                if not self.running:
                    break
                    
                self.progress_signal.emit(i)
                
                # Simulate hash cracking
                if random.random() < 0.1:  # 10% chance to crack a hash
                    cracked += 1
                    hash_sample = f"5d41402abc4b2a76b9719d911017c592"
                    password = random.choice(["password123", "admin", "qwerty", "123456", "letmein"])
                    self.output_signal.emit(f"[CRACKED] {hash_sample}:{password}")
                
                # Update stats
                rate = random.randint(1000, 50000)
                self.stats_signal.emit({
                    'total': total_hashes,
                    'cracked': cracked,
                    'rate': f"{rate:,} H/s",
                    'progress': i
                })
                
                self.msleep(100)
            
            self.output_signal.emit(f"[COMPLETE] Attack finished - {cracked}/{total_hashes} hashes cracked")
            
        except Exception as e:
            self.output_signal.emit(f"[ERROR] {str(e)}")
        finally:
            self.finished_signal.emit()

    def stop(self):
        self.running = False

class LiveAttacksComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("Live Attacks")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Attack controls
        controls_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        controls_layout.addWidget(self.start_btn)
        controls_layout.addWidget(self.stop_btn)
        layout.addLayout(controls_layout)
        
        # Statistics
        stats_layout = QHBoxLayout()
        stats_layout.addWidget(QLabel("Total:"))
        self.total_label = QLabel("0")
        stats_layout.addWidget(self.total_label)
        stats_layout.addWidget(QLabel("Cracked:"))
        self.cracked_label = QLabel("0")
        stats_layout.addWidget(self.cracked_label)
        stats_layout.addWidget(QLabel("Rate:"))
        self.rate_label = QLabel("0 H/s")
        stats_layout.addWidget(self.rate_label)
        layout.addLayout(stats_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Live output
        self.live_output = QTextEdit()
        self.live_output.setMaximumHeight(150)
        self.live_output.setPlaceholderText("Live attack output will appear here...")
        layout.addWidget(self.live_output)

    def start_attack(self):
        # Default attack configuration
        attack_config = {
            'tool': 'Hashcat',
            'mode': 'Dictionary',
            'config': {'threads': 4, 'gpu': False}
        }
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.live_output.clear()
        self.progress_bar.setValue(0)
        
        self.worker = LiveAttackWorker(attack_config)
        self.worker.output_signal.connect(self.live_output.append)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.finished_signal.connect(self.on_attack_finished)
        self.worker.start()

    def stop_attack(self):
        if self.worker:
            self.worker.stop()
        self.on_attack_finished()

    def update_stats(self, stats):
        self.total_label.setText(str(stats['total']))
        self.cracked_label.setText(str(stats['cracked']))
        self.rate_label.setText(stats['rate'])

    def on_attack_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if self.worker:
            self.worker.quit()
            self.worker.wait()
            self.worker = None