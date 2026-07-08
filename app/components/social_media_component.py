from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFrame, QGroupBox)
from PyQt6.QtCore import pyqtSignal

class SocialMediaComponent(QWidget):
    analysis_started = pyqtSignal(str, str)
    analysis_completed = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup social media UI"""
        layout = QHBoxLayout(self)
        
        # Left panel - controls
        left_panel = self.create_controls_panel()
        layout.addWidget(left_panel)
        
        # Right panel - output
        right_panel = self.create_output_panel()
        layout.addWidget(right_panel, 2)

    def create_controls_panel(self):
        """Create controls panel"""
        panel = QFrame()
        panel.setFixedWidth(300)
        layout = QVBoxLayout(panel)
        
        # Target input
        target_group = QGroupBox("Target Configuration")
        target_layout = QVBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Social Media Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("@username or profile URL")
        target_layout.addWidget(self.target_input)
        
        layout.addWidget(target_group)
        
        # Analysis modules
        modules_group = QGroupBox("Social Media Analysis")
        modules_layout = QVBoxLayout(modules_group)
        
        buttons = [
            ("Account Discovery", self.run_account_discovery),
            ("Content Analysis", self.run_content_analysis),
            ("Network Mapping", self.run_network_mapping),
            ("Timeline Recon", self.run_timeline_recon),
            ("Image Analysis", self.run_image_analysis),
            ("Sentiment Analysis", self.run_sentiment_analysis),
            ("Metadata Extract", self.run_metadata_extract),
            ("Full Social Intel", self.run_full_social_intel)
        ]
        
        for text, method in buttons:
            btn = QPushButton(text)
            btn.clicked.connect(method)
            btn.setMinimumHeight(30)
            modules_layout.addWidget(btn)
        
        layout.addWidget(modules_group)
        layout.addStretch()
        
        return panel

    def create_output_panel(self):
        """Create output panel"""
        panel = QFrame()
        layout = QVBoxLayout(panel)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Social media analysis results will appear here...")
        layout.addWidget(self.output_text)
        
        return panel

    def run_account_discovery(self):
        """Run real social media account discovery"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.setHtml("<p style='color: #FFA500;'>⚠ Please enter a target username</p>")
            return

        self.analysis_started.emit(target, "Account Discovery")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[ACCOUNT DISCOVERY] Searching for '{target}' across platforms...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.social_media_engine import account_discovery

        self._worker = OSINTWorker(account_discovery, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_account_results)
        self._worker.finished_signal.connect(lambda: self.analysis_completed.emit({}))
        self._worker.start()

    def _display_account_results(self, results):
        from app.core.html_utils import h
        found = results.get("found", [])
        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ Found {len(found)} accounts across {results.get('total_checked', 0)} platforms</p>")
        for acct in found:
            platform = acct.get("platform", "")
            url = acct.get("url", "")
            extra = ""
            if acct.get("followers"):
                extra += f" | {acct['followers']} followers"
            if acct.get("karma"):
                extra += f" | {acct['karma']} karma"
            if acct.get("repos"):
                extra += f" | {acct['repos']} repos"
            self.output_text.append(f"<p style='color: #00FF41; margin-left: 15px;'>✓ <b>{h(platform.upper())}</b>: {h(url)}{extra}</p>")

    def run_content_analysis(self):
        """Run real content analysis"""
        target = self.target_input.text().strip()
        if not target:
            return

        self.analysis_started.emit(target, "Content Analysis")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[CONTENT ANALYSIS] Analyzing public content for '{target}'...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.social_media_engine import content_analysis

        self._worker = OSINTWorker(content_analysis, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_content_results)
        self._worker.finished_signal.connect(lambda: self.analysis_completed.emit({}))
        self._worker.start()

    def _display_content_results(self, results):
        from app.core.html_utils import h
        gh = results.get("github")
        if gh and not gh.get("error"):
            self.output_text.append("<p style='color: #00FF41; font-weight: bold;'>✅ GitHub Content Analysis</p>")
            self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>Repositories: {gh.get('repos', 0)}</p>")
            self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>Total Stars: {gh.get('total_stars', 0)}</p>")
            langs = gh.get("languages", {})
            if langs:
                self.output_text.append(f"<p style='color: #FFD93D; margin-left: 15px;'>Languages: {', '.join(list(langs.keys())[:10])}</p>")
            topics = gh.get("topics", [])
            if topics:
                self.output_text.append(f"<p style='color: #64C8FF; margin-left: 15px;'>Topics: {', '.join(topics[:10])}</p>")
            for repo in gh.get("recent_repos", [])[:5]:
                desc = f" — {h(repo['description'][:50])}" if repo.get("description") else ""
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 25px;'>• {h(repo['name'])} ⭐{repo['stars']}{desc}</p>")
        elif gh and gh.get("error"):
            self.output_text.append(f"<p style='color: #FF6B6B;'>{h(gh['error'])}</p>")

    def run_network_mapping(self):
        """Run real network mapping"""
        target = self.target_input.text().strip()
        if not target:
            return

        self.analysis_started.emit(target, "Network Mapping")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[NETWORK MAPPING] Mapping connections for '{target}'...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.social_media_engine import network_mapping

        self._worker = OSINTWorker(network_mapping, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_network_results)
        self._worker.finished_signal.connect(lambda: self.analysis_completed.emit({}))
        self._worker.start()

    def _display_network_results(self, results):
        from app.core.html_utils import h
        self.output_text.append("<p style='color: #00FF41; font-weight: bold;'>✅ Network Mapping Complete</p>")
        self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>Followers: {len(results.get('followers', []))}</p>")
        self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>Following: {len(results.get('following', []))}</p>")
        mutual = results.get("mutual", [])
        if mutual:
            self.output_text.append(f"<p style='color: #FFD93D; margin-left: 15px;'>Mutual ({len(mutual)}): {', '.join(mutual[:15])}</p>")

    def run_timeline_recon(self):
        """Run real timeline reconstruction"""
        target = self.target_input.text().strip()
        if not target:
            return

        self.analysis_started.emit(target, "Timeline Reconstruction")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[TIMELINE] Reconstructing activity for '{target}'...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.social_media_engine import timeline_recon

        self._worker = OSINTWorker(timeline_recon, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_timeline_results)
        self._worker.finished_signal.connect(lambda: self.analysis_completed.emit({}))
        self._worker.start()

    def _display_timeline_results(self, results):
        from app.core.html_utils import h
        events = results.get("events", [])
        self.output_text.append(f"<p style='color: #00FF41; font-weight: bold;'>✅ Timeline: {len(events)} events</p>")

        # Activity hours
        hours = results.get("activity_hours", {})
        if hours:
            peak_hour = max(hours, key=hours.get)
            self.output_text.append(f"<p style='color: #FFD93D; margin-left: 15px;'>Peak activity hour: {peak_hour}:00 UTC</p>")

        # Activity days
        days = results.get("activity_days", {})
        if days:
            peak_day = max(days, key=days.get)
            self.output_text.append(f"<p style='color: #FFD93D; margin-left: 15px;'>Most active day: {peak_day}</p>")

        # Recent events
        for event in events[:10]:
            self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>• {h(event['type'])} on {h(event['repo'])} ({event['date'][:10]})</p>")

    def run_image_analysis(self):
        """Image analysis — requires images to be downloaded first"""
        target = self.target_input.text().strip()
        if not target:
            return
        self.analysis_started.emit(target, "Image Analysis")
        self.output_text.clear()
        self.output_text.setHtml(
            "<p style='color: #64C8FF;'>[IMAGE ANALYSIS]</p>"
            "<p style='color: #FFD93D;'>Image analysis requires downloading profile images first.</p>"
            "<p style='color: #DCDCDC;'>This module analyzes:</p>"
            "<p style='color: #DCDCDC; margin-left: 15px;'>• EXIF metadata (GPS, camera, timestamps)</p>"
            "<p style='color: #DCDCDC; margin-left: 15px;'>• Reverse image search</p>"
            "<p style='color: #DCDCDC; margin-left: 15px;'>• Object/location detection</p>"
            "<p style='color: #DCDCDC;'><br>Use Account Discovery first to find profile image URLs.</p>"
        )
        self.analysis_completed.emit({})

    def run_sentiment_analysis(self):
        """Sentiment analysis on public posts"""
        target = self.target_input.text().strip()
        if not target:
            return
        self.analysis_started.emit(target, "Sentiment Analysis")
        self.output_text.clear()
        self.output_text.setHtml(
            "<p style='color: #64C8FF;'>[SENTIMENT ANALYSIS]</p>"
            "<p style='color: #FFD93D;'>Sentiment analysis requires access to user posts/comments.</p>"
            "<p style='color: #DCDCDC;'>Supported sources:</p>"
            "<p style='color: #DCDCDC; margin-left: 15px;'>• Reddit comments (via public API)</p>"
            "<p style='color: #DCDCDC; margin-left: 15px;'>• GitHub commit messages</p>"
            "<p style='color: #DCDCDC; margin-left: 15px;'>• HackerNews posts</p>"
            "<p style='color: #DCDCDC;'><br>Run Content Analysis first to gather text data.</p>"
        )
        self.analysis_completed.emit({})

    def run_metadata_extract(self):
        """Run real metadata extraction"""
        target = self.target_input.text().strip()
        if not target:
            return

        self.analysis_started.emit(target, "Metadata Extraction")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF;'>[METADATA] Extracting profile metadata for '{target}'...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.social_media_engine import metadata_extraction

        self._worker = OSINTWorker(metadata_extraction, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_metadata_results)
        self._worker.finished_signal.connect(lambda: self.analysis_completed.emit({}))
        self._worker.start()

    def _display_metadata_results(self, results):
        from app.core.html_utils import h
        metadata = results.get("metadata", {})
        self.output_text.append("<p style='color: #00FF41; font-weight: bold;'>✅ Metadata Extraction Complete</p>")
        for platform, fields in metadata.items():
            self.output_text.append(f"<p style='color: #FFD93D; font-weight: bold;'>{h(platform.upper())}:</p>")
            for key, value in fields.items():
                self.output_text.append(f"<p style='color: #DCDCDC; margin-left: 15px;'>• {h(key)}: {h(str(value)[:100])}</p>")

    def run_full_social_intel(self):
        """Run comprehensive social media intelligence"""
        target = self.target_input.text().strip()
        if not target:
            self.output_text.setHtml("<p style='color: #FFA500;'>⚠ Please enter a target username</p>")
            return

        self.analysis_started.emit(target, "Full Social Intel")
        self.output_text.clear()
        self.output_text.append(f"<p style='color: #64C8FF; font-weight: bold;'>[FULL SOCIAL INTEL] Comprehensive analysis for '{target}'...</p>")

        from app.core.osint_workers import OSINTWorker
        from app.core.social_media_engine import full_social_intel

        self._worker = OSINTWorker(full_social_intel, target)
        self._worker.output_signal.connect(lambda msg: self.output_text.append(f"<p style='color: #DCDCDC;'>{msg}</p>"))
        self._worker.result_signal.connect(self._display_full_intel_results)
        self._worker.finished_signal.connect(lambda: self.analysis_completed.emit({}))
        self._worker.start()

    def _display_full_intel_results(self, results):
        from app.core.html_utils import h
        self.output_text.append("<p style='color: #00FF41; font-weight: bold; font-size: 14px;'>✅ COMPREHENSIVE SOCIAL INTEL COMPLETE</p>")

        # Account discovery summary
        accts = results.get("account_discovery", {})
        found = accts.get("found", [])
        self.output_text.append(f"<p style='color: #FFD93D;'>Accounts found: {len(found)} / {accts.get('total_checked', 0)} platforms</p>")
        for a in found:
            self.output_text.append(f"<p style='color: #00FF41; margin-left: 15px;'>✓ {h(a.get('platform', '').upper())}</p>")

        # Content summary
        content = results.get("content_analysis", {})
        gh = content.get("github") if content else None
        if gh and not gh.get("error"):
            self.output_text.append(f"<p style='color: #FFD93D;'>GitHub: {gh.get('repos', 0)} repos, {gh.get('total_stars', 0)} stars</p>")

        # Network summary
        network = results.get("network_mapping", {})
        if network:
            self.output_text.append(f"<p style='color: #FFD93D;'>Network: {len(network.get('followers', []))} followers, {len(network.get('following', []))} following</p>")

        # Timeline summary
        timeline = results.get("timeline", {})
        if timeline:
            self.output_text.append(f"<p style='color: #FFD93D;'>Timeline: {len(timeline.get('events', []))} recent events</p>")

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass