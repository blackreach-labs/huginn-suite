from PyQt6.QtWidgets import QWidget, QVBoxLayout, QListWidget, QTextEdit

class NoteViewer(QWidget):
    def __init__(self, notes):
        super().__init__()
        self.notes = notes
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.list_widget = QListWidget()
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)

        for note in self.notes:
            self.list_widget.addItem(note["title"])

        self.list_widget.currentRowChanged.connect(self.load_note)

        layout.addWidget(self.list_widget)
        layout.addWidget(self.text_area)
        self.setLayout(layout)

    def load_note(self, index):
        self.text_area.setPlainText(self.notes[index]["body"])
