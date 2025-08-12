# app/widgets/animated_stacked_widget.py
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve, QPoint, QParallelAnimationGroup
from PyQt6.QtWidgets import QStackedWidget

class AnimatedStackedWidget(QStackedWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.m_duration = 500  # Animation duration in ms
        self.m_animation_type = "fade" # Can be 'fade' or 'slide'
        self.m_next_idx = 0

    def set_animation_duration(self, duration):
        self.m_duration = duration

    def set_animation_type(self, anim_type):
        self.m_animation_type = anim_type

    def animate_to_widget(self, widget):
        self.animate_to_index(self.indexOf(widget))

    def animate_to_index(self, index):
        if self.currentIndex() == index:
            return

        self.m_next_idx = index
        current_widget = self.currentWidget()
        next_widget = self.widget(self.m_next_idx)

        if self.m_animation_type == "fade":
            fade_out = QPropertyAnimation(current_widget, b"windowOpacity")
            fade_out.setDuration(self.m_duration)
            fade_out.setStartValue(1.0)
            fade_out.setEndValue(0.0)

            current_widget.show()
            next_widget.setWindowOpacity(0.0)
            next_widget.show()

            fade_in = QPropertyAnimation(next_widget, b"windowOpacity")
            fade_in.setDuration(self.m_duration)
            fade_in.setStartValue(0.0)
            fade_in.setEndValue(1.0)

            self.anim_group = QParallelAnimationGroup()
            self.anim_group.addAnimation(fade_out)
            self.anim_group.addAnimation(fade_in)
            self.anim_group.finished.connect(self.on_animation_finished)
            self.anim_group.start()

    def on_animation_finished(self):
        self.setCurrentIndex(self.m_next_idx)
        self.widget(self.m_next_idx).setWindowOpacity(1.0)