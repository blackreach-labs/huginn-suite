# app/core/html_utils.py
"""
HTML output utilities for safe rendering in Qt text widgets.

All scan results, error messages, and any other data that originates from
network responses, user input, or the file system must be passed through
``h()`` before being embedded in an HTML string that is sent to a Qt
``QTextEdit``, ``QTextBrowser``, or similar widget.

Usage
-----
::


    # Safe — banner comes from a network response
    self.signals.output.emit(
        f"<p style='color: #87CEEB;'>[INFO] Banner: {h(banner)}</p><br>"
    )

    # Safe — error message may contain angle brackets
    widget.setHtml(f"<p style='color: #FF4500;'>[ERROR] {h(message)}</p>")

Why not use Qt's built-in escaping?
------------------------------------
``Qt.convertFromPlainText()`` and ``QTextDocument.setPlainText()`` exist but
are not always convenient when building styled HTML fragments.  ``html.escape``
from the standard library is the simplest, most explicit choice and has no
external dependencies.
"""

import html as _html


def h(value: object) -> str:
    """Escape *value* for safe embedding in an HTML context.

    Converts the value to a string and escapes ``&``, ``<``, ``>``, ``"``,
    and ``'`` so that it cannot break out of an HTML attribute or element.

    Examples::

        h("<script>alert(1)</script>")
        # → '&lt;script&gt;alert(1)&lt;/script&gt;'

        h('He said "hello"')
        # → 'He said &quot;hello&quot;'

        h(None)
        # → ''
    """
    if value is None:
        return ""
    return _html.escape(str(value), quote=True)


def safe_p(text: object, color: str = "#DCDCDC", extra_style: str = "") -> str:
    """Return a ``<p>`` element with *text* safely escaped.

    Args:
        text:        The text content (will be HTML-escaped).
        color:       CSS colour for the ``style`` attribute.
        extra_style: Additional CSS to append to the ``style`` attribute.

    Returns:
        An HTML string like ``"<p style='color: #DCDCDC;'>safe text</p><br>"``.
    """
    style = f"color: {color};"
    if extra_style:
        style += " " + extra_style
    return f"<p style='{style}'>{h(text)}</p><br>"
