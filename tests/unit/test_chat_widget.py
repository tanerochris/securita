"""Regression: chat send buttons show spinner XOR icon, never both.

The global submit handler prepends a .btn-spinner into every submit
button; icon-only chat buttons must hide their icon while busy, and
the htmx chat forms (no page navigation) must remove the spinner and
re-enable the button after each request.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _base() -> str:
    return (ROOT / "src/security_agent/app/templates/base.html").read_text()


def _widget() -> str:
    return (ROOT / "src/security_agent/app/templates/chat_widget.html").read_text()


def test_busy_chat_buttons_hide_their_icon():
    body = _base()
    assert '.chat-send[aria-busy="true"] > svg' in body
    assert '.chat-icon-btn[aria-busy="true"] > svg' in body


def test_send_button_restores_after_htmx_request():
    body = _base()
    assert "window.chatResetSendButton = function (form)" in body
    assert 'btn.querySelector(".btn-spinner")' in body
    assert 'btn.removeAttribute("aria-busy")' in body
    assert "btn.disabled = false" in body
    # Composer restores via chatFormSent; new-chat restores inline.
    assert "window.chatResetSendButton(form)" in body
    assert "chatResetSendButton(this)" in _widget()


def test_composer_send_button_ships_plane_only():
    widget = _widget()
    send = widget.split('class="chat-send"')[1].split("</button>")[0]
    assert "<svg" in send
    assert "btn-spinner" not in send
