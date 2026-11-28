import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

def test_imports():
    from main import main
    from telegram_proxy import check_telegram_proxy

    assert callable(main)
    assert callable(check_telegram_proxy)
