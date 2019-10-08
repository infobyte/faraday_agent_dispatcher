import pytest
from faraday_agent_dispatcher.config import save_config, reset_config, CONFIG


def test_save_config():
    reset_config()
    with pytest.raises(ValueError):
        save_config(None)
    with pytest.raises(ValueError):
        save_config(CONFIG['default'])