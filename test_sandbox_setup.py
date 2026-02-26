import sys
from unittest.mock import MagicMock
sys.modules['src'] = MagicMock()
from src.agents.workers.test_writer_sandbox import SandboxManager

print(hasattr(SandboxManager, '_ensure_foundry_deps'))
print(not hasattr(SandboxManager, '_run_forge_install'))
