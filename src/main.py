import sys
import networkx as nx

try:
    import slither
    print("Successfully imported slither")
except ImportError:
    print("Failed to import slither")
    sys.exit(1)

try:
    print(f"Successfully imported networkx version: {nx.__version__}")
except ImportError:
    print("Failed to import networkx")
    sys.exit(1)

print("Environment setup verification successful!")
