def normalize_node_id(node_id: str) -> str:
    """
    Convert any node ID format to the canonical graph format (Contract::function).
    Handles:
      - Contract::function  → unchanged
      - Contract.function   → Contract::function
      - Contract.func(uint) → Contract::func(uint)  (future-proof)
    """
    if not node_id or "::" in node_id:
        return node_id

    # Simple case: Contract.function → Contract::function
    if "." in node_id and node_id.count(".") == 1:
        contract, func = node_id.split(".", 1)
        return f"{contract}::{func}"

    # More complex cases (e.g. overloaded functions) — keep as-is for now
    return node_id


def denormalize_node_id(node_id: str) -> str:
    """Optional: Convert back to dot notation for display/human readability."""
    return node_id.replace("::", ".") if "::" in node_id else node_id
