"""PyTorch model definition — only ever imported by train.py (the [train]
extra). The running bot never imports torch; see infer.py for the
numpy-only inference path used in production, which is metadata-driven
rather than tied to this exact module structure.
"""
from __future__ import annotations

from .features import ACTIONS, N_FEATURES

try:
    import torch.nn as nn
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "torch is required for training — install with: pip install '.[train]'"
    ) from e


class ShildNet(nn.Module):
    """22 -> 64 -> 32 -> 3. Same shape as the original ~/shild-ai/model.py
    MLP, just 3 output classes instead of 4 (kick is a rule, not an ML
    class — see features.ACTIONS)."""

    def __init__(self, n_features: int = N_FEATURES, n_actions: int = len(ACTIONS)):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, n_actions),
        )

    def forward(self, x):
        return self.net(x)

    # Activation that follows each Linear layer, by position — passed to
    # artifact.layer_spec_from_torch_state_dict so export doesn't need to
    # know or care which numeric indices nn.Sequential assigned.
    ACTIVATIONS = ["relu", "relu", None]
