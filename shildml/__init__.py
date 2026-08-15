"""shildml — SHILD's AI-decision fusion and ML classifier.

Pure Python, zero dependency on supybot/limnoria or any IRC library, so it
can be unit-tested and replayed offline without a running bot. The Limnoria
plugin (plugins/Shild/) imports this package; this package must never import
anything IRC-related.
"""

from . import features, schema, artifact, infer, fusion  # noqa: F401

__all__ = ["features", "schema", "artifact", "infer", "fusion"]
