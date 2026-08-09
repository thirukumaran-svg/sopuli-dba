"""Output layer: the run document and the serialisers that emit it.

This package is the only place allowed to turn objects into bytes a user sees,
which is what makes invariant 2 enforceable — redaction is applied here, once,
rather than at every call site that handles a secret.
"""
