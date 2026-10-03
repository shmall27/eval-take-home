"""Boundary evaluation: evidence contract v1 and offline scoring.

    from boundary_eval.contract import validate_manifest, validate_events
    from boundary_eval.score import score

The package root deliberately imports nothing. A verifier image carries only this
file, contract.py and score.py, so importing boundary_eval must not pull in any
module that lives elsewhere in the repository.
"""
