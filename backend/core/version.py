"""Single source of truth for scanner versioning and reproducibility metadata.

Every scan record persists these values so two scans can be compared and any
report can state exactly which code, rule set and model produced it.
"""

APP_VERSION = "0.5.1"
SCANNER_NAME = "Automated MCP Pentester"

# Bumped whenever a static rule's logic or thresholds change in a way that can
# alter findings. See backend/scanners/static/registry.py for the rule catalog.
RULESET_VERSION = "1.2.0"

# ML artifacts are versioned independently; the runtime never silently mixes
# a trained model with features from a different feature-schema version.
ML_MODEL_VERSION = "0.2.0"
ML_FEATURE_SCHEMA_VERSION = "2"

# Bumped when the finding/evidence schema itself changes.
SCANNER_SCHEMA_VERSION = "1"
