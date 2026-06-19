"""Detection package.

NOTE: intentionally light — importing submodules (``catalog``, ``detectors``,
``correlation``) directly avoids a circular import between correlation and the
AI analysis module. Use ``from app.detection.detectors import run_detectors`` etc.
"""
