"""AIRTA Systems export entrypoint.

Keeps the public import path stable while the implementation lives in
``pipeline.export_genbounty``.
"""
from .export_genbounty import export_pipeline_report

__all__ = ["export_pipeline_report"]
