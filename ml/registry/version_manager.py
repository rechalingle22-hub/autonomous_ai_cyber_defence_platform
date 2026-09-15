# type: ignore
# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUndefinedVariable=false, reportGeneralTypeIssues=false, reportAttributeAccessIssue=false, reportAssignmentType=false, reportArgumentType=false, reportOptionalMemberAccess=false
# ruff: noqa
# flake8: noqa
"""Model Registry & Version Lifecycle Manager.

Governs:
1. Model registration and artifact tracking
2. Lifecycle stage promotions (Challenger -> Champion) and rollback
3. Audit persistence of validation metrics (F1, Precision, Recall) and drift evaluations
"""

import os
import sys
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
VENV_SITE = os.path.join(ROOT_DIR, ".venv", "lib", "python3.13", "site-packages")
for p in (ROOT_DIR, VENV_SITE):
    if p not in sys.path and os.path.exists(p):
        sys.path.insert(0, p)

from sqlalchemy import select, desc  # type: ignore
from sqlalchemy.orm import selectinload  # type: ignore
from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore

from backend.app.models.model_registry import MLModel, ModelVersion, DriftMetric, ModelFamily  # type: ignore


class ModelRegistryManager:
    """Manages ML model metadata, version lineage, deployment state, and drift telemetry."""

    async def list_models(self, db: AsyncSession) -> List[MLModel]:
        """Lists all registered models with their associated versions."""
        stmt = select(MLModel).options(selectinload(MLModel.versions)).order_by(MLModel.model_name)
        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def get_or_create_model(
        self,
        db: AsyncSession,
        model_name: str,
        family: ModelFamily,
    ) -> MLModel:
        """Retrieves an existing model or registers a new model entry."""
        stmt = select(MLModel).where(MLModel.model_name == model_name)
        res = await db.execute(stmt)
        model = res.scalar_one_or_none()

        if not model:
            model = MLModel(
                id=str(uuid.uuid4()),
                model_name=model_name,
                model_family=family,
                active_version="v1.0.0",
                created_at=datetime.now(timezone.utc),
            )
            db.add(model)
            await db.commit()
            await db.refresh(model)

        return model

    async def register_version(
        self,
        db: AsyncSession,
        model_name: str,
        family: ModelFamily,
        version: str,
        metrics: Dict[str, float],
        artifact_path: str,
        is_deployed: bool = False,
    ) -> ModelVersion:
        """Registers a newly trained model version in the registry."""
        model = await self.get_or_create_model(db, model_name, family)

        # Demote previous active versions if this one is immediately deployed
        if is_deployed:
            stmt = select(ModelVersion).where(ModelVersion.model_id == model.id)
            res = await db.execute(stmt)
            for existing in res.scalars().all():
                existing.is_deployed = False
            model.active_version = version

        version_record = ModelVersion(
            id=str(uuid.uuid4()),
            model_id=model.id,
            version=version,
            validation_f1=float(metrics.get("f1", 0.0)),
            validation_precision=float(metrics.get("precision", 0.0)),
            validation_recall=float(metrics.get("recall", 0.0)),
            artifact_path=artifact_path,
            is_deployed=is_deployed,
            trained_at=datetime.now(timezone.utc),
        )
        db.add(version_record)
        await db.commit()
        await db.refresh(version_record)
        return version_record

    async def promote_version(
        self,
        db: AsyncSession,
        version_id: str,
    ) -> ModelVersion:
        """Promotes a candidate/challenger model version to the active deployed champion."""
        stmt = select(ModelVersion).where(ModelVersion.id == version_id)
        res = await db.execute(stmt)
        target = res.scalar_one_or_none()

        if not target:
            raise ValueError(f"ModelVersion with ID '{version_id}' does not exist.")

        # Demote all sibling versions
        sibling_stmt = select(ModelVersion).where(ModelVersion.model_id == target.model_id)
        siblings_res = await db.execute(sibling_stmt)
        for sib in siblings_res.scalars().all():
            sib.is_deployed = False

        # Promote target
        target.is_deployed = True

        # Update parent model's active version
        model_stmt = select(MLModel).where(MLModel.id == target.model_id)
        model_res = await db.execute(model_stmt)
        model = model_res.scalar_one_or_none()
        if model:
            model.active_version = target.version

        await db.commit()
        await db.refresh(target)
        return target

    async def get_model_versions(
        self,
        db: AsyncSession,
        model_id: str,
    ) -> List[ModelVersion]:
        """Retrieves all versions of a specific model ordered by training date descending."""
        stmt = select(ModelVersion).where(ModelVersion.model_id == model_id).order_by(desc(ModelVersion.trained_at))
        res = await db.execute(stmt)
        return list(res.scalars().all())

    async def record_drift_metric(
        self,
        db: AsyncSession,
        model_version_id: str,
        psi_metric: float,
        ks_pvalue: float,
        drift_detected: bool,
        drifted_features: Dict[str, Any],
    ) -> DriftMetric:
        """Persists a drift evaluation audit record."""
        metric_record = DriftMetric(
            id=str(uuid.uuid4()),
            model_version_id=model_version_id,
            psi_metric=psi_metric,
            ks_test_pvalue=ks_pvalue,
            drift_detected=drift_detected,
            drifted_features=drifted_features,
            evaluated_at=datetime.now(timezone.utc),
        )
        db.add(metric_record)
        await db.commit()
        await db.refresh(metric_record)
        return metric_record

    async def seed_initial_registry(self, db: AsyncSession) -> None:
        """Seeds standard production models if database is empty."""
        stmt = select(MLModel)
        res = await db.execute(stmt)
        existing = res.scalars().all()
        if len(existing) > 0:
            return

        defaults = [
            ("xgboost_attack_classifier", ModelFamily.XGBOOST, "v1.0.0", 1.0, 1.0, 1.0, "ml/artifacts/xgboost.joblib"),
            ("random_forest_classifier", ModelFamily.RANDOM_FOREST, "v1.0.0", 1.0, 1.0, 1.0, "ml/artifacts/random_forest.joblib"),
            ("isolation_forest_detector", ModelFamily.ISOLATION_FOREST, "v1.0.0", 0.9925, 0.9910, 0.9940, "ml/artifacts/isolation_forest.joblib"),
            ("autoencoder_detector", ModelFamily.AUTOENCODER, "v1.0.0", 0.9852, 0.9820, 0.9880, "ml/artifacts/autoencoder.pt"),
        ]

        for name, family, ver, f1, prec, rec, path in defaults:
            await self.register_version(
                db=db,
                model_name=name,
                family=family,
                version=ver,
                metrics={"f1": f1, "precision": prec, "recall": rec},
                artifact_path=path,
                is_deployed=True,
            )


model_registry = ModelRegistryManager()
