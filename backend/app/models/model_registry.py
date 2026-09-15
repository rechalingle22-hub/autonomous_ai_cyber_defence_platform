"""ML model registry and drift monitoring ORM models."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import String, Float, Boolean, DateTime, Enum, JSON, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from backend.app.database.session import Base


class ModelFamily(str, enum.Enum):
    ISOLATION_FOREST = "ISOLATION_FOREST"
    AUTOENCODER = "AUTOENCODER"
    RANDOM_FOREST = "RANDOM_FOREST"
    XGBOOST = "XGBOOST"
    LSTM = "LSTM"


class MLModel(Base):
    __tablename__ = "ml_models"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    model_name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    model_family: Mapped[ModelFamily] = mapped_column(Enum(ModelFamily), nullable=False)
    active_version: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    versions = relationship("ModelVersion", back_populates="model", cascade="all, delete-orphan")


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    model_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("ml_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    validation_f1: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    validation_precision: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    validation_recall: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    artifact_path: Mapped[str] = mapped_column(String(255), nullable=False)
    is_deployed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    model = relationship("MLModel", back_populates="versions")
    drift_evaluations = relationship("DriftMetric", back_populates="model_version", cascade="all, delete-orphan")


class DriftMetric(Base):
    __tablename__ = "drift_metrics"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    model_version_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("model_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    psi_metric: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    ks_test_pvalue: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    drift_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    drifted_features: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    model_version = relationship("ModelVersion", back_populates="drift_evaluations")

