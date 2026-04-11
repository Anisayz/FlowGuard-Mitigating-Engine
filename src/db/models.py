import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from src.db.database import Base


class Alert(Base):

    __tablename__ = "alerts"

    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    received_at     = Column(DateTime,  default=datetime.utcnow, nullable=False, index=True)

    # Source of the alert
    source          = Column(String(32),  nullable=False)  # "ml_engine" | "ids" | "manual"

    # ML verdict fields
    verdict         = Column(String(16),  nullable=False)  # ATTACK | SUSPECT | ANOMALY | BENIGN
    action          = Column(String(16),  nullable=False)  # block | ratelimit | isolate | log_only
    label           = Column(String(128), nullable=True)   # CIC-IDS2018 class label
    confidence      = Column(Float,       nullable=True)
    ml_source       = Column(String(16),  nullable=True)   # RF | RF+AE | AE

    # Flow identity — used to match the OVS flow
    src_ip          = Column(String(45),  nullable=False, index=True)
    dst_ip          = Column(String(45),  nullable=True)
    src_port        = Column(Integer,     nullable=True)
    dst_port        = Column(Integer,     nullable=True)
    protocol        = Column(Integer,     nullable=True)   # 6=TCP 17=UDP

    # Timestamps from the flow itself (milliseconds since epoch)
    start_time_ms   = Column(BigInteger,  nullable=True)
    end_time_ms     = Column(BigInteger,  nullable=True)

    # Anomaly detection fields
    anomaly_score   = Column(Float,   nullable=True)
    anomaly_flagged = Column(Boolean, default=False)

    # Link to the rule that was installed as a result (null if log_only)
    rule_id         = Column(
        UUID(as_uuid=True),
        ForeignKey("rules.rule_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    rule = relationship("Rule", back_populates="alerts", foreign_keys=[rule_id])

    def __repr__(self):
        return (
            f"<Alert id={self.id} verdict={self.verdict} "
            f"label={self.label} src={self.src_ip}>"
        )


class Rule(Base):

    __tablename__ = "rules"

    rule_id      = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    src_ip       = Column(String(45),  nullable=False, index=True)
    action       = Column(String(16),  nullable=False)  # block | ratelimit | isolate
    dpid         = Column(BigInteger,  nullable=True)   # OVS switch ID (filled from Ryu response)
    source       = Column(String(32),  nullable=False)  # "manual" | "mitigation_engine"
    rate_kbps    = Column(Integer,     nullable=True)   # only for ratelimit action
    created_at   = Column(DateTime,   default=datetime.utcnow, nullable=False, index=True)
    deleted_at   = Column(DateTime,   nullable=True)    # null = still active
    idle_timeout = Column(Integer,    default=300)
    hard_timeout = Column(Integer,    default=3600)
    active       = Column(Boolean,    default=True,     nullable=False, index=True)

    # The alert that triggered this rule (null for manual rules)
    alert_id     = Column(BigInteger, ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)

    alerts = relationship("Alert", back_populates="rule", foreign_keys="Alert.rule_id")

    def __repr__(self):
        return (
            f"<Rule rule_id={self.rule_id} action={self.action} "
            f"src={self.src_ip} active={self.active}>"
        )