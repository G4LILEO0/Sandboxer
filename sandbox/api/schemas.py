from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sandbox.runner.profiles import PROFILES

Mode = Literal["automated", "interactive"]
Verdict = Literal["benign", "suspicious", "malicious", "unknown"]


class Viewport(BaseModel):
    width: int = Field(1366, ge=320, le=3840)
    height: int = Field(768, ge=240, le=2160)


class RunOptions(BaseModel):
    """Per-run options (SUB-6), stored with the analysis."""

    model_config = ConfigDict(extra="forbid")

    locale: str = Field("en-US", pattern=r"^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$")
    timezone: str = Field("UTC", max_length=64, pattern=r"^[A-Za-z0-9_+\-/]+$")
    viewport: Viewport = Field(default_factory=Viewport)
    user_agent_profile: str = Field("chrome-windows", pattern=r"^[a-z0-9\-]{1,40}$")
    time_limit_s: int | None = Field(None, ge=30, le=3600)

    @field_validator("user_agent_profile")
    @classmethod
    def _known_profile(cls, value: str) -> str:
        if value not in PROFILES:
            raise ValueError(f"Unknown profile; choose one of {', '.join(PROFILES)}")
        return value


class AnalysisCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=8192)
    mode: Mode = "automated"
    options: RunOptions = Field(default_factory=RunOptions)
    # ANA-10: None uses the admin default; the UI warns that enrichment shares indicators.
    enrich: bool | None = None
    # ADM-7: restrict visibility to these users (plus the submitter and admins).
    restricted_to: list[str] = Field(default_factory=list, max_length=50)
    # SUB-5: reuse a recent finished report for the same URL instead of detonating again.
    reuse_recent: bool = False


class BulkCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    urls: list[str] = Field(min_length=1, max_length=100)
    mode: Mode = "automated"
    options: RunOptions = Field(default_factory=RunOptions)
    enrich: bool | None = None
    restricted_to: list[str] = Field(default_factory=list, max_length=50)


class AnalysisSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    url: str
    normalised_url: str
    host: str
    mode: Mode
    status: str
    verdict: str | None
    score: int | None
    submitted_by: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class AnalysisCreated(AnalysisSummary):
    warnings: list[str]
    reused: bool = False


class SessionInfo(BaseModel):
    id: str
    interactive: bool
    started_at: datetime
    expires_at: datetime
    paused_at: datetime | None
    ended_at: datetime | None
    end_reason: str | None
    live_view: bool
    seconds_left: int | None


class AnalysisDetail(AnalysisSummary):
    error: str | None
    version: int
    bundle_id: str | None
    enrich: bool
    restricted_to: list[str]
    profile: dict[str, Any]
    time_limit_s: int
    tags: list[str]
    queue_position: int | None = None
    estimated_wait_s: int | None = None
    session: SessionInfo | None = None
    override: dict[str, Any] | None = None


class AnalysisList(BaseModel):
    items: list[AnalysisSummary]
    limit: int
    offset: int
    total: int | None = None


class BulkResult(BaseModel):
    url: str
    ok: bool
    analysis: AnalysisCreated | None = None
    error: str | None = None


class TagBody(BaseModel):
    tag: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9\-_.:]*$")


class OverrideBody(BaseModel):
    verdict: Verdict
    reason: str = Field(min_length=3, max_length=2000)


class NoteBody(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


class ExtendBody(BaseModel):
    seconds: int | None = Field(None, ge=30, le=3600)


class ErrorBody(BaseModel):
    error: str
    detail: str
