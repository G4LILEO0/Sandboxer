"""Who may see which analysis (ADM-7).

An analysis with an empty ``restricted_to`` is visible to every user. A restricted one is
visible to the listed users, its submitter and admins only, and is left out of search.
Service tokens see unrestricted analyses and their own submissions.
"""

from fastapi import HTTPException
from sqlalchemy import ColumnElement, and_, any_, literal, or_

from sandbox.api.auth import Principal
from sandbox.db.models import Analysis


def visible_clause(principal: Principal) -> ColumnElement[bool]:
    if principal.is_admin:
        return and_(True)
    unrestricted = Analysis.restricted_to == []
    if principal.kind == "client":
        return or_(unrestricted, Analysis.api_client_id == principal.client_id)
    return or_(
        unrestricted,
        literal(principal.subject) == any_(Analysis.restricted_to),
        Analysis.submitted_by == principal.subject,
    )


def can_see(principal: Principal, analysis: Analysis) -> bool:
    if principal.is_admin or not analysis.restricted_to:
        return True
    if principal.kind == "client":
        return analysis.api_client_id == principal.client_id
    return principal.subject in analysis.restricted_to or analysis.submitted_by == principal.subject


async def get_visible(db, principal: Principal, analysis_id: str) -> Analysis:
    analysis = await db.get(Analysis, analysis_id)
    # Restricted analyses look exactly like missing ones to everyone else.
    if analysis is None or not can_see(principal, analysis):
        raise HTTPException(404, {"error": "not_found", "detail": f"No analysis {analysis_id}"})
    return analysis
