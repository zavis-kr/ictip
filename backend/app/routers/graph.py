"""IOC relationship graph API router."""
from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.database import get_db
from app.models import Threat, ThreatFeed
from app.auth import get_current_user

router = APIRouter(prefix="/api/graph", tags=["graph"])


def _threat_node(threat_id: int, title: str, severity: str) -> Dict[str, Any]:
    color_map = {"긴급": "#2563eb", "높음": "#3b82f6", "중간": "#60a5fa", "낮음": "#93c5fd"}
    return {
        "id": f"threat_{threat_id}",
        "type": "threat",
        "label": f"T{threat_id}: {(title or '')[:30]}",
        "color": color_map.get(severity or "", "#2563eb"),
        "size": 20,
        "data": {"threat_id": threat_id, "severity": severity},
    }


def _actor_node(actor: str) -> Dict[str, Any]:
    return {
        "id": f"actor_{actor}",
        "type": "actor",
        "label": actor,
        "color": "#dc2626",
        "size": 25,
        "data": {"actor": actor},
    }


def _ioc_node(ioc_value: str, ioc_type: str) -> Dict[str, Any]:
    return {
        "id": f"ioc_{ioc_value[:50]}",
        "type": "ioc",
        "label": f"[{ioc_type}] {(ioc_value or '')[:30]}",
        "color": "#f97316",
        "size": 15,
        "data": {"ioc_value": ioc_value, "ioc_type": ioc_type},
    }


def _campaign_node(campaign: str) -> Dict[str, Any]:
    return {
        "id": f"campaign_{campaign}",
        "type": "campaign",
        "label": campaign,
        "color": "#7c3aed",
        "size": 22,
        "data": {"campaign": campaign},
    }


def _edge(source: str, target: str, edge_type: str) -> Dict[str, Any]:
    return {
        "id": f"{source}__{edge_type}__{target}",
        "source": source,
        "target": target,
        "type": edge_type,
        "label": edge_type,
    }


@router.get("/ioc/{threat_id}")
async def get_ioc_graph(
    threat_id: int,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return a relationship graph centered on the given threat."""
    threat = (await db.execute(
        select(Threat).where(Threat.id == threat_id)
    )).scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set = set()

    def add_node(node: Dict[str, Any]):
        if node["id"] not in seen_nodes:
            seen_nodes.add(node["id"])
            nodes.append(node)

    # Central threat node
    center = _threat_node(threat.id, threat.title, threat.severity)
    add_node(center)

    # Actor relationship
    if threat.actor_tag:
        actor_node = _actor_node(threat.actor_tag)
        add_node(actor_node)
        edges.append(_edge(actor_node["id"], center["id"], "uses"))

    # IOC relationship
    if threat.ioc_value and threat.ioc_type:
        ioc_node = _ioc_node(threat.ioc_value, threat.ioc_type)
        add_node(ioc_node)
        edges.append(_edge(center["id"], ioc_node["id"], "uses"))

    # Find related threats (same actor, same IOC type, same threat_type)
    related_q = select(Threat).where(Threat.is_active == True).where(Threat.id != threat_id)
    conditions = []
    if threat.actor_tag:
        conditions.append(Threat.actor_tag == threat.actor_tag)
    if threat.threat_type:
        conditions.append(Threat.threat_type == threat.threat_type)

    from sqlalchemy import or_
    if conditions:
        related_result = await db.execute(
            related_q.where(or_(*conditions)).order_by(desc(Threat.detected_at)).limit(10)
        )
        related_threats = related_result.scalars().all()
        for rt in related_threats:
            rt_node = _threat_node(rt.id, rt.title, rt.severity)
            add_node(rt_node)
            edges.append(_edge(center["id"], rt_node["id"], "related_to"))

            # Related actor
            if rt.actor_tag and rt.actor_tag != threat.actor_tag:
                ra_node = _actor_node(rt.actor_tag)
                add_node(ra_node)
                edges.append(_edge(ra_node["id"], rt_node["id"], "uses"))

            # Related IOC
            if rt.ioc_value and rt.ioc_type:
                ri_node = _ioc_node(rt.ioc_value, rt.ioc_type)
                add_node(ri_node)
                edges.append(_edge(rt_node["id"], ri_node["id"], "uses"))

    # Also pull from ThreatFeed for same actor
    if threat.actor_tag:
        feed_result = await db.execute(
            select(ThreatFeed)
            .where(ThreatFeed.actor_tag == threat.actor_tag)
            .limit(5)
        )
        for tf in feed_result.scalars().all():
            if tf.ioc_value and tf.ioc_type:
                fi_node = _ioc_node(tf.ioc_value, tf.ioc_type)
                add_node(fi_node)
                actor_id = f"actor_{threat.actor_tag}"
                if actor_id in seen_nodes:
                    edges.append(_edge(actor_id, fi_node["id"], "uses"))

    return {"nodes": nodes, "edges": edges, "total_nodes": len(nodes), "total_edges": len(edges)}


@router.get("/actor/{actor_name}")
async def get_actor_graph(
    actor_name: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return a relationship graph centered on the given threat actor."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set = set()

    def add_node(node: Dict[str, Any]):
        if node["id"] not in seen_nodes:
            seen_nodes.add(node["id"])
            nodes.append(node)

    # Central actor node
    center = _actor_node(actor_name)
    add_node(center)

    # Find all threats attributed to this actor
    threats_result = await db.execute(
        select(Threat)
        .where(Threat.actor_tag == actor_name)
        .where(Threat.is_active == True)
        .order_by(desc(Threat.detected_at))
        .limit(20)
    )
    actor_threats = threats_result.scalars().all()

    # Campaign grouping by threat_type
    campaigns: dict = {}
    for t in actor_threats:
        if t.threat_type:
            campaigns[t.threat_type] = campaigns.get(t.threat_type, 0) + 1

    for campaign, count in campaigns.items():
        camp_node = _campaign_node(f"{actor_name}:{campaign}")
        add_node(camp_node)
        edges.append(_edge(center["id"], camp_node["id"], "targets"))

    for t in actor_threats:
        t_node = _threat_node(t.id, t.title, t.severity)
        add_node(t_node)
        edges.append(_edge(center["id"], t_node["id"], "uses"))

        if t.ioc_value and t.ioc_type:
            i_node = _ioc_node(t.ioc_value, t.ioc_type)
            add_node(i_node)
            edges.append(_edge(t_node["id"], i_node["id"], "uses"))

        # Campaign link
        if t.threat_type:
            camp_id = f"campaign_{actor_name}:{t.threat_type}"
            if camp_id in seen_nodes:
                edges.append(_edge(camp_id, t_node["id"], "related_to"))

    # ThreatFeed data for same actor
    feed_result = await db.execute(
        select(ThreatFeed)
        .where(ThreatFeed.actor_tag == actor_name)
        .limit(10)
    )
    for tf in feed_result.scalars().all():
        if tf.ioc_value and tf.ioc_type:
            fi_node = _ioc_node(tf.ioc_value, tf.ioc_type)
            add_node(fi_node)
            edges.append(_edge(center["id"], fi_node["id"], "uses"))

    return {
        "actor": actor_name,
        "nodes": nodes,
        "edges": edges,
        "total_nodes": len(nodes),
        "total_edges": len(edges),
    }


@router.get("/overview")
async def get_overview_graph(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    """Return an overview graph with the top 30 nodes from the entire dataset."""
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    seen_nodes: set = set()

    def add_node(node: Dict[str, Any]):
        if node["id"] not in seen_nodes:
            seen_nodes.add(node["id"])
            nodes.append(node)

    # Top actors by frequency
    actor_result = await db.execute(
        select(Threat.actor_tag, func.count(Threat.id).label("cnt"))
        .where(Threat.actor_tag.isnot(None))
        .where(Threat.is_active == True)
        .group_by(Threat.actor_tag)
        .order_by(desc("cnt"))
        .limit(10)
    )
    actor_rows = actor_result.all()

    for row in actor_rows:
        add_node(_actor_node(row.actor_tag))

    # Top threats (most recent critical/high)
    threat_result = await db.execute(
        select(Threat)
        .where(Threat.is_active == True)
        .where(Threat.severity.in_(["긴급", "높음"]))
        .order_by(desc(Threat.detected_at))
        .limit(15)
    )
    top_threats = threat_result.scalars().all()

    for t in top_threats:
        t_node = _threat_node(t.id, t.title, t.severity)
        add_node(t_node)

        # Actor -> Threat edge
        if t.actor_tag and f"actor_{t.actor_tag}" in seen_nodes:
            edges.append(_edge(f"actor_{t.actor_tag}", t_node["id"], "uses"))

        # Threat -> IOC edge
        if t.ioc_value and t.ioc_type:
            i_node = _ioc_node(t.ioc_value, t.ioc_type)
            add_node(i_node)
            edges.append(_edge(t_node["id"], i_node["id"], "uses"))

    # Top threat type campaigns
    type_result = await db.execute(
        select(Threat.threat_type, func.count(Threat.id).label("cnt"))
        .where(Threat.is_active == True)
        .group_by(Threat.threat_type)
        .order_by(desc("cnt"))
        .limit(5)
    )
    for row in type_result.all():
        if row.threat_type:
            camp_node = _campaign_node(row.threat_type)
            add_node(camp_node)

    # Connect actors to campaign types
    for actor_row in actor_rows:
        actor_id = f"actor_{actor_row.actor_tag}"
        # Find what types this actor uses
        at_result = await db.execute(
            select(Threat.threat_type, func.count(Threat.id).label("cnt"))
            .where(Threat.actor_tag == actor_row.actor_tag)
            .where(Threat.is_active == True)
            .group_by(Threat.threat_type)
            .limit(3)
        )
        for at_row in at_result.all():
            camp_id = f"campaign_{at_row.threat_type}"
            if camp_id in seen_nodes and actor_id in seen_nodes:
                edges.append(_edge(actor_id, camp_id, "targets"))

    # Deduplicate edges
    seen_edges: set = set()
    unique_edges = []
    for e in edges:
        eid = e["id"]
        if eid not in seen_edges:
            seen_edges.add(eid)
            unique_edges.append(e)

    return {
        "nodes": nodes[:30],
        "edges": unique_edges[:60],
        "total_nodes": len(nodes),
        "total_edges": len(unique_edges),
    }
