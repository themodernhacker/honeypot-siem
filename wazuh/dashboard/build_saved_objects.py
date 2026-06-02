#!/usr/bin/env python3
"""
Generate an OpenSearch Dashboards saved-objects file for the Cowrie honeypot.

Running this writes  cowrie-dashboard.ndjson  next to this script. Import it in
Wazuh via:  Dashboard menu -> Dashboards Management -> Saved Objects -> Import.

Every visualisation is scoped to  rule.groups: cowrie  and points at the
wazuh-alerts-* index pattern (id is the same string in a default Wazuh install).
The Cowrie fields (data.src_ip, data.username, data.password, data.input) and
the rule.* fields are all mapped as keyword, so they aggregate directly.
"""
import json
import os

INDEX_ID = "wazuh-alerts-*"
QUERY = {"query": "rule.groups: cowrie", "language": "kuery"}
OUT = os.path.join(os.path.dirname(__file__), "cowrie-dashboard.ndjson")


def search_source():
    return json.dumps({
        "query": QUERY,
        "filter": [],
        "indexRefName": "kibana.savedObjectMeta.searchSourceJSON.index",
    })


def terms_table(vid, title, field, size=10):
    vis = {
        "title": title,
        "type": "table",
        "params": {
            "perPage": 10, "showPartialRows": False,
            "showMetricsAtAllLevels": False, "showTotal": False,
            "totalFunc": "sum", "percentageCol": "",
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": field, "orderBy": "1", "order": "desc",
                        "size": size, "otherBucket": False, "missingBucket": False}},
        ],
    }
    return obj(vid, title, vis)


def terms_bar(vid, title, field, size=10):
    vis = {
        "title": title,
        "type": "histogram",
        "params": {
            "type": "histogram", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "left",
                              "show": True, "scale": {"type": "linear"}, "labels": {"show": True, "filter": False, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "bottom",
                           "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": True, "truncate": 100}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "histogram", "mode": "normal", "data": {"label": "Count", "id": "1"},
                              "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True}],
            "addTooltip": True, "addLegend": False, "legendPosition": "right", "times": [], "addTimeMarker": False,
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc",
                        "size": size, "otherBucket": False, "missingBucket": False}},
        ],
    }
    return obj(vid, title, vis)


def pie(vid, title, field, size=10):
    vis = {
        "title": title,
        "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right",
                   "isDonut": True, "labels": {"show": True, "values": True, "last_level": True, "truncate": 100}},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": field, "orderBy": "1", "order": "desc",
                        "size": size, "otherBucket": False, "missingBucket": False}},
        ],
    }
    return obj(vid, title, vis)


def over_time(vid, title):
    vis = {
        "title": title,
        "type": "area",
        "params": {
            "type": "area", "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                              "show": True, "scale": {"type": "linear"}, "labels": {"show": True, "filter": True, "truncate": 100}, "title": {}}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left",
                           "show": True, "scale": {"type": "linear", "mode": "normal"},
                           "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100}, "title": {"text": "Count"}}],
            "seriesParams": [{"show": True, "type": "area", "mode": "stacked", "data": {"label": "Count", "id": "1"},
                              "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": True, "showCircles": True, "interpolate": "linear"}],
            "addTooltip": True, "addLegend": False, "legendPosition": "right", "times": [], "addTimeMarker": False,
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "timestamp", "useNormalizedOpenSearchInterval": True,
                        "interval": "auto", "drop_partials": False, "min_doc_count": 1, "extended_bounds": {}}},
        ],
    }
    return obj(vid, title, vis)


def obj(vid, title, vis):
    return {
        "id": vid,
        "type": "visualization",
        "attributes": {
            "title": title,
            "visState": json.dumps(vis),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
        },
        "references": [
            {"name": "kibana.savedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": INDEX_ID}
        ],
    }


# --- the visualisations -----------------------------------------------------
vizzes = [
    over_time("cowrie-alerts-over-time", "Cowrie - Alerts over time"),
    terms_table("cowrie-top-src-ips", "Cowrie - Top source IPs", "data.src_ip"),
    pie("cowrie-mitre", "Cowrie - Alerts by MITRE technique", "rule.mitre.technique"),
    terms_bar("cowrie-top-usernames", "Cowrie - Top usernames tried", "data.username"),
    terms_bar("cowrie-top-passwords", "Cowrie - Top passwords tried", "data.password"),
    terms_table("cowrie-commands", "Cowrie - Commands run", "data.input", size=20),
    terms_table("cowrie-top-rules", "Cowrie - Top detection rules", "rule.description"),
]

# --- the dashboard ----------------------------------------------------------
layout = [
    ("cowrie-alerts-over-time", 0, 0, 48, 12),
    ("cowrie-top-src-ips", 0, 12, 24, 15),
    ("cowrie-mitre", 24, 12, 24, 15),
    ("cowrie-top-usernames", 0, 27, 24, 15),
    ("cowrie-top-passwords", 24, 27, 24, 15),
    ("cowrie-commands", 0, 42, 28, 18),
    ("cowrie-top-rules", 28, 42, 20, 18),
]
panels, refs = [], []
for i, (vid, x, y, w, h) in enumerate(layout):
    name = f"panel_{i}"
    panels.append({"version": "2.13.0", "panelIndex": str(i + 1),
                   "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                   "embeddableConfig": {}, "panelRefName": name})
    refs.append({"name": name, "type": "visualization", "id": vid})

dashboard = {
    "id": "cowrie-overview",
    "type": "dashboard",
    "attributes": {
        "title": "Honeypot SIEM - Cowrie overview",
        "hits": 0,
        "description": "Attacks against the Cowrie SSH honeypot, mapped to MITRE ATT&CK.",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeTo": "now",
        "timeFrom": "now-7d",
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": refs,
}

with open(OUT, "w", encoding="utf-8", newline="\n") as f:
    for o in vizzes + [dashboard]:
        f.write(json.dumps(o) + "\n")

print(f"wrote {len(vizzes)} visualisations + 1 dashboard to {OUT}")
