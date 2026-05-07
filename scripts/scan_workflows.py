from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, START, END
import os, glob, json, yaml, re

class State(TypedDict):
    repo_path: str
    workflow_files: List[str]
    findings: List[Dict[str, Any]]
    report_path: str

def discover(state: State):
    patterns = [
        os.path.join(state["repo_path"], ".github", "workflows", "*.yml"),
        os.path.join(state["repo_path"], ".github", "workflows", "*.yaml"),
    ]
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    return {"workflow_files": files, "findings": []}

def _normalize_on_field(on_field):
    if isinstance(on_field, str):
        return [on_field]
    if isinstance(on_field, list):
        return on_field
    if isinstance(on_field, dict):
        return list(on_field.keys())
    return []

def scan(state: State):
    findings = []
    for path in state["workflow_files"]:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}

        if not isinstance(doc, dict):
            continue

        triggers = _normalize_on_field(doc.get("on"))
        permissions = doc.get("permissions", {})
        jobs = doc.get("jobs", {})

        if "pull_request_target" in triggers:
            findings.append({
                "file": path,
                "job": None,
                "step": None,
                "rule": "dangerous-trigger",
                "severity": "high",
                "message": "Workflow uses pull_request_target"
            })

        if permissions == "write-all":
            findings.append({
                "file": path,
                "job": None,
                "step": None,
                "rule": "broad-permissions",
                "severity": "medium",
                "message": "Workflow uses write-all permissions"
            })

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            job_perms = job.get("permissions")
            if job_perms == "write-all":
                findings.append({
                    "file": path,
                    "job": job_name,
                    "step": None,
                    "rule": "broad-permissions",
                    "severity": "medium",
                    "message": "Job uses write-all permissions"
                })

            for i, step in enumerate(job.get("steps", [])):
                if not isinstance(step, dict):
                    continue

                uses = step.get("uses", "")
                run = step.get("run", "")
                name = step.get("name", f"step_{i}")

                if uses and re.search(r"@(main|master|latest)$", uses):
                    findings.append({
                        "file": path,
                        "job": job_name,
                        "step": i,
                        "step_name": name,
                        "rule": "mutable-action-ref",
                        "severity": "medium",
                        "message": f"Action is pinned to a mutable ref: {uses}"
                    })

                if uses and "actions/checkout@" in uses:
                    if re.search(r"@(main|master|latest)$", uses):
                        findings.append({
                            "file": path,
                            "job": job_name,
                            "step": i,
                            "step_name": name,
                            "rule": "mutable-checkout-ref",
                            "severity": "high",
                            "message": f"Checkout uses mutable ref: {uses}"
                        })

                if run:
                    if "curl " in run or "wget " in run:
                        findings.append({
                            "file": path,
                            "job": job_name,
                            "step": i,
                            "step_name": name,
                            "rule": "remote-download",
                            "severity": "high",
                            "message": "Downloads remote content in run step"
                        })

                    if re.search(r"(?i)(secret|token|password)\s*[:=]", run):
                        findings.append({
                            "file": path,
                            "job": job_name,
                            "step": i,
                            "step_name": name,
                            "rule": "possible-secret-exposure",
                            "severity": "high",
                            "message": "Potential secret-like value in run step"
                        })

    return {"findings": findings}

def write_report(state: State):
    os.makedirs("output", exist_ok=True)
    out = state["report_path"]
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "repo_path": state["repo_path"],
            "workflow_files": state["workflow_files"],
            "finding_count": len(state["findings"]),
            "findings": state["findings"]
        }, f, indent=2)
    return {"report_path": out}

g = StateGraph(State)
g.add_node("discover", discover)
g.add_node("scan", scan)
g.add_node("write", write_report)
g.add_edge(START, "discover")
g.add_edge("discover", "scan")
g.add_edge("scan", "write")
g.add_edge("write", END)
app = g.compile()
