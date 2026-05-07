from typing import TypedDict, List, Dict, Any
from langgraph.graph import StateGraph, START, END
import os
import glob
import json
import yaml
import re

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
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    files = sorted(set(files))
    return {
        "workflow_files": files,
        "findings": [],
        "repo_path": state["repo_path"],
        "report_path": state["report_path"],
    }

def normalize_on_field(on_field):
    if isinstance(on_field, str):
        return [on_field]
    if isinstance(on_field, list):
        return on_field
    if isinstance(on_field, dict):
        return list(on_field.keys())
    return []

def add_finding(findings, file, job, step, rule, severity, message, step_name=None):
    item = {
        "file": file,
        "job": job,
        "step": step,
        "rule": rule,
        "severity": severity,
        "message": message,
    }
    if step_name is not None:
        item["step_name"] = step_name
    findings.append(item)

def scan(state: State):
    findings = []

    for path in state["workflow_files"]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except Exception as e:
            add_finding(
                findings,
                path,
                None,
                None,
                "yaml-parse-error",
                "high",
                f"Failed to parse workflow YAML: {e}",
            )
            continue

        if not isinstance(doc, dict):
            add_finding(
                findings,
                path,
                None,
                None,
                "invalid-workflow-root",
                "high",
                "Workflow file root is not a YAML mapping",
            )
            continue

        triggers = normalize_on_field(doc.get("on"))
        permissions = doc.get("permissions", {})
        jobs = doc.get("jobs", {})

        if "pull_request_target" in triggers:
            add_finding(
                findings,
                path,
                None,
                None,
                "dangerous-trigger",
                "high",
                "Workflow uses pull_request_target",
            )

        if permissions == "write-all":
            add_finding(
                findings,
                path,
                None,
                None,
                "broad-permissions",
                "medium",
                "Workflow uses write-all permissions",
            )

        if isinstance(jobs, dict):
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue

                job_perms = job.get("permissions")
                if job_perms == "write-all":
                    add_finding(
                        findings,
                        path,
                        job_name,
                        None,
                        "broad-permissions",
                        "medium",
                        "Job uses write-all permissions",
                    )

                steps = job.get("steps", [])
                if not isinstance(steps, list):
                    continue

                for i, step in enumerate(steps):
                    if not isinstance(step, dict):
                        continue

                    uses = step.get("uses", "")
                    run = step.get("run", "")
                    step_name = step.get("name", f"step_{i}")

                    if uses and re.search(r"@(main|master|latest)$", uses):
                        add_finding(
                            findings,
                            path,
                            job_name,
                            i,
                            "mutable-action-ref",
                            "medium",
                            f"Action is pinned to a mutable ref: {uses}",
                            step_name,
                        )

                    if uses and "actions/checkout@" in uses and re.search(r"@(main|master|latest)$", uses):
                        add_finding(
                            findings,
                            path,
                            job_name,
                            i,
                            "mutable-checkout-ref",
                            "high",
                            f"Checkout uses mutable ref: {uses}",
                            step_name,
                        )

                    if run:
                        if "curl " in run or "wget " in run:
                            add_finding(
                                findings,
                                path,
                                job_name,
                                i,
                                "remote-download",
                                "high",
                                "Downloads remote content in run step",
                                step_name,
                            )

                        if re.search(r"(?i)(secret|token|password)\s*[:=]", run):
                            add_finding(
                                findings,
                                path,
                                job_name,
                                i,
                                "possible-secret-exposure",
                                "high",
                                "Potential secret-like value in run step",
                                step_name,
                            )

    return {"findings": findings}

def write_report(state: State):
    os.makedirs("output", exist_ok=True)
    out = state["report_path"]
    report = {
        "repo_path": state["repo_path"],
        "workflow_files": state["workflow_files"],
        "finding_count": len(state["findings"]),
        "findings": state["findings"],
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Wrote report to {out}")
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

if __name__ == "__main__":
    repo_path = os.environ.get("REPO_PATH", ".")
    report_path = os.environ.get("REPORT_PATH", "output/scan-results.json")

    result = app.invoke({
        "repo_path": repo_path,
        "workflow_files": [],
        "findings": [],
        "report_path": report_path,
    })

    print(result["report_path"])
