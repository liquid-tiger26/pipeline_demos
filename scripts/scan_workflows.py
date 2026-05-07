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
    return {"workflow_files": files, "findings": []}

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
        
