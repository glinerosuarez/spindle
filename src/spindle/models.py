from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field

Category = Literal["travel", "finance", "auth", "health", "work", "personal", "promo", "other"]
Action = Literal["allow", "ask", "deny"]
Level = Literal["light", "standard", "strict"]


@dataclass
class Email:
    id: str
    thread_id: str
    sender: str
    to: str
    subject: str
    date: str
    snippet: str
    body_text: str
    body_html: Optional[str] = None
    labels: List[str] = field(default_factory=list)



class Classification(BaseModel):
    category: Category
    sensitivity: Literal["low", "medium", "high"]
    source: Literal["rules", "llm", "llm_error", "override"]
    reason: str


class InjectionReport(BaseModel):
    hidden_text: bool
    hidden_text_excerpt: str = ""
    heuristic_hits: List[str] = Field(default_factory=list)
    llm_suspected: Optional[bool] = None
    llm_confidence: Optional[float] = None
    quarantine: bool
    reason: str


class Redaction(BaseModel):
    type: str
    count: int


class Decision(BaseModel):
    action: Literal["allow", "ask", "deny", "quarantine", "passthrough"]
    reason: str
    request_id: Optional[int] = None


class CustomRule(BaseModel):
    name: str
    pattern: str


class AgentPolicy(BaseModel):
    description: str = ""
    passthrough: bool = False
    protection_level: Level = "standard"
    access: Dict[Category, Action] = Field(default_factory=dict)
    max_results: int = 20
    custom_rules: List[CustomRule] = Field(default_factory=list)



class PolicyFile(BaseModel):
    agents: Dict[str, AgentPolicy]
