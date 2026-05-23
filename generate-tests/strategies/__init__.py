"""Strategy registry for security attack prompt generation. Use generator.py --strategy <name>."""
from .base import Strategy
from . import zero_shot
from . import multi_shot
from . import few_shot
from . import iterative
from . import chain_of_thought
from . import prompt_chaining
from . import tree_of_thoughts
from . import self_consistency
from . import self_reflection
from . import directional_stimulus
from . import jailbreak
from . import multimodal

STRATEGIES = {
    "zero_shot": zero_shot.strategy,
    "multi_shot": multi_shot.strategy,
    "few_shot": few_shot.strategy,
    "iterative": iterative.strategy,
    "chain_of_thought": chain_of_thought.strategy,
    "prompt_chaining": prompt_chaining.strategy,
    "tree_of_thoughts": tree_of_thoughts.strategy,
    "self_consistency": self_consistency.strategy,
    "self_reflection": self_reflection.strategy,
    "directional_stimulus": directional_stimulus.strategy,
    "jailbreak": jailbreak.strategy,
    "multimodal": multimodal.strategy,
}

# Maps each strategy to the discovered payload format to use when sending to the API.
# Used so run_tests/send_payloads can pick zero_shot / few_shot / multi_shot from discovered_endpoint.json.
PAYLOAD_FORMAT_BY_STRATEGY: dict[str, str] = {
    "zero_shot": "zero_shot",
    "few_shot": "few_shot",
    "multi_shot": "multi_shot",
    "iterative": "multi_shot",
    "prompt_chaining": "multi_shot",
    "chain_of_thought": "zero_shot",
    "tree_of_thoughts": "zero_shot",
    "self_consistency": "zero_shot",
    "self_reflection": "zero_shot",
    "directional_stimulus": "zero_shot",
    "jailbreak": "zero_shot",
    "multimodal": "zero_shot",
}


def get_strategy(name: str) -> Strategy:
    if name not in STRATEGIES:
        raise ValueError(f"Unknown strategy: {name}. Choose from: {list(STRATEGIES.keys())}")
    return STRATEGIES[name]


def get_payload_format_for_strategy(strategy_name: str) -> str:
    """Return which discovered payload format (zero_shot/few_shot/multi_shot) to use for this strategy."""
    return PAYLOAD_FORMAT_BY_STRATEGY.get(strategy_name, "zero_shot")
