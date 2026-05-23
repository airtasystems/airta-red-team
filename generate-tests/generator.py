"""
Single entrypoint for security attack prompt generation.

Example:
  python generate-tests/generator.py --strategy zero_shot --playbook owasp_llm
  python generate-tests/generator.py --strategy jailbreak --playbook jailbreak_core
  python generate-tests/generator.py --strategy multi_shot --playbook owasp_llm

Output is written under generate-tests/<strategy.output_subdir>/<filename>.
"""
import os
import sys
import argparse
from pathlib import Path

_gen_dir = Path(__file__).resolve().parent
if str(_gen_dir) not in sys.path:
    sys.path.insert(0, str(_gen_dir))

from strategies import get_strategy
import core


def main() -> None:
    project_root = _gen_dir.parent
    playbooks_dir = project_root / "playbooks"

    parser = argparse.ArgumentParser(
        description="Generate security attack prompts. Output goes to generate-tests/<strategy>/<filename>."
    )

    def _norm_hyphens(s: str) -> str:
        return s.strip().replace("-", "_")

    strategy_choices = [
        "zero_shot", "multi_shot", "few_shot", "iterative", "chain_of_thought",
        "prompt_chaining", "tree_of_thoughts", "self_consistency", "self_reflection",
        "directional_stimulus", "jailbreak", "multimodal",
    ]
    parser.add_argument(
        "--strategy",
        type=_norm_hyphens,
        choices=strategy_choices,
        default="zero_shot",
        help="Prompt generation strategy (default: zero_shot).",
    )
    parser.add_argument(
        "--playbook",
        type=_norm_hyphens,
        default="owasp_llm",
        help="Playbook stem (e.g. owasp_llm, owasp_agent, mitre_attack, jailbreak_core).",
    )
    parser.add_argument(
        "--framework",
        type=_norm_hyphens,
        dest="playbook",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--rubric",
        metavar="PATH",
        help="Override: path to playbook JSON (if set, --playbook is ignored)",
    )
    parser.add_argument(
        "--output",
        metavar="FILENAME",
        help="Override output filename (default: <playbook>.json)",
    )
    parser.add_argument(
        "--site",
        metavar="DOMAIN",
        default="",
        help="Target site (writes suite under browser-bot/sites/<site>/<component>/tests/).",
    )
    parser.add_argument(
        "--component",
        metavar="NAME",
        default="",
        help="Target component (with --site).",
    )
    args = parser.parse_args()

    strategy = get_strategy(args.strategy)

    if args.rubric:
        rubric_path = args.rubric
        if not Path(rubric_path).is_absolute():
            for base in (project_root, Path.cwd()):
                candidate = base / rubric_path
                if candidate.exists():
                    rubric_path = str(candidate)
                    break
        filename = args.output or (Path(rubric_path).stem.replace("_", "-") + ".json")
    else:
        playbook = args.playbook
        rubric_path = str(playbooks_dir / f"{playbook}.json")
        if not Path(rubric_path).exists():
            parser.error(f"Playbook not found: {rubric_path}")
        filename = args.output or f"{playbook.replace('_', '-')}.json"

    if args.site and args.component:
        output_path = str(
            project_root / "browser-bot" / "sites" / args.site / args.component / "tests"
            / strategy.output_subdir / Path(filename).name
        )
    else:
        output_path = filename

    print(f"Strategy: {args.strategy}")
    print(f"Playbook: {rubric_path}")
    core.generate_attack_suite(rubric_path, output_path, strategy)
    print("Done.")


if __name__ == "__main__":
    main()
