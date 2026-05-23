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
import json
from pathlib import Path

_gen_dir = Path(__file__).resolve().parent
if str(_gen_dir) not in sys.path:
    sys.path.insert(0, str(_gen_dir))

from strategies import get_strategy
import core


def _apply_site_component_rubric_env(project_root: Path, site: str, component: str) -> None:
    site = (site or "").strip()
    component = (component or "").strip()
    if site:
        os.environ["AIRTA_SITE"] = site
    if component:
        os.environ["AIRTA_COMPONENT"] = component
    sites_root = project_root / "browser-bot" / "sites"
    if site:
        company_p = sites_root / site / "company.json"
        if company_p.is_file():
            resolved = str(company_p.resolve())
            os.environ["COMPANY_RUBRIC_JSON"] = resolved
            os.environ["COMPONENT_RUBRIC_JSON"] = resolved
            os.environ["COMPONENT_RUBRIC_CACHE_JSON"] = resolved
    if site and component:
        spec_p = sites_root / site / component / "component.json"
        if spec_p.is_file():
            os.environ["COMPONENT_SPEC_RUBRIC_JSON"] = str(spec_p.resolve())


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
        "--run-type",
        choices=["playbook", "framework", "tools", "capabilities"],
        default="playbook",
        help="playbook: generate category attack prompts. tools/capabilities: component tool tests.",
    )
    parser.add_argument(
        "--component-rubric",
        metavar="PATH",
        help="Path to component spec JSON for tools/capabilities append.",
    )
    parser.add_argument(
        "--append-to",
        metavar="PATH",
        help="Append tools/capabilities category to existing suite JSON.",
    )
    parser.add_argument(
        "--site",
        metavar="DOMAIN",
        default="",
    )
    parser.add_argument(
        "--component",
        metavar="NAME",
        default="",
    )
    args = parser.parse_args()
    if args.run_type == "framework":
        args.run_type = "playbook"

    strategy = get_strategy(args.strategy)

    if args.site and args.component:
        _apply_site_component_rubric_env(project_root, args.site, args.component)

    if args.run_type in ("tools", "capabilities"):
        comp = args.component_rubric
        if not comp and args.site and args.component:
            default_spec = (
                project_root / "browser-bot" / "sites" / args.site / args.component / "component.json"
            )
            if default_spec.is_file():
                comp = str(default_spec.resolve())
        if not comp:
            parser.error("--component-rubric required for tools/capabilities")
        if not Path(comp).is_absolute():
            for base in (project_root, Path.cwd()):
                candidate = base / comp
                if candidate.exists():
                    comp = str(candidate)
                    break
        comp_path = Path(comp)
        if not comp_path.exists():
            parser.error(f"Component rubric not found: {comp}")
        append_to = None
        output_path = None
        if args.append_to:
            p = Path(args.append_to)
            append_to = str(p.resolve()) if p.is_absolute() else str((project_root / args.append_to).resolve())
        else:
            try:
                data = json.loads(comp_path.read_text(encoding="utf-8"))
                component_name = data.get("component") or comp_path.stem
            except Exception:
                component_name = comp_path.stem
            output_path = args.output or f"{args.run_type}/{component_name}.json"
        framework_rubric_path = None
        if append_to:
            framework_rubric_path = str(playbooks_dir / f"{args.playbook}.json")
        core.generate_tools_or_capabilities_suite(
            comp, args.run_type, strategy,
            output_path=output_path,
            append_to_path=append_to,
            framework_rubric_path=framework_rubric_path,
        )
        print("Done.")
        return

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
