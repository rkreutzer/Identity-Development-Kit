#!/usr/bin/env python3
"""Run standalone IDK pack CI with Maven prerequisites, using only this repository."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib

PACKS = ("core", "infra", "identity-security", "protocols", "platform", "wallet-lib")
PUBLIC_REPOSITORY = "Sphereon-Opensource/Identity-Development-Kit"
PRIVATE_REPOSITORY = "Sphereon-Opensource/Identity-Development-Kit-private"


def without_comments(content: str) -> str:
    """Keep Kotlin strings and line positions while removing nested comments."""
    output, index = [], 0
    while index < len(content):
        if content.startswith("//", index):
            end = content.find("\n", index)
            index = len(content) if end < 0 else end
        elif content.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(content) and depth:
                if content.startswith("/*", index):
                    depth += 1
                    index += 2
                elif content.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    if content[index] == "\n":
                        output.append("\n")
                    index += 1
        elif content[index] in ('"', "'"):
            delimiter = content[index] * (3 if content.startswith('"""', index) else 1)
            output.append(delimiter)
            index += len(delimiter)
            while index < len(content):
                if content.startswith(delimiter, index):
                    output.append(delimiter)
                    index += len(delimiter)
                    break
                if content[index] == "\\" and len(delimiter) == 1:
                    output.append(content[index:index + 2])
                    index += 2
                else:
                    output.append(content[index])
                    index += 1
        else:
            output.append(content[index])
            index += 1
    return "".join(output)


def accessor(name: str) -> str:
    parts = name.split("-")
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def inventory(root: Path) -> tuple[dict, dict]:
    root = root.resolve()
    modules, registered = {}, {}
    for pack in PACKS:
        settings = without_comments((root / pack / "settings.gradle.kts").read_text(encoding="utf-8"))
        matches = re.findall(r'\binclude(?:Local|Mapped)\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', settings)
        if not matches:
            raise ValueError(f"No mapped modules in {pack}/settings.gradle.kts")
        registered[pack] = set()
        for name, relative in matches:
            path = (root / pack / relative).resolve()
            try:
                owner = path.relative_to(root).parts[0]
            except ValueError as error:
                raise ValueError(f"Module {name} escapes the IDK checkout") from error
            if owner not in PACKS or not (path / "build.gradle.kts").is_file():
                raise ValueError(f"Invalid IDK module {name}: {path}")
            if name in modules and modules[name]["path"] != path:
                raise ValueError(f"Conflicting ownership for {name}")
            modules[name] = {"path": path, "pack": owner}
            registered[pack].add(name)
    return modules, registered


def internal_catalog(root: Path) -> dict[str, str]:
    catalog = root / "gradle" / "libs.versions.toml"
    if not catalog.is_file():
        return {}
    result = {}
    for alias, declaration in tomllib.loads(catalog.read_text(encoding="utf-8")).get("libraries", {}).items():
        coordinate = declaration if isinstance(declaration, str) else declaration.get("module", "")
        if coordinate.startswith("com.sphereon.idk:"):
            name = coordinate.split(":")[1]
            result[alias.replace("-", ".").replace("_", ".")] = name
            result[accessor(alias)] = name
    return result


def dependencies(path: Path, modules: dict, catalog: dict) -> tuple[set, set]:
    """Recognize declared project/Maven/catalog edges; test edges do not order publication."""
    production, tests, stack = set(), set(), []
    by_accessor = {accessor(name): name for name in modules}
    content = without_comments(path.read_text(encoding="utf-8"))
    for line in content.splitlines():
        test_scope = bool(re.search(r'\b(?:\w*(?:Test|Tests)|test\w*)\b|["\']test["\']', line))
        for _ in range(line.count("{")):
            stack.append(test_scope or (stack[-1] if stack else False))
        refs = set(re.findall(r'project\(\s*":([^"$]+)"\s*\)', line))
        refs.update(re.findall(r'["\']com\.sphereon\.idk:([^:"\']+):[^"\']+["\']', line))
        for name in re.findall(r'\bprojects\.([a-zA-Z]\w*)', line):
            if name not in by_accessor:
                raise ValueError(f"Unknown project accessor {name} in {path}")
            refs.add(by_accessor[name])
        for alias in re.findall(r'\blibs\.([\w.]+)', line):
            if alias in catalog:
                refs.add(catalog[alias])
        unknown = refs - modules.keys()
        if unknown:
            raise ValueError(f"Unknown IDK dependencies in {path}: {', '.join(sorted(unknown))}")
        (tests if (stack[-1] if stack else test_scope) else production).update(refs)
        for _ in range(line.count("}")):
            if stack:
                stack.pop()
    return production, tests


def pack_graph(root: Path, modules: dict) -> dict[str, set[str]]:
    graph = {pack: set() for pack in PACKS}
    catalog = internal_catalog(root)
    for name, module in modules.items():
        # A BOM declares constraints, not compile dependencies; it can generate its
        # catalog without resolving every constrained module.
        if name.endswith("-bom"):
            continue
        production, _tests = dependencies(module["path"] / "build.gradle.kts", modules, catalog)
        for dependency in production:
            owner = modules[dependency]["pack"]
            if owner != module["pack"]:
                graph[module["pack"]].add(owner)
    return graph


def publication_order(graph: dict[str, set[str]]) -> list[str]:
    result, visiting = [], []

    def visit(pack: str) -> None:
        if pack in visiting:
            cycle = visiting[visiting.index(pack):] + [pack]
            raise ValueError("Production pack dependency cycle: " + " -> ".join(cycle))
        if pack in result:
            return
        visiting.append(pack)
        for dependency in sorted(graph[pack]):
            if dependency not in graph:
                raise ValueError(f"Unknown prerequisite pack {dependency}")
            visit(dependency)
        visiting.pop()
        result.append(pack)

    for pack in graph:
        visit(pack)
    return result


def publication_allowed(mode: str, environment: dict) -> bool:
    branch = environment.get("GITHUB_REF_NAME", "")
    if mode == "private":
        return (environment.get("GITHUB_REPOSITORY") == PRIVATE_REPOSITORY
                and environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and branch == "codex/infra-owned-workspaces"
                and environment.get("GITHUB_REF") == "refs/heads/" + branch)
    return (mode == "public"
            and environment.get("GITHUB_REPOSITORY") == PUBLIC_REPOSITORY
            and ((environment.get("GITHUB_EVENT_NAME") == "push" and branch in {"main", "develop"})
                 or (environment.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                     and branch in {"main", "develop", "codex/infra-owned-workspaces"}
                     and environment.get("GITHUB_REF") == "refs/heads/" + branch)))


def exclusions(mode: str, registered: set[str]) -> list[str]:
    if mode == "public":
        candidates = ["jvmTest", "koverVerify", ":lib-crypto-kms-provider-aws:kotest",
                      ":lib-crypto-kms-provider-azure:kotest"]
    else:
        candidates = ["koverVerify", ":lib-crypto-kms-provider-aws:jvmTest",
                      ":lib-crypto-kms-provider-azure:jvmTest", ":lib-data-link-http-client:jvmTest"]
    # Fully qualified exclusions belong only to the pack registering that module.
    return [task for task in candidates if not task.startswith(":") or task.split(":")[1] in registered]


def preparation_stages(ordered: list[str], mode: str) -> list[dict]:
    stages = []
    for pack in ordered:
        tasks = ["publishAllPublicationsToCiPrerequisitesRepository"]
        if mode == "public":
            tasks[:0] = ["kotlinUpgradePackageLock", "kotlinWasmUpgradePackageLock"]
        stages.append({"phase": "prepare", "pack": pack, "tasks": tasks, "exclusions": []})
    return stages


def plan(root: Path, mode: str, publish: bool, environment: dict, remote_only: bool = False, snapshot_prerequisites_only: bool = False, publish_modules: str = "") -> list[dict]:
    selected = []
    if publish_modules:
        if mode != "private" or not publish or remote_only or not snapshot_prerequisites_only:
            raise ValueError("Selected Maven publication requires private --publish --snapshot-prerequisites-only and forbids --remote-only")
        names = publish_modules.split(",")
        if any(not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", name) for name in names):
            raise ValueError("Invalid selected Maven module name")
        selected = sorted(set(names))
    if snapshot_prerequisites_only:
        if mode != "private" or not publish or remote_only:
            raise ValueError("Snapshot prerequisite publication requires private --publish and forbids --remote-only")
        versions = dict(line.strip().split("=", 1) for line in (root / "platform-version.properties").read_text().splitlines()
                        if line.strip() and not line.lstrip().startswith("#") and "=" in line)
        if not versions.get("platformVersion", "").endswith("-SNAPSHOT"):
            raise ValueError("Snapshot prerequisite publication requires a SNAPSHOT platformVersion")
    if remote_only and publish:
        raise ValueError("Remote-only acceptance cannot also publish")
    if publish and not publication_allowed(mode, environment):
        raise ValueError("Remote publication is restricted to owning public main/develop push or explicitly authorized owning branch dispatch CI")
    modules, registered = inventory(root)
    ordered = publication_order(pack_graph(root, modules))
    if selected:
        for name in selected:
            if name not in modules or name.endswith("-bom"):
                raise ValueError(f"Unknown or unsupported selected Maven module: {name}")
            source = without_comments((modules[name]["path"] / "build.gradle.kts").read_text(encoding="utf-8"))
            if not re.search(r"\balias\(sphereonplug\.plugins\.com\.(?:vanniktech\.maven\.publish|sphereon\.gradle\.plugin\.project\.publication)\)|\bid\([\"'](?:maven-publish|com\.vanniktech\.maven\.publish)[\"']\)|`maven-publish`", source):
                raise ValueError(f"Selected module does not declare a Maven publication plugin: {name}")
        packs = [pack for pack in ordered if any(modules[name]["pack"] == pack for name in selected)]
        # Changed peer APIs must exist before any selected pack can be checked.
        # Prepare every pack into this job's private Maven repository; these
        # prerequisites do not establish remote-only consumer acceptance.
        checks = [{"phase": "check", "pack": pack, "tasks": ["build"],
                   "exclusions": exclusions(mode, registered.get(pack, set()))}
                  for pack in packs]
        publications = [{"phase": "publish", "pack": pack,
                         "tasks": [f":{name}:publishAllPublicationsToSphereon-opensourceRepository"
                                   for name in selected if modules[name]["pack"] == pack],
                         "exclusions": [], "selected_publication": True} for pack in packs]
        return preparation_stages(ordered, mode) + checks + publications
    stages = preparation_stages([] if remote_only else ordered, mode)
    # Test dependencies may point back to a later production pack. Run checks only
    # after every pack has produced its Maven artifacts; do not turn those edges
    # into source composites or weaken the checks to break the test cycle.
    checked_packs = ordered if snapshot_prerequisites_only else [*ordered, "."]
    for pack in checked_packs:
        tasks = ["check" if mode == "public" else "build"]
        if pack == ".":
            # The root's owning guards are not guaranteed by subproject build
            # selection. Retain that selection and explicitly run root check.
            tasks.append(":check")
        stages.append({"phase": "check", "pack": pack, "tasks": tasks,
                       "exclusions": exclusions(mode, registered.get(pack, set()))})
    if publish:
        for pack in checked_packs:
            stages.append({"phase": "publish", "pack": pack,
                           "tasks": ["publishCiMavenRemote" if mode == "private" else "publish"],
                           "exclusions": []})
    return stages


# Public CI runs on Linux, which cannot build the iOS targets. Declaring them anyway makes Gradle skip them
# silently (kotlin.native.ignoreDisabledTargets), publishes artifacts without iOS variants and leaves the common
# metadata of every consumer pack unable to see those artifacts. Build exactly the targets this host can produce.
PUBLIC_TARGETS = "jvm,js,wasmjs,linuxx64"


def stage_targets(stage: dict, mode: str) -> str:
    """Kotlin targets of one stage. Private checks stay JVM-only for speed, but every publication uses the
    public target set: a snapshot replaces the Gradle module metadata of its coordinates, so a JVM-only
    publish would drop the JS and wasm variants an earlier publish carried."""
    return PUBLIC_TARGETS if mode == "public" or stage["phase"] == "publish" else "jvm"


def command(root: Path, stage: dict, mode: str, repository: Path, remote_only: bool = False, refresh_dependencies: bool = False) -> list[str]:
    remote_only = remote_only or stage.get("remote_inputs", False)
    wrapper = root / ("gradlew.bat" if os.name == "nt" else "gradlew")
    arguments = [str(wrapper), "--project-dir", str(root / stage["pack"]), "--build-cache",
                 "-Dkmp.targets=" + stage_targets(stage, mode),
                 "-Didk.ci.prerequisites=" + str(repository.resolve()),
                 "-Didk.ci.publish=" + str(stage["phase"] == "publish").lower(),
                 "--init-script", str(root / ".github/scripts/pack-ci.init.gradle"), *stage["tasks"]]
    if mode == "private" and stage["phase"] == "check":
        # Report independent failures in this pack before exiting nonzero. The
        # caller collects required check failures before remote publication.
        arguments.append("--continue")
    if remote_only:
        arguments.extend(["-Didk.ci.remote-only=true", "--no-build-cache", "--refresh-dependencies"])
    if refresh_dependencies and not remote_only:
        arguments.append("--refresh-dependencies")
    for task in stage["exclusions"]:
        if task == "koverVerify":
            # Some standalone packs apply no coverage plugin. Match optional
            # coverage tasks in the init script instead of an invalid CLI -x.
            arguments.append("-Didk.ci.exclude-kover=true")
        else:
            arguments.extend(["-x", task])
    return arguments


def execute(root: Path, stages: list[dict], mode: str, repository: Path, runner=subprocess.run, remote_only: bool = False) -> None:
    environment = os.environ.copy()
    if any(stage.get("selected_publication") and stage["phase"] == "publish" for stage in stages):
        if not environment.get("NEXUS_USERNAME") or not environment.get("NEXUS_PASSWORD"):
            raise ValueError("Selected Maven publication requires owning Nexus credentials")
    # This repository runner owns its ephemeral Maven prerequisites. Unrelated
    # source-selection or worktree inputs must not redirect ordinary CI.
    for key in ("IDK_LOCAL_PACKS", "WORKSPACE_SOURCE_MODULES", "WORKSPACE_MAVEN_REPO",
                "WORKTREE_MAVEN_REPO", "WORKSPACE_TOOL_MAVEN_REPO"):
        environment.pop(key, None)
    bootstrap = any(stage["phase"] == "publish" for stage in stages)
    check_failures = []
    for stage in stages:
        if check_failures and stage["phase"] != "check":
            raise check_failures[0]
        print(f"IDK CI {stage['phase']}: {stage['pack']}", flush=True)
        try:
            runner(command(root, stage, mode, repository, remote_only, refresh_dependencies=bootstrap), cwd=root, env=environment, check=True)
        except subprocess.CalledProcessError as error:
            if mode != "private" or stage["phase"] != "check":
                raise
            # All preparation already succeeded. Gather other required pack
            # checks, retaining failure and forbidding every publication stage.
            print(f"IDK CI check failed: {stage['pack']} (exit {error.returncode})", flush=True)
            check_failures.append(error)
    if check_failures:
        raise check_failures[0]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("private", "public"), required=True)
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--remote-only", action="store_true", help="Verify published dependencies without file Maven repositories or local pack prerequisites")
    parser.add_argument("--snapshot-prerequisites-only", action="store_true", help="Publish checked SNAPSHOT producer packs; full remote consumer acceptance remains required")
    parser.add_argument("--publish-modules", default="", help="Comma-separated owning Maven module names; private checked SNAPSHOT publication only")
    parser.add_argument("--plan", action="store_true", help="Print the exact CI plan without running Gradle")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    stages = plan(root, args.mode, args.publish, os.environ, args.remote_only, args.snapshot_prerequisites_only, args.publish_modules)
    if args.snapshot_prerequisites_only:
        print("Snapshot producer prerequisites only: full remote consumer/root acceptance remains required", flush=True)
    if args.plan:
        print(json.dumps(stages, indent=2))
        return
    if os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("Gradle execution through this runner requires GitHub Actions")
    with tempfile.TemporaryDirectory(prefix="idk-ci-maven-", dir=os.environ.get("RUNNER_TEMP")) as directory:
        execute(root, stages, args.mode, Path(directory), remote_only=args.remote_only)


if __name__ == "__main__":
    main()
