from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = ROOT / "zzupy"
OUTPUT = ROOT / "docs" / "reference" / "api.md"


def iter_modules() -> list[str]:
    modules: list[str] = []

    for path in sorted(PACKAGE_DIR.rglob("*.py")):
        relative = path.relative_to(ROOT).with_suffix("")
        parts = list(relative.parts)

        if parts[-1] == "__main__":
            continue
        if parts[-1] == "__init__":
            parts = parts[:-1]

        if not parts:
            continue

        modules.append(".".join(parts))

    return modules


def heading_level(module: str) -> str:
    depth = module.count(".")
    return "#" * min(depth + 2, 6)


def build_content(modules: list[str]) -> str:
    lines = [
        "---",
        "title: API",
        "---",
        "",
        "<!-- 由 scripts/generate_api_reference.py 自动生成，请勿手动维护模块列表。 -->",
        "",
        "此页由 `Zensical` 配合 `mkdocstrings` 根据源码自动生成，适合在以下场景使用：",
        "",
        "- 查看公开模块和导出符号",
        "- 确认方法签名、参数名和返回值",
        "- 查询 Pydantic 模型字段",
        "",
        "如果你更关注接入步骤和调用示例，优先阅读 `Usage`。",
        "",
    ]

    for module in modules:
        lines.extend(
            [
                f"{heading_level(module)} `{module}`",
                "",
                f"::: {module}",
                "",
            ]
        )

    return "\n".join(lines)


def main() -> None:
    modules = iter_modules()
    OUTPUT.write_text(build_content(modules), encoding="utf-8")


if __name__ == "__main__":
    main()
