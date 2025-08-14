# finance-research-data

finance-research-data — scaffolded by **newpackage**.

**Author:** Mihai Ion  
**License:** MIT (c) 2025 Mihai Ion

## Layout
```
finance-research-data/
  ├─ pyproject.toml
  ├─ README.md
  ├─ LICENSE
  ├─ .gitignore
  └─ src/
     └─ finance_research_data/
        └─ __init__.py
```

## Development install
```bash
pip install -e .
```

## Notes
- MIT license included.
- `src` layout with explicit package map in `pyproject.toml`.
- A console script entry point is pre-wired to `finance_research_data.cli:main` and exposes the `finance_research_data` command. Create `src/finance_research_data/cli.py` with a `main()` to activate it.
