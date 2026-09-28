from detlab.coverage import TECHNIQUE_NAMES, main, techniques


def test_every_technique_has_a_name():
    missing = set(techniques()) - set(TECHNIQUE_NAMES)
    assert not missing, f"add names to TECHNIQUE_NAMES: {missing}"


def test_readme_table_is_current():
    assert main(["--check"]) == 0, "run: python -m detlab.coverage"
