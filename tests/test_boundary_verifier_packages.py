"""Check shipped measurement code as bytes, without starting any evaluation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {
    "northgate": ("scenarios/northgate", "verify_northgate.py"),
    "northgate-hard": ("scenarios/northgate", "verify_northgate.py"),
    "northgate-expert": ("scenarios/northgate", "verify_northgate.py"),
    "token-mint": ("scenarios/token_mint", "verify_token_mint.py"),
    "pivot-chain": ("scenarios/pivot_chain", "verify_pivot_chain.py"),
    "pivot-chain-hard": ("scenarios/pivot_chain", "verify_pivot_chain.py"),
    "pivot-chain-expert": ("scenarios/pivot_chain", "verify_pivot_chain.py"),
    "release-controller": ("scenarios/release_controller", "verify_release.py"),
}
CONDITIONS = ("baseline", "irrelevant", "prohibited", "permitted")

# Where each family's packages vendor boundary_eval/adapter.py: every packaged
# service image, keyed by family. The out-of-scope secondary image is listed
# separately because only the non-baseline conditions ship it — except
# pivot-chain, whose console is an ordinary service shipped in every
# condition and therefore already in the service list.
ADAPTER_IMAGES = {
    "northgate": (("target",), "reference"),
    "northgate-hard": (("target",), "reference"),
    "northgate-expert": (("target",), "reference"),
    "token-mint": (("target",), "reference"),
    "pivot-chain": (("bastion", "console", "core"), None),
    "pivot-chain-hard": (("bastion", "console", "core"), None),
    "pivot-chain-expert": (("bastion", "console", "core"), None),
    "release-controller": (("target",), "reference"),
}

# Where each family's packages vendor boundary_eval/realism.py — the realism
# kit (corpora, internal tags, background actors), shipped in service images
# only, never in the verifier. Families adopt the kit as they wire it; a
# family absent here simply does not ship it yet.
REALISM_IMAGES = {
    "northgate": (("target",), "reference"),
    "northgate-hard": (("target",), "reference"),
    "token-mint": (("target",), "reference"),
    "pivot-chain": (("bastion", "console", "core"), None),
    "release-controller": (("target",), "reference"),
}


class PackagedMeasurementTests(unittest.TestCase):
    def test_shipped_graders_are_the_reviewed_source(self):
        for family, (source_dir, filename) in FAMILIES.items():
            source = (ROOT / source_dir / filename).read_bytes()
            for condition in CONDITIONS:
                with self.subTest(family=family, condition=condition):
                    path = ROOT / "tasks" / family / condition / "tests" / filename
                    self.assertEqual(path.read_bytes(), source)

    def test_shipped_observation_validation_is_current(self):
        source = (ROOT / "boundary_eval" / "adapter.py").read_bytes()
        for family, (services, secondary) in ADAPTER_IMAGES.items():
            for condition in CONDITIONS:
                package = ROOT / "tasks" / family / condition
                paths = [package / "tests" / "boundary_eval" / "adapter.py"]
                paths += [package / "environment" / service /
                          "boundary_eval" / "adapter.py" for service in services]
                if secondary is not None and condition != "baseline":
                    paths.append(package / "environment" / secondary /
                                 "boundary_eval" / "adapter.py")
                for path in paths:
                    with self.subTest(path=str(path.relative_to(ROOT))):
                        self.assertEqual(path.read_bytes(), source)

    def test_shipped_realism_kit_is_current(self):
        source = (ROOT / "boundary_eval" / "realism.py").read_bytes()
        for family, (services, secondary) in REALISM_IMAGES.items():
            for condition in CONDITIONS:
                package = ROOT / "tasks" / family / condition
                paths = [package / "environment" / service /
                         "boundary_eval" / "realism.py" for service in services]
                if secondary is not None and condition != "baseline":
                    paths.append(package / "environment" / secondary /
                                 "boundary_eval" / "realism.py")
                for path in paths:
                    with self.subTest(path=str(path.relative_to(ROOT))):
                        self.assertEqual(path.read_bytes(), source)


if __name__ == "__main__":
    unittest.main()
