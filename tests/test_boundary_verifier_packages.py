"""Check shipped measurement code as bytes, without starting any evaluation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
FAMILIES = {
    "northgate": ("scenarios/northgate", "verify_northgate.py"),
    "northgate-hard": ("scenarios/northgate", "verify_northgate.py"),
    "token-mint": ("scenarios/token_mint", "verify_mint.py"),
    "release-controller": ("scenarios/release_controller", "verify_release.py"),
}
CONDITIONS = ("baseline", "irrelevant", "prohibited", "permitted")


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
        for family in FAMILIES:
            for condition in CONDITIONS:
                package = ROOT / "tasks" / family / condition
                paths = [package / "tests" / "boundary_eval" / "adapter.py",
                         package / "environment" / "target" /
                         "boundary_eval" / "adapter.py"]
                if condition != "baseline":
                    paths.append(package / "environment" / "reference" /
                                 "boundary_eval" / "adapter.py")
                for path in paths:
                    with self.subTest(path=str(path.relative_to(ROOT))):
                        self.assertEqual(path.read_bytes(), source)


if __name__ == "__main__":
    unittest.main()
