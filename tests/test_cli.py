"""Unit tests for CLI helpers and workflow entry points."""

import json
from argparse import Namespace
from pathlib import Path

import pytest

from src.cli import (
    create_parser,
    parse_snapshot_specs,
    print_demo_timeline,
    run_multi_snapshot_mode,
)
from src.models import ForensicTimeline


class TestCliHelpers:
    """Test user-facing CLI helper output."""

    def test_print_demo_timeline_embeds_json(self, capsys):
        """Demo mode should show the JSON timeline directly in terminal output."""
        timeline = ForensicTimeline(events=[], run_mode="demo", data_origin="synthetic")

        print_demo_timeline(timeline)
        output = capsys.readouterr().out

        assert "DEMO TIMELINE JSON" in output
        json_start = output.index("{")
        parsed = json.loads(output[json_start:])
        assert parsed["run_mode"] == "demo"
        assert parsed["data_origin"] == "synthetic"

    def test_examples_flag_prints_copy_paste_commands(self, capsys):
        """CLI should expose example commands for demo and disk-image usage."""
        parser = create_parser()

        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])

        assert exc.value.code == 0
        output = capsys.readouterr().out
        assert "python -m src.cli --demo" in output
        assert 'python -m src.cli --mount "E:\\" --output timeline.json --pretty' in output
        assert "--snapshot A=E:\\" in output

    def test_parse_snapshot_specs_rejects_invalid_label(self):
        """Snapshot labels should stay filename-safe."""
        with pytest.raises(ValueError, match="Invalid snapshot label"):
            parse_snapshot_specs(["phase a=E:\\"])

    def test_run_multi_snapshot_mode_exports_one_file_per_snapshot(self, monkeypatch):
        """Multi-snapshot mode should emit predictable phase-based output names."""
        exported = []
        output_dir = Path(".snapshot-test-output")

        def fake_build_timeline(args):
            return ForensicTimeline(events=[], phase=args.phase)

        def fake_export_timeline(args, timeline, output_path):
            exported.append((args.mount, timeline.phase, output_path))

        def fake_mkdir(self, parents=False, exist_ok=False):
            return None

        monkeypatch.setattr("src.cli.build_forensic_timeline", fake_build_timeline)
        monkeypatch.setattr("src.cli.export_timeline", fake_export_timeline)
        monkeypatch.setattr("src.cli.Path.mkdir", fake_mkdir)

        args = Namespace(
            demo=False,
            mount=None,
            snapshot=["A=E:\\", "B=F:\\"],
            output_dir=str(output_dir),
            format="json",
            hash=True,
            pretty=True,
            phase=None,
        )

        run_multi_snapshot_mode(args)

        assert exported == [
            ("E:\\", "A", str(output_dir / "phase_a.json")),
            ("F:\\", "B", str(output_dir / "phase_b.json")),
        ]
