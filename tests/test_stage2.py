from pathlib import Path

import pytest

from autosbom.common.models import Vulnerability
from autosbom.stage2_vex.context import DeviceContext
from autosbom.stage2_vex.openvex import export_openvex
from autosbom.stage2_vex.review import ReviewError, ReviewStore
from autosbom.stage2_vex.rules import (
    RuleEngine, STATUS_FIXED, STATUS_NOT_AFFECTED,
    J_CODE_NOT_IN_EXECUTE_PATH,
)

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def context():
    return DeviceContext.load(FIXTURES / "device-context.json")


def test_context_feature_hierarchy(context):
    assert context.feature_enabled("bluetooth") is True
    assert context.feature_enabled("bluetooth.avrcp") is False
    assert context.feature_enabled("cellular") is None
    # disabled parent implies disabled child
    ctx2 = DeviceContext(features={"bluetooth": False})
    assert ctx2.feature_enabled("bluetooth.avrcp") is False


def test_perfektblue_avrcp_rule(context):
    """The PerfektBlue demo scenario: AVRCP disabled -> CVE-2024-45434
    proposed not_affected; the RFCOMM CVEs stay (bluetooth itself is on)."""
    engine = RuleEngine(context=context)
    avrcp = Vulnerability(cve_id="CVE-2024-45434", component="bluez5",
                          severity="CRITICAL", cvss=8.0,
                          description="Use-after-free in AVRCP service")
    rfcomm = Vulnerability(cve_id="CVE-2024-45433", component="bluez5",
                           severity="MEDIUM",
                           description="Incorrect function termination in RFCOMM")

    p = engine.evaluate(avrcp)
    assert p is not None
    assert p.proposed_status == STATUS_NOT_AFFECTED
    assert p.justification == J_CODE_NOT_IN_EXECUTE_PATH
    assert p.rule == "feature-disabled"
    assert p.state == "pending"

    assert engine.evaluate(rfcomm) is None  # bluetooth enabled -> finding stands


def test_backport_annotation_rule(context):
    annotations = {
        "CVE-2022-9999": {
            "status": "fixed", "keyword": "backported-patch",
            "reason": "debian patch", "source": "CVE_STATUS",
            "recipe": "zlib_1.2.13.bb",
        }
    }
    engine = RuleEngine(context=context, backport_annotations=annotations)
    v = Vulnerability(cve_id="CVE-2022-9999", component="zlib")
    p = engine.evaluate(v)
    assert p is not None
    assert p.proposed_status == STATUS_FIXED
    assert p.rule == "yocto-backport-annotation"


def test_not_in_execute_path_rule(context):
    engine = RuleEngine(context=context)
    v = Vulnerability(cve_id="CVE-2019-7317", component="libpng",
                      description="use-after-free in png_image_free")
    p = engine.evaluate(v)
    assert p is not None
    assert p.rule == "not-in-execute-path"


def test_network_isolated_rule_needs_network_wording(context):
    engine = RuleEngine(context=context)
    remote = Vulnerability(cve_id="CVE-2022-1111", component="zlib",
                           description="remote attacker via crafted network stream")
    local = Vulnerability(cve_id="CVE-2022-2222", component="zlib",
                          description="crash when parsing local file")
    assert engine.evaluate(remote) is not None
    assert engine.evaluate(local) is None


def test_review_gate_blocks_unapproved(tmp_path, context):
    engine = RuleEngine(context=context)
    v = Vulnerability(cve_id="CVE-2024-45434", component="bluez5",
                      description="AVRCP UAF")
    proposals = engine.evaluate_all([v])
    store = ReviewStore.load(tmp_path / "review.json")
    assert store.add_proposals(proposals) == 1
    store.save()

    # Nothing suppressed while pending.
    assert store.suppressed_cves() == set()

    # Export of pending proposals is refused.
    with pytest.raises(ValueError, match="non-approved"):
        export_openvex(store.pending(), author="t", product_purl="pkg:generic/x")

    # Approval requires a reviewer name.
    with pytest.raises(ReviewError):
        store.approve("CVE-2024-45434", "bluez5", reviewer="")

    store.approve("CVE-2024-45434", "bluez5", reviewer="Michael",
                  note="AVRCP disabled in build config, verified on device")
    assert store.suppressed_cves() == {"CVE-2024-45434"}

    doc = export_openvex(store.approved(), author="Michael",
                         product_purl="pkg:generic/pi5-ivi-demo")
    stmt = doc["statements"][0]
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == J_CODE_NOT_IN_EXECUTE_PATH
    assert doc["@context"].startswith("https://openvex.dev/ns/")


def test_rerun_does_not_clobber_review(tmp_path, context):
    engine = RuleEngine(context=context)
    v = Vulnerability(cve_id="CVE-2024-45434", component="bluez5",
                      description="AVRCP UAF")
    store = ReviewStore.load(tmp_path / "review.json")
    store.add_proposals(engine.evaluate_all([v]))
    store.approve("CVE-2024-45434", "bluez5", reviewer="Michael")
    store.save()

    store2 = ReviewStore.load(tmp_path / "review.json")
    added = store2.add_proposals(engine.evaluate_all([v]))
    assert added == 0
    assert store2.suppressed_cves() == {"CVE-2024-45434"}


def test_rejected_not_suppressed(tmp_path, context):
    engine = RuleEngine(context=context)
    v = Vulnerability(cve_id="CVE-2024-45434", component="bluez5",
                      description="AVRCP UAF")
    store = ReviewStore.load(tmp_path / "review.json")
    store.add_proposals(engine.evaluate_all([v]))
    store.reject("CVE-2024-45434", "bluez5", reviewer="Michael",
                 note="cannot verify AVRCP is actually off — keep the finding")
    assert store.suppressed_cves() == set()
