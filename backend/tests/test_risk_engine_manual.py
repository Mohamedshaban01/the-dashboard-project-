"""
Manual unit test for UnifiedRiskEngine.
Tests score/penalty logic without requiring a database session.
"""
from app.services.unified_risk_engine import UnifiedRiskEngine
from app.models.scan import SeverityLevel


def test_high_risk_port_weights():
    """Verify telnet and SMB carry the expected deduction weights."""
    assert UnifiedRiskEngine.HIGH_RISK_PORTS[23][1] == 20,  "Telnet should carry 20-pt penalty"
    assert UnifiedRiskEngine.HIGH_RISK_PORTS[445][1] == 20, "SMB should carry 20-pt penalty"
    print("✅ High-risk port weights verified")


def test_severity_weights():
    """Verify severity → score deduction mapping."""
    assert UnifiedRiskEngine.SEVERITY_WEIGHTS[SeverityLevel.CRITICAL] == 25
    assert UnifiedRiskEngine.SEVERITY_WEIGHTS[SeverityLevel.HIGH] == 15
    assert UnifiedRiskEngine.SEVERITY_WEIGHTS[SeverityLevel.LOW] == 2
    print("✅ Severity weights verified")


def test_asset_value_multipliers():
    """Verify asset criticality multipliers."""
    assert UnifiedRiskEngine.ASSET_VALUE_MAP["CRITICAL"] == 1.5
    assert UnifiedRiskEngine.ASSET_VALUE_MAP["MEDIUM"] == 1.0
    print("✅ Asset value multipliers verified")


if __name__ == "__main__":
    test_high_risk_port_weights()
    test_severity_weights()
    test_asset_value_multipliers()
    print("\nAll manual risk engine tests passed.")
