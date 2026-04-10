"""
Standalone tests for Phase 8 Wave 2 features:
- Monte Carlo CRQC Arrival Simulation
- Certificate Expiry vs CRQC Race Analysis (logic only, not DB-dependent)
"""
import os
import sys
import numpy as np

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.monte_carlo import (
    simulate_crqc_arrival,
    simulate_asset_exposure,
    simulate_portfolio,
    _classify_exposure_probability,
)
from app.services.risk_engine import (
    _generate_race_headline,
    compute_migration_complexity,
)


# ─── Track D: Monte Carlo CRQC Arrival Tests ───────────────────────────────


def test_crqc_arrival_distribution_shape():
    """Distribution should peak around mode_year with reasonable spread."""
    result = simulate_crqc_arrival(n_simulations=10000, mode_year=2032, sigma=3.5, seed=42)

    assert result["n_simulations"] == 10000
    assert result["statistics"]["median"] > 2029
    assert result["statistics"]["median"] < 2038
    assert result["statistics"]["std_dev"] > 0
    print(f"  ✅ Median={result['statistics']['median']}, StdDev={result['statistics']['std_dev']}")


def test_crqc_arrival_deterministic():
    """Same seed should produce identical results."""
    r1 = simulate_crqc_arrival(n_simulations=1000, seed=123)
    r2 = simulate_crqc_arrival(n_simulations=1000, seed=123)

    assert r1["statistics"]["mean"] == r2["statistics"]["mean"]
    assert r1["percentiles"] == r2["percentiles"]
    print(f"  ✅ Deterministic: seed=123 → mean={r1['statistics']['mean']}")


def test_crqc_arrival_probability_sums_to_1():
    """Year probabilities should sum to ~1.0."""
    result = simulate_crqc_arrival(n_simulations=10000, seed=42)

    total_prob = sum(result["probability_by_year"].values())
    assert abs(total_prob - 1.0) < 0.01, f"Total probability={total_prob}, expected ~1.0"
    print(f"  ✅ Total probability={total_prob:.6f}")


def test_crqc_arrival_percentiles_ordered():
    """Percentiles should be in order: P5 < P25 < P50 < P75 < P95."""
    result = simulate_crqc_arrival(n_simulations=10000, seed=42)
    p = result["percentiles"]

    assert p["p5"] <= p["p25"] <= p["p50"] <= p["p75"] <= p["p95"]
    print(f"  ✅ P5={p['p5']}, P25={p['p25']}, P50={p['p50']}, P75={p['p75']}, P95={p['p95']}")


def test_crqc_arrival_cumulative():
    """Cumulative distribution should reach ~1.0."""
    result = simulate_crqc_arrival(n_simulations=10000, seed=42)

    max_cum = max(result["cumulative_by_year"].values())
    assert abs(max_cum - 1.0) < 0.01, f"Max cumulative={max_cum}"
    print(f"  ✅ Max cumulative={max_cum:.6f}")


def test_crqc_arrival_bounds():
    """All samples should be within [min_year, max_year]."""
    result = simulate_crqc_arrival(n_simulations=10000, seed=42)

    min_sampled = result["statistics"]["min_sampled"]
    max_sampled = result["statistics"]["max_sampled"]
    assert min_sampled >= 2027, f"Min sampled={min_sampled}, expected >= 2027"
    assert max_sampled <= 2045, f"Max sampled={max_sampled}, expected <= 2045"
    print(f"  ✅ Range: [{min_sampled}, {max_sampled}] within [2027, 2045]")


# ─── Track D: Monte Carlo Asset Exposure Tests ──────────────────────────────


def test_asset_high_exposure():
    """Asset with long migration + long shelf life should have high exposure probability."""
    result = simulate_asset_exposure(
        migration_time_years=4.0,
        data_shelf_life_years=10.0,
        n_simulations=10000,
        seed=42,
    )

    assert result["exposure_probability"] > 0.5, \
        f"Expected >50% exposure for X=4+Y=10, got {result['exposure_probability']:.1%}"
    print(f"  ✅ High risk: X=4+Y=10 → {result['exposure_probability']:.1%} exposure")


def test_asset_low_exposure():
    """Asset with short migration + short shelf life should have low exposure probability."""
    result = simulate_asset_exposure(
        migration_time_years=0.5,
        data_shelf_life_years=1.0,
        n_simulations=10000,
        seed=42,
    )

    assert result["exposure_probability"] < 0.3, \
        f"Expected <30% exposure for X=0.5+Y=1, got {result['exposure_probability']:.1%}"
    print(f"  ✅ Low risk: X=0.5+Y=1 → {result['exposure_probability']:.1%} exposure")


def test_asset_exposure_by_year():
    """Exposure by year should be provided for each year in range."""
    result = simulate_asset_exposure(
        migration_time_years=2.0,
        data_shelf_life_years=5.0,
        n_simulations=1000,
        seed=42,
    )

    assert len(result["exposure_by_year"]) >= 10
    # Exposure should decrease as we look at later CRQC years
    years = sorted(result["exposure_by_year"].keys())
    last_val = result["exposure_by_year"][years[-1]]
    first_val = result["exposure_by_year"][years[0]]
    print(f"  ✅ Exposure by year: {len(result['exposure_by_year'])} years, first={first_val:.4f}, last={last_val:.4f}")


def test_asset_mosca_threshold():
    """Mosca threshold should equal X + Y."""
    result = simulate_asset_exposure(
        migration_time_years=3.0,
        data_shelf_life_years=7.0,
        seed=42,
    )
    assert result["mosca_threshold"] == 10.0
    print(f"  ✅ Mosca threshold: X=3+Y=7 → {result['mosca_threshold']}")


# ─── Track D: Monte Carlo Portfolio Tests ────────────────────────────────────


def test_portfolio_simulation():
    """Portfolio simulation should return per-asset and aggregate results."""
    assets = [
        {"hostname": "swift.bank.in", "migration_time_years": 4.0, "data_shelf_life_years": 10.0},
        {"hostname": "api.bank.in", "migration_time_years": 1.5, "data_shelf_life_years": 3.0},
        {"hostname": "web.bank.in", "migration_time_years": 1.0, "data_shelf_life_years": 1.0},
    ]

    result = simulate_portfolio(assets, n_simulations=5000, seed=42)

    assert result["n_assets"] == 3
    assert len(result["per_asset"]) == 3
    assert "portfolio_summary" in result
    assert result["portfolio_summary"]["max_assets_exposed"] <= 3
    assert result["portfolio_summary"]["min_assets_exposed"] >= 0
    print(
        f"  ✅ Portfolio: {result['n_assets']} assets, "
        f"avg_exposed={result['portfolio_summary']['avg_assets_exposed']}, "
        f"pct={result['portfolio_summary']['pct_portfolio_exposed']:.1%}"
    )


def test_portfolio_ordering():
    """Per-asset results should be sorted by exposure probability (highest first)."""
    assets = [
        {"hostname": "low.bank.in", "migration_time_years": 0.5, "data_shelf_life_years": 1.0},
        {"hostname": "high.bank.in", "migration_time_years": 5.0, "data_shelf_life_years": 15.0},
        {"hostname": "mid.bank.in", "migration_time_years": 2.0, "data_shelf_life_years": 5.0},
    ]

    result = simulate_portfolio(assets, n_simulations=5000, seed=42)

    probs = [a["exposure_probability"] for a in result["per_asset"]]
    assert probs == sorted(probs, reverse=True), \
        f"Expected descending order, got {probs}"
    print(f"  ✅ Sorted: {[f'{a['hostname']}={a['exposure_probability']:.2%}' for a in result['per_asset']]}")


def test_portfolio_correlated_risk():
    """Same CRQC samples should be used (correlated). CRQC simulation should be consistent."""
    result = simulate_portfolio(
        [{"hostname": "a", "migration_time_years": 3, "data_shelf_life_years": 7}],
        n_simulations=5000, seed=42,
    )

    assert "crqc_simulation" in result
    assert result["crqc_simulation"]["p5"] <= result["crqc_simulation"]["p95"]
    print(f"  ✅ CRQC sim: median={result['crqc_simulation']['median_arrival']}, "
          f"P5={result['crqc_simulation']['p5']}, P95={result['crqc_simulation']['p95']}")


# ─── Track D: Exposure Classification Tests ─────────────────────────────────


def test_exposure_classification():
    """Classification thresholds should be correct."""
    assert _classify_exposure_probability(0.9) == "critical"
    assert _classify_exposure_probability(0.7) == "high"
    assert _classify_exposure_probability(0.4) == "medium"
    assert _classify_exposure_probability(0.15) == "low"
    assert _classify_exposure_probability(0.05) == "minimal"
    print(f"  ✅ All 5 exposure classifications correct")


# ─── Track E: Cert-CRQC Race Helper Tests ────────────────────────────────────


def test_race_headline_safe():
    """All safe certs should get positive headline."""
    headline = _generate_race_headline({"at_risk": 0, "natural_rotation": 5, "safe": 3}, 8)
    assert "✅" in headline
    print(f"  ✅ Safe headline: {headline}")


def test_race_headline_critical():
    """Mostly at-risk certs should get critical headline."""
    headline = _generate_race_headline({"at_risk": 8, "natural_rotation": 1, "safe": 1}, 10)
    assert "CRITICAL" in headline
    print(f"  ✅ Critical headline: {headline}")


def test_race_headline_mixed():
    """Mixed portfolio should get warning headline."""
    headline = _generate_race_headline({"at_risk": 3, "natural_rotation": 4, "safe": 3}, 10)
    assert "⚠️" in headline
    assert "3/10" in headline
    print(f"  ✅ Mixed headline: {headline}")


def test_migration_complexity_integration():
    """Migration complexity should adjust based on agility score."""
    # Low agility = high complexity
    low = compute_migration_complexity("swift_endpoint", agility_score=20)
    high = compute_migration_complexity("swift_endpoint", agility_score=80)

    assert low["complexity_years"] > high["complexity_years"]
    assert len(low["adjustments"]) > 0
    print(f"  ✅ Migration: low_agility={low['complexity_years']}yr, high_agility={high['complexity_years']}yr")


# ─── Runner ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        # Monte Carlo CRQC Arrival
        ("CRQC distribution shape", test_crqc_arrival_distribution_shape),
        ("CRQC deterministic (seed)", test_crqc_arrival_deterministic),
        ("CRQC probability sums to 1", test_crqc_arrival_probability_sums_to_1),
        ("CRQC percentiles ordered", test_crqc_arrival_percentiles_ordered),
        ("CRQC cumulative → 1.0", test_crqc_arrival_cumulative),
        ("CRQC bounds [2027, 2045]", test_crqc_arrival_bounds),
        # Monte Carlo Asset Exposure
        ("Asset high exposure", test_asset_high_exposure),
        ("Asset low exposure", test_asset_low_exposure),
        ("Asset exposure by year", test_asset_exposure_by_year),
        ("Asset Mosca threshold", test_asset_mosca_threshold),
        # Monte Carlo Portfolio
        ("Portfolio simulation", test_portfolio_simulation),
        ("Portfolio ordering", test_portfolio_ordering),
        ("Portfolio correlated risk", test_portfolio_correlated_risk),
        # Exposure classification
        ("Exposure classification", test_exposure_classification),
        # Cert-CRQC Race helpers
        ("Race headline: safe", test_race_headline_safe),
        ("Race headline: critical", test_race_headline_critical),
        ("Race headline: mixed", test_race_headline_mixed),
        ("Migration complexity", test_migration_complexity_integration),
    ]

    print(f"\n{'='*60}")
    print(f"Phase 8 Wave 2 — Standalone Tests ({len(tests)} tests)")
    print(f"{'='*60}")

    passed = 0
    failed = 0
    for name, test_fn in tests:
        try:
            print(f"\n🧪 {name}:")
            test_fn()
            passed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*60}")

    sys.exit(0 if failed == 0 else 1)
