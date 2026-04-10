"""
Monte Carlo CRQC Arrival Simulation Service

Provides probability-weighted CRQC (Cryptographically Relevant Quantum Computer)
arrival simulations for quantum risk assessment. Uses log-normal distribution
modeling based on expert consensus data.

Replaces the 3-scenario discrete model (pessimistic/median/optimistic) with
a continuous probability distribution for more nuanced risk quantification.
"""
import numpy as np
from typing import Optional

from app.core.logging import get_logger
from app.core.timing import timed

logger = get_logger("monte_carlo")

# Default CRQC arrival parameters based on expert consensus
# Median ~2032, with heavy right tail (could be later) and thin left tail (unlikely before 2028)
DEFAULT_CRQC_PARAMS = {
    "mode_year": 2032,       # Most likely arrival year
    "sigma": 3.5,            # Spread in years (standard deviation of underlying normal)
    "min_year": 2027,        # Absolute minimum (physical impossibility before this)
    "max_year": 2045,        # Practical maximum for planning
}


@timed(service="monte_carlo")
def simulate_crqc_arrival(
    n_simulations: int = 10000,
    mode_year: float = None,
    sigma: float = None,
    min_year: int = None,
    max_year: int = None,
    seed: int = None,
) -> dict:
    """
    Simulate CRQC arrival year using log-normal distribution.

    The log-normal distribution naturally models "time until event" with
    a long right tail — matching the uncertain nature of quantum computing
    breakthroughs (could happen soon, but might take much longer).

    Args:
        n_simulations: Number of Monte Carlo samples (default: 10,000)
        mode_year: Most likely CRQC arrival year
        sigma: Spread of distribution in years
        min_year: Earliest possible year (hard cutoff)
        max_year: Latest year to consider
        seed: Random seed for reproducibility

    Returns:
        dict with probability distribution by year, percentiles, and summary statistics
    """
    if mode_year is None:
        mode_year = DEFAULT_CRQC_PARAMS["mode_year"]
    if sigma is None:
        sigma = DEFAULT_CRQC_PARAMS["sigma"]
    if min_year is None:
        min_year = DEFAULT_CRQC_PARAMS["min_year"]
    if max_year is None:
        max_year = DEFAULT_CRQC_PARAMS["max_year"]

    rng = np.random.default_rng(seed)

    # Sample from normal distribution centered on mode_year with given sigma
    # Then apply skew by exponentiating a shifted normal (creates right-heavy tail)
    # Approach: use a skew-normal approximation via shifted log-normal
    offset = mode_year - min_year
    if offset <= 0:
        offset = 5  # safety

    # Log-normal parameters: median matches mode_year
    # mu and sigma of underlying normal distribution
    mu = np.log(offset)
    sigma_ln = sigma / offset  # scale sigma appropriately

    samples = rng.lognormal(mean=mu, sigma=sigma_ln, size=n_simulations)
    samples = samples + min_year  # shift to actual years

    # Clip to [min_year, max_year]
    samples = np.clip(samples, min_year, max_year)

    # Round to integer years for discrete probability distribution
    year_samples = np.round(samples).astype(int)

    # Compute probability distribution by year
    unique_years, counts = np.unique(year_samples, return_counts=True)
    probability_by_year = {
        int(year): round(float(count / n_simulations), 6)
        for year, count in zip(unique_years, counts)
    }

    # Fill in missing years with 0 probability
    for y in range(min_year, max_year + 1):
        if y not in probability_by_year:
            probability_by_year[y] = 0.0

    # Sort by year
    probability_by_year = dict(sorted(probability_by_year.items()))

    # Compute cumulative probability (CDF)
    cumulative_by_year = {}
    cumulative = 0.0
    for year in sorted(probability_by_year.keys()):
        cumulative += probability_by_year[year]
        cumulative_by_year[year] = round(cumulative, 6)

    # Percentiles
    percentiles = {
        "p5": int(np.percentile(samples, 5)),
        "p25": int(np.percentile(samples, 25)),
        "p50": int(np.percentile(samples, 50)),
        "p75": int(np.percentile(samples, 75)),
        "p95": int(np.percentile(samples, 95)),
    }

    result = {
        "n_simulations": n_simulations,
        "parameters": {
            "mode_year": mode_year,
            "sigma": sigma,
            "min_year": min_year,
            "max_year": max_year,
        },
        "statistics": {
            "mean": round(float(np.mean(samples)), 2),
            "median": round(float(np.median(samples)), 2),
            "std_dev": round(float(np.std(samples)), 2),
            "min_sampled": int(np.min(year_samples)),
            "max_sampled": int(np.max(year_samples)),
        },
        "percentiles": percentiles,
        "probability_by_year": probability_by_year,
        "cumulative_by_year": cumulative_by_year,
    }

    logger.info(
        f"CRQC simulation: {n_simulations} samples, "
        f"median={result['statistics']['median']}, "
        f"P5={percentiles['p5']}, P95={percentiles['p95']}",
        extra={
            "n_simulations": n_simulations,
            "median": result["statistics"]["median"],
            "p5": percentiles["p5"],
            "p95": percentiles["p95"],
        },
    )

    return result


@timed(service="monte_carlo")
def simulate_asset_exposure(
    migration_time_years: float,
    data_shelf_life_years: float,
    n_simulations: int = 10000,
    mode_year: float = None,
    sigma: float = None,
    reference_year: int = None,
    seed: int = None,
) -> dict:
    """
    Simulate whether a specific asset is exposed to quantum risk.

    For each CRQC arrival sample, checks Mosca's inequality:
    X + Y > Z → asset is exposed (migration + shelf life exceeds time until CRQC)

    Args:
        migration_time_years: X = time to migrate to PQC
        data_shelf_life_years: Y = confidentiality requirement
        n_simulations: Number of Monte Carlo samples
        mode_year: CRQC arrival mode year
        sigma: Distribution spread
        reference_year: Base year (default: 2026)
        seed: Random seed

    Returns:
        dict with exposure probability, expected exposure year, probability curve
    """
    if mode_year is None:
        mode_year = DEFAULT_CRQC_PARAMS["mode_year"]
    if sigma is None:
        sigma = DEFAULT_CRQC_PARAMS["sigma"]
    if reference_year is None:
        from datetime import datetime, timezone
        reference_year = datetime.now(timezone.utc).year

    min_year = DEFAULT_CRQC_PARAMS["min_year"]
    max_year = DEFAULT_CRQC_PARAMS["max_year"]

    rng = np.random.default_rng(seed)

    # Generate CRQC arrival samples
    offset = mode_year - min_year
    if offset <= 0:
        offset = 5
    mu = np.log(offset)
    sigma_ln = sigma / offset
    crqc_samples = rng.lognormal(mean=mu, sigma=sigma_ln, size=n_simulations) + min_year
    crqc_samples = np.clip(crqc_samples, min_year, max_year)

    # Mosca's inequality check for each sample
    x = migration_time_years
    y = data_shelf_life_years

    z_samples = crqc_samples - reference_year  # years until CRQC for each sample
    exposed_mask = (x + y) > z_samples  # True if exposed in that scenario

    exposure_probability = float(np.mean(exposed_mask))

    # Compute expected exposure year (earliest year of exposure)
    exposure_year_samples = crqc_samples[exposed_mask]
    expected_exposure_year = (
        round(float(np.mean(exposure_year_samples)), 1) if len(exposure_year_samples) > 0 else None
    )

    # Exposure probability by year (what % of scenarios have CRQC before this year?)
    exposure_by_year = {}
    for year in range(min_year, max_year + 1):
        z = year - reference_year
        exposed_at_year = float(np.mean((x + y) > (year - reference_year)))
        exposure_by_year[year] = round(exposed_at_year, 6)

    result = {
        "migration_time_years": x,
        "data_shelf_life_years": y,
        "reference_year": reference_year,
        "n_simulations": n_simulations,
        "exposure_probability": round(exposure_probability, 4),
        "expected_exposure_year": expected_exposure_year,
        "exposure_by_year": exposure_by_year,
        "mosca_threshold": round(x + y, 2),
    }

    logger.info(
        f"Asset exposure: X={x}yr + Y={y}yr, "
        f"exposure_probability={exposure_probability:.2%}",
        extra={
            "x": x, "y": y,
            "exposure_probability": exposure_probability,
            "expected_exposure_year": expected_exposure_year,
        },
    )

    return result


@timed(service="monte_carlo")
def simulate_portfolio(
    assets: list[dict],
    n_simulations: int = 10000,
    mode_year: float = None,
    sigma: float = None,
    reference_year: int = None,
    seed: int = None,
) -> dict:
    """
    Run Monte Carlo simulation for an entire portfolio of assets.

    Uses the same CRQC arrival samples for all assets (correlated risk).

    Args:
        assets: List of dicts with 'hostname', 'migration_time_years', 'data_shelf_life_years'
        n_simulations: Number of simulations
        mode_year: CRQC arrival mode year
        sigma: Distribution spread
        reference_year: Base year
        seed: Random seed

    Returns:
        dict with per-asset exposure probability, portfolio summary, risk distribution
    """
    if mode_year is None:
        mode_year = DEFAULT_CRQC_PARAMS["mode_year"]
    if sigma is None:
        sigma = DEFAULT_CRQC_PARAMS["sigma"]
    if reference_year is None:
        from datetime import datetime, timezone
        reference_year = datetime.now(timezone.utc).year

    min_year = DEFAULT_CRQC_PARAMS["min_year"]
    max_year = DEFAULT_CRQC_PARAMS["max_year"]

    rng = np.random.default_rng(seed)

    # Single set of CRQC samples (same quantum breakthrough affects all assets)
    offset = mode_year - min_year
    if offset <= 0:
        offset = 5
    mu = np.log(offset)
    sigma_ln = sigma / offset
    crqc_samples = rng.lognormal(mean=mu, sigma=sigma_ln, size=n_simulations) + min_year
    crqc_samples = np.clip(crqc_samples, min_year, max_year)

    z_samples = crqc_samples - reference_year

    # Per-asset exposure analysis
    per_asset_results = []
    exposure_counts = np.zeros(n_simulations)  # count of exposed assets per simulation

    for asset in assets:
        x = asset.get("migration_time_years", 1.5)
        y = asset.get("data_shelf_life_years", 5.0)
        hostname = asset.get("hostname", "unknown")

        exposed_mask = (x + y) > z_samples
        exposure_prob = float(np.mean(exposed_mask))
        exposure_counts += exposed_mask.astype(float)

        per_asset_results.append({
            "hostname": hostname,
            "migration_time_years": x,
            "data_shelf_life_years": y,
            "exposure_probability": round(exposure_prob, 4),
            "risk_level": _classify_exposure_probability(exposure_prob),
        })

    # Portfolio-level statistics
    n_assets = len(assets)
    avg_exposed_per_sim = float(np.mean(exposure_counts))
    pct_portfolio_exposed = round(avg_exposed_per_sim / max(n_assets, 1), 4)

    # Distribution of exposed asset counts
    unique_counts, count_freq = np.unique(exposure_counts.astype(int), return_counts=True)
    exposure_distribution = {
        int(count): round(float(freq / n_simulations), 4)
        for count, freq in zip(unique_counts, count_freq)
    }

    # Sort per-asset by exposure probability (highest risk first)
    per_asset_results.sort(key=lambda x: x["exposure_probability"], reverse=True)

    result = {
        "n_assets": n_assets,
        "n_simulations": n_simulations,
        "reference_year": reference_year,
        "portfolio_summary": {
            "avg_assets_exposed": round(avg_exposed_per_sim, 1),
            "pct_portfolio_exposed": pct_portfolio_exposed,
            "max_assets_exposed": int(np.max(exposure_counts)),
            "min_assets_exposed": int(np.min(exposure_counts)),
        },
        "per_asset": per_asset_results,
        "exposure_distribution": exposure_distribution,
        "crqc_simulation": {
            "median_arrival": round(float(np.median(crqc_samples)), 1),
            "p5": int(np.percentile(crqc_samples, 5)),
            "p95": int(np.percentile(crqc_samples, 95)),
        },
    }

    logger.info(
        f"Portfolio simulation: {n_assets} assets, "
        f"avg exposed={avg_exposed_per_sim:.1f}, "
        f"pct={pct_portfolio_exposed:.1%}",
        extra={
            "n_assets": n_assets,
            "avg_exposed": avg_exposed_per_sim,
            "pct_exposed": pct_portfolio_exposed,
        },
    )

    return result


def _classify_exposure_probability(prob: float) -> str:
    """Classify exposure probability into risk level."""
    if prob >= 0.8:
        return "critical"
    elif prob >= 0.6:
        return "high"
    elif prob >= 0.3:
        return "medium"
    elif prob >= 0.1:
        return "low"
    else:
        return "minimal"
