"""
Chart Generator — Produces Matplotlib/Seaborn charts embedded as base64 PNGs for reports.
All charts use the Agg (headless) backend so they work in server environments.
"""
import io
import base64
import logging
from typing import Dict, Any, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

from sqlalchemy.orm import Session
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore, RiskFactor
from app.models.compliance import ComplianceResult
from app.models.cbom import CBOMComponent, CBOMRecord
from app.models.certificate import Certificate

logger = logging.getLogger(__name__)

CHART_BG = "#ffffff"
CARD_BG  = "#f8fafc"
BORDER   = "#e2e8f0"
GOLD     = "#d97706"
RED      = "#dc2626"
ORANGE   = "#ea580c"
GREEN    = "#16a34a"
BLUE     = "#2563eb"
PURPLE   = "#7c3aed"
MUTED    = "#94a3b8"
TEXT     = "#1e293b"
DARK_BG  = CHART_BG  # kept for compatibility


def _fig_to_b64(fig: plt.Figure) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=180, bbox_inches="tight",
                facecolor=fig.get_facecolor(), edgecolor="none")
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded


def _apply_light_style(ax, fig):
    fig.patch.set_facecolor(CHART_BG)
    ax.set_facecolor(CARD_BG)
    ax.tick_params(colors=TEXT, labelsize=8)
    ax.xaxis.label.set_color(TEXT)
    ax.yaxis.label.set_color(TEXT)
    ax.title.set_color(TEXT)
    for spine in ax.spines.values():
        spine.set_edgecolor(BORDER)
    ax.grid(color=BORDER, linewidth=0.5, alpha=0.7)


# Alias kept for any legacy internal calls
_apply_dark_style = _apply_light_style


class ChartGenerator:
    def __init__(self, db: Session, scan_job: ScanJob):
        self.db = db
        self.scan_id = scan_job.id
        self.assets = db.query(Asset).filter(Asset.scan_id == self.scan_id).all()
        self.risks = db.query(RiskScore).filter(RiskScore.scan_id == self.scan_id).all()
        self.compliance = db.query(ComplianceResult).filter(ComplianceResult.scan_id == self.scan_id).all()
        self.cbom_components = db.query(CBOMComponent).filter(CBOMComponent.scan_id == self.scan_id).all()
        self.certs = db.query(Certificate).filter(Certificate.scan_id == self.scan_id).all()

    def generate_all(self) -> Dict[str, str]:
        charts = {}
        generators = [
            ("risk_distribution", self.risk_distribution_donut),
            ("cbom_algorithm_bar", self.cbom_algorithm_bar),
            ("tls_version_distribution", self.tls_version_distribution),
            ("compliance_radar", self.compliance_radar),
            ("asset_type_risk_scatter", self.asset_type_risk_scatter),
            ("quantum_readiness_gauge", self.quantum_readiness_gauge),
            ("migration_complexity_heatmap", self.migration_complexity_heatmap),
            ("third_party_vendor_matrix", self.third_party_vendor_matrix),
            ("crypto_agility_bar", self.crypto_agility_bar),
            ("hndl_exposure_timeline", self.hndl_exposure_timeline),
        ]
        for name, fn in generators:
            try:
                charts[name] = fn()
            except Exception as exc:
                logger.warning(f"Chart '{name}' generation failed: {exc}")
                charts[name] = ""
        return charts

    def risk_distribution_donut(self) -> str:
        labels_map = {
            "quantum_critical": "Critical",
            "quantum_vulnerable": "Vulnerable",
            "quantum_at_risk": "At Risk",
            "quantum_aware": "Aware",
            "quantum_ready": "Ready",
            "unknown": "Unknown",
        }
        colors_map = {
            "quantum_critical": "#b91c1c",
            "quantum_vulnerable": "#ea580c",
            "quantum_at_risk": "#d97706",
            "quantum_aware": "#2563eb",
            "quantum_ready": "#16a34a",
            "unknown": "#475569",
        }
        counts: Dict[str, int] = {}
        for r in self.risks:
            cls = r.risk_classification or "unknown"
            counts[cls] = counts.get(cls, 0) + 1

        if not counts:
            counts = {"unknown": 1}

        labels = [labels_map.get(k, k) for k in counts]
        sizes = list(counts.values())
        colors = [colors_map.get(k, MUTED) for k in counts]

        fig, ax = plt.subplots(figsize=(6, 4))
        _apply_light_style(ax, fig)
        ax.grid(False)
        wedges, texts, autotexts = ax.pie(
            sizes, labels=None, colors=colors, autopct="%1.0f%%",
            startangle=90, pctdistance=0.75,
            wedgeprops={"linewidth": 2, "edgecolor": CHART_BG}
        )
        for at in autotexts:
            at.set_color(TEXT)
            at.set_fontsize(7)
        centre_circle = plt.Circle((0, 0), 0.55, fc=CARD_BG)
        ax.add_patch(centre_circle)
        ax.text(0, 0, f"{len(self.risks)}\nassets", ha="center", va="center",
                fontsize=10, fontweight="bold", color=TEXT)
        ax.legend(wedges, labels, loc="lower center", bbox_to_anchor=(0.5, -0.08),
                  ncol=3, fontsize=7, frameon=False, labelcolor=TEXT)
        ax.set_title("Quantum Risk Distribution", color=TEXT, fontsize=10, pad=10)
        return _fig_to_b64(fig)

    def quantum_readiness_gauge(self) -> str:
        total = len(self.risks)
        ready = sum(1 for r in self.risks if (r.risk_classification or "").startswith("quantum_ready"))
        pct = (ready / total * 100) if total else 0

        fig, ax = plt.subplots(figsize=(5, 4), subplot_kw={"polar": True})
        fig.patch.set_facecolor(CHART_BG)
        ax.set_facecolor(CARD_BG)

        theta = np.linspace(0, np.pi, 200)
        ax.fill_between(theta, 0, 0.7, color=CARD_BG, alpha=0.8)
        danger_zone = np.linspace(0, np.pi * 0.33, 100)
        ax.fill_between(danger_zone, 0, 0.7, color=RED, alpha=0.3)
        mid_zone = np.linspace(np.pi * 0.33, np.pi * 0.67, 100)
        ax.fill_between(mid_zone, 0, 0.7, color=GOLD, alpha=0.3)
        safe_zone = np.linspace(np.pi * 0.67, np.pi, 100)
        ax.fill_between(safe_zone, 0, 0.7, color=GREEN, alpha=0.3)

        needle_angle = np.pi * (1 - pct / 100)
        ax.annotate("", xy=(needle_angle, 0.65), xytext=(0, 0),
                    arrowprops={"arrowstyle": "->", "color": TEXT, "lw": 2})
        ax.set_ylim(0, 1)
        ax.set_xlim(0, np.pi)
        ax.set_theta_zero_location("W")
        ax.set_theta_direction(1)
        ax.set_axis_off()
        ax.text(0.5, 0.1, f"{pct:.0f}%", transform=ax.transAxes,
                ha="center", va="center", fontsize=18, fontweight="bold", color=GOLD)
        ax.set_title("Quantum Readiness", color=TEXT, fontsize=9, pad=5)
        return _fig_to_b64(fig)

    def cbom_algorithm_bar(self) -> str:
        algo_counts: Dict[str, int] = {}
        algo_vuln: Dict[str, bool] = {}
        for c in self.cbom_components:
            name = c.name or "Unknown"
            algo_counts[name] = algo_counts.get(name, 0) + 1
            algo_vuln[name] = bool(c.is_quantum_vulnerable)

        if not algo_counts:
            fig, ax = plt.subplots(figsize=(6, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No CBOM data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        sorted_items = sorted(algo_counts.items(), key=lambda x: x[1], reverse=True)[:15]
        names = [i[0] for i in sorted_items]
        counts = [i[1] for i in sorted_items]
        bar_colors = [RED if algo_vuln.get(n, True) else GREEN for n in names]

        fig, ax = plt.subplots(figsize=(7, 4))
        _apply_light_style(ax, fig)
        bars = ax.barh(range(len(names)), counts, color=bar_colors, edgecolor=CHART_BG, linewidth=0.5)
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=7, color=TEXT)
        ax.set_xlabel("Count", color=TEXT, fontsize=8)
        ax.set_title("CBOM Algorithm Distribution", color=TEXT, fontsize=10)
        ax.tick_params(axis="x", colors=TEXT)
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(count), va="center", color=TEXT, fontsize=7)
        legend_patches = [
            mpatches.Patch(color=RED, label="Quantum Vulnerable"),
            mpatches.Patch(color=GREEN, label="Quantum Safe"),
        ]
        ax.legend(handles=legend_patches, fontsize=7, frameon=False, labelcolor=TEXT)
        plt.tight_layout()
        return _fig_to_b64(fig)

    def tls_version_distribution(self) -> str:
        version_counts: Dict[str, int] = {}
        for asset in self.assets:
            ver = asset.tls_version or "Unknown"
            version_counts[ver] = version_counts.get(ver, 0) + 1

        if not version_counts:
            fig, ax = plt.subplots(figsize=(5, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No TLS data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        version_colors = {
            "TLSv1.3": GREEN, "TLS 1.3": GREEN, "1.3": GREEN,
            "TLSv1.2": GOLD, "TLS 1.2": GOLD, "1.2": GOLD,
            "TLSv1.1": ORANGE, "TLS 1.1": ORANGE, "1.1": ORANGE,
            "TLSv1.0": RED, "TLS 1.0": RED, "1.0": RED,
            "Unknown": MUTED,
        }
        labels = list(version_counts.keys())
        sizes = list(version_counts.values())
        colors = [version_colors.get(l, MUTED) for l in labels]

        fig, ax = plt.subplots(figsize=(6, 4))
        _apply_light_style(ax, fig)
        bars = ax.bar(labels, sizes, color=colors, edgecolor=CHART_BG, linewidth=0.5)
        ax.set_xlabel("TLS Version", color=TEXT, fontsize=8)
        ax.set_ylabel("Asset Count", color=TEXT, fontsize=8)
        ax.set_title("TLS Version Distribution", color=TEXT, fontsize=10)
        for bar, count in zip(bars, sizes):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                    str(count), ha="center", color=TEXT, fontsize=8)
        plt.tight_layout()
        return _fig_to_b64(fig)

    def compliance_radar(self) -> str:
        if not self.compliance:
            fig, ax = plt.subplots(figsize=(5, 4))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No compliance data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        total = len(self.compliance)
        metrics = {
            "FIPS-203\n(ML-KEM)": sum(1 for c in self.compliance if c.fips_203_deployed) / total,
            "FIPS-204\n(ML-DSA)": sum(1 for c in self.compliance if c.fips_204_deployed) / total,
            "FIPS-205\n(SLH-DSA)": sum(1 for c in self.compliance if c.fips_205_deployed) / total,
            "TLS 1.3": sum(1 for c in self.compliance if c.tls_13_enforced) / total,
            "RBI": sum(1 for c in self.compliance if c.rbi_compliant) / total,
            "PCI DSS": sum(1 for c in self.compliance if c.pci_compliant) / total,
        }
        labels = list(metrics.keys())
        values = list(metrics.values())
        N = len(labels)
        angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
        values += values[:1]
        angles += angles[:1]

        fig, ax = plt.subplots(figsize=(6, 5), subplot_kw={"polar": True})
        fig.patch.set_facecolor(CHART_BG)
        ax.set_facecolor(CARD_BG)
        ax.plot(angles, values, color=GOLD, linewidth=2)
        ax.fill(angles, values, alpha=0.2, color=GOLD)
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(labels, size=7, color=TEXT)
        ax.set_ylim(0, 1)
        ax.set_yticks([0.25, 0.5, 0.75, 1.0])
        ax.set_yticklabels(["25%", "50%", "75%", "100%"], size=6, color=MUTED)
        ax.tick_params(colors=TEXT)
        ax.grid(color=BORDER, linestyle="--", linewidth=0.5)
        ax.spines["polar"].set_color(BORDER)
        ax.set_title("Compliance Coverage", color=TEXT, fontsize=10, pad=15)
        return _fig_to_b64(fig)

    def asset_type_risk_scatter(self) -> str:
        risk_by_asset = {str(r.asset_id): r.quantum_risk_score for r in self.risks}
        type_map: Dict[str, List[int]] = {}
        for asset in self.assets:
            atype = asset.asset_type or "unknown"
            score = risk_by_asset.get(str(asset.id), 0) or 0
            type_map.setdefault(atype, []).append(score)

        if not type_map:
            fig, ax = plt.subplots(figsize=(6, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No asset data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        fig, ax = plt.subplots(figsize=(6, 4))
        _apply_light_style(ax, fig)
        colors_list = [RED, ORANGE, GOLD, BLUE, PURPLE, GREEN, MUTED]
        for i, (atype, scores) in enumerate(sorted(type_map.items())):
            color = colors_list[i % len(colors_list)]
            x = np.random.normal(i, 0.1, size=len(scores))
            ax.scatter(x, scores, color=color, alpha=0.7, s=30, label=atype)
        ax.set_xticks([])
        ax.set_ylabel("Quantum Risk Score", color=TEXT, fontsize=8)
        ax.set_title("Risk Score by Asset Type", color=TEXT, fontsize=10)
        ax.set_ylim(0, 1050)
        ax.legend(fontsize=7, frameon=False, labelcolor=TEXT, loc="upper right")
        plt.tight_layout()
        return _fig_to_b64(fig)

    def migration_complexity_heatmap(self) -> str:
        if not self.risks or not self.assets:
            fig, ax = plt.subplots(figsize=(6, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        risk_by_asset = {str(r.asset_id): r for r in self.risks}
        rows = []
        for asset in self.assets[:20]:
            r = risk_by_asset.get(str(asset.id))
            if r:
                rows.append({
                    "host": (asset.hostname or "")[:20],
                    "risk": r.quantum_risk_score or 0,
                    "hndl": 1 if r.hndl_exposed else 0,
                    "migration_x": round(r.mosca_x or 0, 1),
                })
        if not rows:
            fig, ax = plt.subplots(figsize=(6, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No risk data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        rows.sort(key=lambda x: x["risk"], reverse=True)
        data = np.array([[r["risk"], r["migration_x"] * 100, r["hndl"] * 1000] for r in rows])
        labels = [r["host"] for r in rows]
        col_labels = ["Risk Score", "Migration\nComplexity", "HNDL\nExposure"]

        fig, ax = plt.subplots(figsize=(7, max(4, len(rows) * 0.35 + 1)))
        _apply_light_style(ax, fig)
        norm_data = data / np.maximum(data.max(axis=0), 1)
        im = ax.imshow(norm_data, cmap="RdYlGn_r", aspect="auto", vmin=0, vmax=1)
        ax.set_xticks(range(len(col_labels)))
        ax.set_xticklabels(col_labels, fontsize=7, color=TEXT)
        ax.set_yticks(range(len(labels)))
        ax.set_yticklabels(labels, fontsize=6, color=TEXT)
        ax.set_title("Migration Complexity Heatmap", color=TEXT, fontsize=10)
        plt.colorbar(im, ax=ax, fraction=0.03, pad=0.04).ax.tick_params(labelcolor=TEXT)
        plt.tight_layout()
        return _fig_to_b64(fig)

    def third_party_vendor_matrix(self) -> str:
        third_party = [a for a in self.assets if a.is_third_party]
        if not third_party:
            fig, ax = plt.subplots(figsize=(5, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No third-party assets detected", transform=ax.transAxes,
                    ha="center", va="center", color=MUTED, fontsize=9)
            ax.set_title("Third-Party Vendor PQC Matrix", color=TEXT, fontsize=10)
            return _fig_to_b64(fig)

        risk_by_asset = {str(r.asset_id): r for r in self.risks}
        vendors: Dict[str, Dict] = {}
        for asset in third_party:
            vendor = asset.third_party_vendor or asset.hosting_provider or "Unknown"
            if vendor not in vendors:
                vendors[vendor] = {"count": 0, "risk_sum": 0, "hndl": 0}
            vendors[vendor]["count"] += 1
            r = risk_by_asset.get(str(asset.id))
            if r:
                vendors[vendor]["risk_sum"] += r.quantum_risk_score or 0
                if r.hndl_exposed:
                    vendors[vendor]["hndl"] += 1

        vendor_names = list(vendors.keys())[:12]
        avg_risks = [vendors[v]["risk_sum"] / max(vendors[v]["count"], 1) for v in vendor_names]
        hndl_counts = [vendors[v]["hndl"] for v in vendor_names]

        fig, ax = plt.subplots(figsize=(7, max(4, len(vendor_names) * 0.45 + 1)))
        _apply_light_style(ax, fig)
        bar_colors = [RED if r > 600 else ORANGE if r > 400 else GOLD for r in avg_risks]
        bars = ax.barh(vendor_names, avg_risks, color=bar_colors, edgecolor=CHART_BG)
        ax2 = ax.twiny()
        ax2.scatter(hndl_counts, vendor_names, color=BLUE, s=50, zorder=5, label="HNDL exposed")
        ax2.set_xlabel("HNDL Assets", color=BLUE, fontsize=7)
        ax2.tick_params(colors=BLUE)
        ax.set_xlabel("Avg Quantum Risk Score", color=TEXT, fontsize=8)
        ax.set_title("Third-Party Vendor Risk Matrix", color=TEXT, fontsize=10)
        ax.tick_params(colors=TEXT)
        ax.set_xlim(0, 1000)
        plt.tight_layout()
        return _fig_to_b64(fig)

    def crypto_agility_bar(self) -> str:
        if not self.compliance:
            fig, ax = plt.subplots(figsize=(6, 3))
            _apply_dark_style(ax, fig)
            ax.text(0.5, 0.5, "No compliance data", transform=ax.transAxes, ha="center", color=MUTED)
            return _fig_to_b64(fig)

        buckets = {"0-25": 0, "26-50": 0, "51-75": 0, "76-100": 0}
        for c in self.compliance:
            score = c.crypto_agility_score or 0
            if score <= 25:
                buckets["0-25"] += 1
            elif score <= 50:
                buckets["26-50"] += 1
            elif score <= 75:
                buckets["51-75"] += 1
            else:
                buckets["76-100"] += 1

        fig, ax = plt.subplots(figsize=(6, 4))
        _apply_light_style(ax, fig)
        colors = [RED, ORANGE, GOLD, GREEN]
        bars = ax.bar(buckets.keys(), buckets.values(), color=colors, edgecolor=CHART_BG)
        ax.set_xlabel("Crypto Agility Score Range", color=TEXT, fontsize=8)
        ax.set_ylabel("Asset Count", color=TEXT, fontsize=8)
        ax.set_title("Crypto Agility Distribution", color=TEXT, fontsize=10)
        for bar, count in zip(bars, buckets.values()):
            if count > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
                        str(count), ha="center", color=TEXT, fontsize=8)
        plt.tight_layout()
        return _fig_to_b64(fig)

    def hndl_exposure_timeline(self) -> str:
        hndl_count = sum(1 for r in self.risks if r.hndl_exposed)
        total = len(self.risks)
        safe_count = total - hndl_count

        years = list(range(2024, 2036))
        crqc_prob = [max(0, min(1, (y - 2027) / 8)) for y in years]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
        _apply_light_style(ax1, fig)
        _apply_light_style(ax2, fig)
        ax1.grid(False)

        ax1.pie([hndl_count or 1, safe_count], labels=["HNDL Exposed", "Protected"],
                colors=[RED, GREEN], autopct="%1.0f%%", startangle=90,
                wedgeprops={"edgecolor": CHART_BG, "linewidth": 2},
                textprops={"color": TEXT, "fontsize": 8})
        ax1.set_title("HNDL Exposure", color=TEXT, fontsize=9)

        ax2.fill_between(years, crqc_prob, alpha=0.3, color=RED)
        ax2.plot(years, crqc_prob, color=RED, linewidth=2, label="CRQC Probability")
        ax2.axvline(x=2027, color=GOLD, linestyle="--", linewidth=1, label="Earliest CRQC")
        ax2.axvline(x=2033, color=ORANGE, linestyle="--", linewidth=1, label="Median CRQC")
        ax2.set_xlabel("Year", color=TEXT, fontsize=8)
        ax2.set_ylabel("CRQC Probability", color=TEXT, fontsize=8)
        ax2.set_title("CRQC Threat Timeline", color=TEXT, fontsize=9)
        ax2.legend(fontsize=6, frameon=False, labelcolor=TEXT)
        ax2.set_ylim(0, 1.1)

        plt.tight_layout()
        return _fig_to_b64(fig)
