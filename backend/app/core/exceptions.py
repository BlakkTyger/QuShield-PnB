"""QuShield-PnB Custom Exceptions."""


class QuShieldError(Exception):
    """Base exception for all QuShield errors."""
    pass


class ScanError(QuShieldError):
    """Error during scan execution."""
    pass


class DiscoveryError(ScanError):
    """Error during asset discovery phase."""
    pass


class CryptoInspectionError(ScanError):
    """Error during cryptographic inspection."""
    pass


class CBOMGenerationError(ScanError):
    """Error during CBOM generation."""
    pass


class RiskComputationError(ScanError):
    """Error during risk score computation."""
    pass


class DatabaseError(QuShieldError):
    """Database connection or query error."""
    pass


class ConfigurationError(QuShieldError):
    """Invalid configuration."""
    pass
