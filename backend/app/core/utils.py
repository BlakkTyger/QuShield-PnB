import re
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,6}$"
)

def clean_domain(target: str) -> str:
    """
    Normalizes a target input by stripping protocols, whitespaces, and paths.
    
    Example:
        'https://pnb.bank.in/dashboard' -> 'pnb.bank.in'
        '  pnb.bank.in  ' -> 'pnb.bank.in'
    """
    if not target:
        return ""
        
    clean_tgt = target.strip()
    
    # Handle protocol://domain.com/path
    if "://" in clean_tgt:
        try:
            parsed = urlparse(clean_tgt)
            clean_tgt = parsed.netloc
        except Exception:
            # Fallback if urlparse fails
            clean_tgt = clean_tgt.split("://")[-1]
            
    # Handle domain.com/path (no protocol)
    if "/" in clean_tgt:
        clean_tgt = clean_tgt.split("/")[0]
        
    return clean_tgt.lower()

def is_valid_domain(domain: str) -> bool:
    """Check if the string follows a basic domain format."""
    return bool(DOMAIN_REGEX.match(domain))
