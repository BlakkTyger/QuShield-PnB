from datetime import datetime, timedelta, timezone
from app.models.auth import ScanCache
import pytest
from unittest.mock import MagicMock
from app.api.v1.scans import check_scan_cache

def test_check_scan_cache():
    # Mock DB session
    db_session = MagicMock()
    
    # Return a mocked cache entry
    cache_entry = ScanCache(
        domain="example.com",
        scan_type="deep",
        scan_id="00000000-0000-0000-0000-000000000001",
        user_id="user123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
    )
    
    # Create a mock that returns itself for chained calls
    m = MagicMock()
    m.query.return_value = m
    m.filter.return_value = m
    m.order_by.return_value = m
    m.all.return_value = [cache_entry]
    m.first.return_value = MagicMock(status="completed", total_assets=1, id="00000000-0000-0000-0000-000000000001")
    
    # Run function with user context
    result = check_scan_cache(m, "example.com", ["deep", "shallow"], user_id="user123")
    
    assert result is not None
    assert result.domain == "example.com"
    assert result.scan_type == "deep"
    
    # Verify mock was called
    db_session.query.assert_called_once_with(ScanCache)
