from datetime import datetime, timedelta, timezone
from app.models.auth import ScanCache
import pytest
from unittest.mock import MagicMock
from app.api.v1.scans import check_scan_cache

def test_check_scan_cache():
    # Mock DB session
    db_session = MagicMock()
    
    # Setup mock query
    mock_query = db_session.query.return_value
    mock_filter = mock_query.filter.return_value
    mock_order = mock_filter.order_by.return_value
    
    # Return a mocked cache entry
    cache_entry = ScanCache(
        domain="example.com",
        scan_type="deep",
        scan_id="00000000-0000-0000-0000-000000000001",
        user_id="user123",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
    )
    mock_order.first.return_value = cache_entry
    
    # Run function
    result = check_scan_cache(db_session, "example.com", ["deep", "shallow"])
    
    assert result is not None
    assert result.domain == "example.com"
    assert result.scan_type == "deep"
    
    # Verify mock was called
    db_session.query.assert_called_once_with(ScanCache)
