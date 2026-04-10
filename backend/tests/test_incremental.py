import pytest
from app.services.incremental import compute_fingerprint

def test_compute_fingerprint():
    # Identical configurations should have identical hashes
    fp1 = compute_fingerprint('1.1.1.1', 'TLSv1.2', 'ECDHE-RSA-AES128-GCM-SHA256', 'cert_abc')
    fp2 = compute_fingerprint('1.1.1.1', 'TLSv1.2', 'ECDHE-RSA-AES128-GCM-SHA256', 'cert_abc')
    assert fp1 == fp2

    # Changing TLS version should change hash
    fp3 = compute_fingerprint('1.1.1.1', 'TLSv1.3', 'TLS_AES_256_GCM_SHA384', 'cert_abc')
    assert fp1 != fp3
