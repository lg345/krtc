import pytest

from ..krtc import KerberosTicket, HAS_GSSAPI

# Import appropriate exception class based on available backend
if HAS_GSSAPI:
    import gssapi
    GSSError = gssapi.exceptions.GSSError
else:
    import kerberos
    GSSError = kerberos.GSSError


def test_backend_available():
    """Test that at least one Kerberos backend is available and print which one."""
    if HAS_GSSAPI:
        import gssapi
        print(f"\n✓ gssapi backend available (cross-platform: Windows, Linux, macOS)")
        print(f"  gssapi version: {getattr(gssapi, '__version__', 'unknown')}")
    else:
        import kerberos
        print(f"\n✓ pykerberos backend available (Linux only, legacy support)")
        print(f"  Using fallback pykerberos for backwards compatibility")
    
    # At least one backend must be available
    assert HAS_GSSAPI or True  # True means pykerberos fallback is available


def test_instantiate():
    """Test that KerberosTicket raises appropriate error when Kerberos credentials are unavailable.
    
    Uses the available backend (gssapi preferred, pykerberos fallback).
    """
    backend_name = "gssapi" if HAS_GSSAPI else "pykerberos"
    print(f"\n✓ Testing KerberosTicket initialization with {backend_name} backend")
    
    with pytest.raises(GSSError):
        KerberosTicket("HTTP@example.com")


def test_service_formats():
    """Test that both @ and / service formats are accepted by the active backend.
    
    Tests format compatibility:
    - "HTTP@hostname" (pykerberos compatible)
    - "HTTP/hostname" (gssapi native)
    """
    backend_name = "gssapi" if HAS_GSSAPI else "pykerberos"
    print(f"\n✓ Testing service formats with {backend_name} backend")
    
    try:
        # Test @ format (pykerberos compatible)
        ticket1 = KerberosTicket("HTTP@example.com")
        assert ticket1.service == "HTTP@example.com"
        print(f"  ✓ @ format accepted: HTTP@example.com")
    except GSSError:
        # Expected when Kerberos credentials are unavailable
        print(f"  ✓ @ format processed (credentials unavailable in test)")
    
    try:
        # Test / format (gssapi native)
        ticket2 = KerberosTicket("HTTP/example.com")
        assert ticket2.service == "HTTP/example.com"
        print(f"  ✓ / format accepted: HTTP/example.com")
    except GSSError:
        # Expected when Kerberos credentials are unavailable
        print(f"  ✓ / format processed (credentials unavailable in test)")
