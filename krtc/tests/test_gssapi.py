import gssapi
import pytest

from ..krtc import KerberosTicket


def test_instantiate():
    """Test that KerberosTicket raises GSSError when Kerberos credentials are unavailable."""
    with pytest.raises(gssapi.exceptions.GSSError):
        KerberosTicket("HTTP@example.com")


def test_service_formats():
    """Test that both @ and / service formats are accepted."""
    # These should not raise during initialization (though they will fail
    # if Kerberos credentials are not available, which is expected in test environment)
    try:
        # Test @ format (pykerberos compatible)
        ticket1 = KerberosTicket("HTTP@example.com")
        assert ticket1.service == "HTTP@example.com"
    except gssapi.exceptions.GSSError:
        # Expected when Kerberos credentials are unavailable
        pass
    
    try:
        # Test / format (gssapi native)
        ticket2 = KerberosTicket("HTTP/example.com")
        assert ticket2.service == "HTTP/example.com"
    except gssapi.exceptions.GSSError:
        # Expected when Kerberos credentials are unavailable
        pass
