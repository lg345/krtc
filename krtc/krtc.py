try:
    import gssapi
    from gssapi import Name, NameType
    import base64
except ImportError:
    raise ImportError("Please install gssapi: pip install gssapi")


class KerberosTicket:
    """
    Cross-platform Kerberos implementation using gssapi.
    Works on Windows, Linux, and macOS.
    
    This class creates and manages Kerberos authentication tokens using the GSSAPI
    (Generic Security Service Application Program Interface) library. It handles
    the Kerberos authentication handshake for HTTP services.
    
    Example:
        >>> ticket = KerberosTicket("HTTP@pswww.slac.stanford.edu")
        >>> headers = ticket.getAuthHeaders()
        >>> # Use headers in HTTP request:
        >>> # requests.get(url, headers=headers)
    
    Prerequisites:
        1. Install gssapi: pip install gssapi
        2. Authenticate with Kerberos: kinit username@REALM
        3. Check tickets: klist
    
    Attributes:
        service: The service principal name (e.g., "HTTP@hostname")
        auth_header: The Negotiate authentication token (generated during init)
    """
    
    def __init__(self, service):
        """
        Initialize a Kerberos ticket for a service.
        
        Args:
            service (str): Service principal name in format "HTTP@hostname" or "HTTP/hostname".
                          Examples:
                          - "HTTP@pswww.slac.stanford.edu"
                          - "HTTP/server.example.com"
        
        Raises:
            ImportError: If gssapi is not installed.
            gssapi.exceptions.GSSError: If Kerberos initialization fails.
        """
        self.service = service
        self._context = None
        self._setup_context()
    
    def _setup_context(self):
        """
        Initialize the GSSAPI security context.
        
        Creates a GSSAPI security context for the service principal and generates
        the initial authentication token. This is called during __init__.
        
        Raises:
            gssapi.exceptions.GSSError: If context creation or token generation fails.
                                       Common causes: missing Kerberos credentials,
                                       invalid service principal, or Kerberos not configured.
        """
        target_name = Name(self.service, NameType.hostbased_service)
        
        self._context = gssapi.SecurityContext(
            name=target_name,
            usage='initiate'
        )
        
        # Get initial token
        token = self._context.step()
        self.auth_header = "Negotiate " + base64.b64encode(token).decode('ascii')
    
    def verify_response(self, auth_header):
        """
        Verify and process the server's Kerberos response.
        
        Completes the Kerberos authentication handshake by processing the
        server's response token. This is typically called after receiving
        a 401 response with a Negotiate challenge.
        
        Args:
            auth_header (str): The 'www-authenticate' header from the server response,
                             typically containing "Negotiate <token>".
        
        Raises:
            ValueError: If the auth_header doesn't contain a Negotiate token.
            RuntimeError: If the ticket has already been verified or used.
            gssapi.exceptions.GSSError: If token verification fails.
        """
        # Handle comma-separated lists of authentication fields
        for field in auth_header.split(","):
            kind, __, details = field.strip().partition(" ")
            if kind.lower() == "negotiate":
                auth_details = details.strip()
                break
        else:
            raise ValueError("Negotiate not found in %s" % auth_header)
        
        if self._context is None:
            raise RuntimeError("Ticket already used for verification")
        
        token = base64.b64decode(auth_details)
        self._context.step(token)
        self._context = None
    
    def getAuthHeaders(self):
        """
        Get the HTTP Authorization headers for the Kerberos ticket.
        
        Returns the dictionary containing the Authorization header with the
        Negotiate token. This should be added to HTTP request headers.
        
        Returns:
            dict: Dictionary with key 'Authorization' containing the Negotiate token.
                  Example: {'Authorization': 'Negotiate YIIFXDCCBVigAwIBA...'}
        
        Example:
            >>> ticket = KerberosTicket("HTTP@hostname.com")
            >>> headers = ticket.getAuthHeaders()
            >>> requests.get(url, headers=headers)
        """
        return {"Authorization": self.auth_header}