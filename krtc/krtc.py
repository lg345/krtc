import base64

# Try to import gssapi first (cross-platform), fall back to pykerberos (Linux)
try:
    import gssapi
    from gssapi import Name, NameType
    HAS_GSSAPI = True
except ImportError:
    HAS_GSSAPI = False
    try:
        import kerberos
    except ImportError:
        raise ImportError(
            "Please install either gssapi (recommended, cross-platform) "
            "or pykerberos (Linux only): pip install gssapi  # or: pip install pykerberos"
        )


class KerberosTicket:
    """
    Cross-platform Kerberos implementation with dual backend support.
    
    This class creates and manages Kerberos authentication tokens using either:
    - gssapi (recommended): Works on Windows, Linux, and macOS
    - pykerberos (legacy): Linux only, for backwards compatibility
    
    The implementation automatically selects the available backend, preferring gssapi
    if both are installed. This handles the Kerberos authentication handshake for HTTP services.
    
    Example:
        >>> ticket = KerberosTicket("HTTP@pswww.slac.stanford.edu")
        >>> headers = ticket.getAuthHeaders()
        >>> # Use headers in HTTP request:
        >>> # requests.get(url, headers=headers)
    
    Prerequisites:
        1. Install gssapi: pip install gssapi (recommended, cross-platform)
           OR pykerberos: pip install pykerberos (Linux only)
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
            ImportError: If neither gssapi nor pykerberos is installed.
            gssapi.exceptions.GSSError: If gssapi Kerberos initialization fails.
            kerberos.GSSError: If pykerberos Kerberos initialization fails.
        """
        self.service = service
        self._context = None
        self._setup_context()
    
    def _setup_context(self):
        """
        Initialize the Kerberos security context.
        
        Creates a Kerberos security context for the service principal and generates
        the initial authentication token. Uses gssapi if available, otherwise falls
        back to pykerberos. This is called during __init__.
        
        Raises:
            gssapi.exceptions.GSSError: If using gssapi and context creation fails.
            kerberos.GSSError: If using pykerberos and authentication fails.
                              Common causes: missing Kerberos credentials,
                              invalid service principal, or Kerberos not configured.
        """
        if HAS_GSSAPI:
            self._setup_context_gssapi()
        else:
            self._setup_context_pykerberos()
    
    def _setup_context_gssapi(self):
        """
        Initialize the GSSAPI security context.
        
        Creates a GSSAPI security context for the service principal and generates
        the initial authentication token.
        
        Raises:
            gssapi.exceptions.GSSError: If context creation or token generation fails.
        """
        target_name = Name(self.service, NameType.hostbased_service)
        
        self._context = gssapi.SecurityContext(
            name=target_name,
            usage='initiate'
        )
        
        # Get initial token
        token = self._context.step()
        self.auth_header = "Negotiate " + base64.b64encode(token).decode('ascii')
    
    def _setup_context_pykerberos(self):
        """
        Initialize the pykerberos context.
        
        Uses pykerberos for Kerberos authentication (Linux-only, legacy).
        Generates the initial authentication token.
        
        Raises:
            kerberos.GSSError: If authentication fails.
        """
        # pykerberos uses a different format: "HTTP/hostname"
        service_principal = self.service.replace("@", "/")
        
        self._context, self.auth_header = kerberos.authGSSClientInit(service_principal)
        # authGSSClientStep with empty challenge generates initial token
        kerberos.authGSSClientStep(self._context, "")
    
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
            gssapi.exceptions.GSSError: If using gssapi and token verification fails.
            kerberos.GSSError: If using pykerberos and token verification fails.
        """
        if HAS_GSSAPI:
            self._verify_response_gssapi(auth_header)
        else:
            self._verify_response_pykerberos(auth_header)
    
    def _verify_response_gssapi(self, auth_header):
        """
        Verify response using gssapi backend.
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
    
    def _verify_response_pykerberos(self, auth_header):
        """
        Verify response using pykerberos backend.
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
        
        kerberos.authGSSClientStep(self._context, auth_details)
        kerberos.authGSSClientClean(self._context)
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