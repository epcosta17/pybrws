"""my_firefox: a profile of your own, built on pybrws's firefox157.

Every name the TCP client reads is spelled out below, so the file shows the
whole contract. The required names are those in
`pybrws.profiles.REQUIRED_TCP`, plus EXTENSIONS. Change a value to what your
own browser sends, then check the result:

    pybrws verify --local --profile my_firefox.py --capture my_firefox.hex
    pybrws --profile my_firefox.py https://example.com/

pybrws loads this file on its own, outside any package, so its imports are
absolute.
"""

from pybrws.profiles import firefox157

# The profile's own name. `pybrws -v` prints it, and `pybrws ab` logs it.
NAME = "my_firefox"

# The ClientHello's fixed fields: record and legacy versions, the cipher
# suites in order, the session id size and the compression methods.
RECORD_VERSION = firefox157.RECORD_VERSION
LEGACY_VERSION = firefox157.LEGACY_VERSION
CIPHER_SUITES = firefox157.CIPHER_SUITES
SESSION_ID_SIZE = firefox157.SESSION_ID_SIZE
COMPRESSION_METHODS = firefox157.COMPRESSION_METHODS

# The key shares, as (group, public key size) in the order they are sent.
KEY_SHARE_GROUPS = firefox157.KEY_SHARE_GROUPS

# The extensions in wire order, as (type, payload). Bytes are sent as they
# are; a function is called with the connection for each hello. A browser
# that draws its order per connection is written as extension_order(ctx)
# and payload_for(type, ctx) instead (see chrome155).
EXTENSIONS = firefox157.EXTENSIONS

# HTTP/2: the SETTINGS frame, the connection WINDOW_UPDATE, the first stream
# id and the order of the pseudo-headers.
H2_SETTINGS = firefox157.H2_SETTINGS
H2_CONNECTION_WINDOW_UPDATE = firefox157.H2_CONNECTION_WINDOW_UPDATE
H2_FIRST_STREAM_ID = firefox157.H2_FIRST_STREAM_ID
H2_PSEUDO_ORDER = firefox157.H2_PSEUDO_ORDER

# A navigation's headers in wire order, and the header a cookie goes before:
# over HTTP/2, then over HTTP/1.1.
H2_NAVIGATION_HEADERS = firefox157.H2_NAVIGATION_HEADERS
H2_COOKIE_BEFORE = firefox157.H2_COOKIE_BEFORE
H1_HEADERS = firefox157.H1_HEADERS
H1_COOKIE_BEFORE = firefox157.H1_COOKIE_BEFORE

# Optional from here on.

# The priority carried in the HTTP/2 HEADERS frame. Without it the frame
# carries none.
H2_HEADERS_PRIORITY = firefox157.H2_HEADERS_PRIORITY

# Where cookie fields go in an HTTP/2 set that lacks H2_COOKIE_BEFORE, as
# the fetch POST does. Without it they go last.
H2_COOKIE_BEFORE_FALLBACK = firefox157.H2_COOKIE_BEFORE_FALLBACK

# How much the greased ECH payload grows when a session ticket is offered.
# Without it a resumed hello keeps the fresh hello's ECH payload size.
ech_growth_for_psk = firefox157.ech_growth_for_psk

# The header sets of other kinds of request. A request whose set is missing
# raises pybrws.client.Unmeasured rather than sending a guess.
H1_POST_XHR_HEADERS = firefox157.H1_POST_XHR_HEADERS
H2_POST_XHR_HEADERS = firefox157.H2_POST_XHR_HEADERS
H1_POST_FORM_HEADERS = firefox157.H1_POST_FORM_HEADERS
H2_POST_FORM_HEADERS = firefox157.H2_POST_FORM_HEADERS
H1_POST_FORM_SCRIPT_HEADERS = firefox157.H1_POST_FORM_SCRIPT_HEADERS
H2_POST_FORM_SCRIPT_HEADERS = firefox157.H2_POST_FORM_SCRIPT_HEADERS
H1_IMAGE_HEADERS = firefox157.H1_IMAGE_HEADERS
H2_IMAGE_HEADERS = firefox157.H2_IMAGE_HEADERS

# No DRAWN: firefox157 sends the same shape every time, so `pybrws verify`
# compares this profile strictly. A profile whose browser draws a field per
# connection names it in DRAWN (see chrome155).
