"""Hand-built ClientHello test vectors.

MINIMAL layout:
    record    16 0301 003c
    handshake 01 000038
    body      0303 | random(32) | session_id(0) | ciphers(2) | compression | extensions
"""

MINIMAL_HEX = (
    "160301003c"                                                          # record header
    "01000038"                                                            # handshake header
    "0303"                                                                # legacy_version
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"    # random
    "00"                                                                  # session_id, empty
    "00041301c02b"                                                        # 2 cipher suites
    "0100"                                                                # compression [0]
    "000b"                                                                # extensions, 11 bytes
    "00000000"                                                            # server_name, empty
    "002b0003020304"                                                      # supported_versions
)

# Identical except the two cipher suites are swapped: same lengths throughout,
# so order is the only difference.
SWAPPED_CIPHERS_HEX = MINIMAL_HEX.replace("00041301c02b", "0004c02b1301")

MINIMAL = bytes.fromhex(MINIMAL_HEX)
SWAPPED_CIPHERS = bytes.fromhex(SWAPPED_CIPHERS_HEX)
