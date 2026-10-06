"""Hand-built test vectors. Known input, known answer.

MINIMAL is a deliberately tiny but well-formed ClientHello so you get a tight
red-green loop before you have captured anything real. Count the bytes by hand
once - it is a useful ten minutes.

    record    16 0301 003c
    handshake 01 000038
    body      0303 | random(32) | sid_len=0 | ciphers(2) | compression | extensions(2)
"""

MINIMAL_HEX = (
    "160301003c"                                                          # record
    "01000038"                                                            # handshake hdr
    "0303"                                                                # legacy_version
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"    # random
    "00"                                                                  # session_id len 0
    "00041301c02b"                                                        # 2 cipher suites
    "0100"                                                                # compression [0]
    "000b"                                                                # extensions len 11
    "00000000"                                                            #   server_name, 0B
    "002b0003020304"                                                      #   supported_versions
)

# Same thing with the two cipher suites swapped. Every length stays identical,
# so the only difference is order - exactly the kind of thing your differ exists
# to catch.
SWAPPED_CIPHERS_HEX = MINIMAL_HEX.replace("00041301c02b", "0004c02b1301")

MINIMAL = bytes.fromhex(MINIMAL_HEX)
SWAPPED_CIPHERS = bytes.fromhex(SWAPPED_CIPHERS_HEX)
