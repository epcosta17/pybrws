# The method

I made pybrws's profiles in five steps, and the tools for each step ship in the package. These articles walk through them on my own captures of Firefox 157 and Chrome 155, so that you can repeat them with your own browser.

| Step | Article | Tools |
|---|---|---|
| 1 | [Catching your browser's ClientHello](01-capture.md) | `pybrws capture hello`, `capture request`, `capture h2`, `capture quic`, `pybrws read-quic` |
| 2 | [What changes between connections](02-compare.md) | `pybrws capture hello --count`, `capture resumed`, `pybrws ja4` |
| 3 | [Writing the profile](03-profile.md) | the example profile, [my_firefox.py](../examples/my_firefox.py) |
| 4 | [Proving it](04-verify.md) | `pybrws verify --local`, `pybrws probe` |
| 5 | [Measuring without fooling yourself](05-measure.md) | `pybrws ab`, `pybrws isolate` |

## What you need

- pybrws. The QUIC tools need the `http3` extra, and step 5 needs `measure`:

    ```console
    pip install "pybrws[http3,measure]"
    ```

- The browser you want to imitate, on the same machine.
- Wireshark, if you want to see the packets as well as the files. No step requires it.

The capture tools listen on `127.0.0.1:4443`. Open them in the browser as `https://pybrws.127.0.0.1.nip.io:4443/`. nip.io is a public DNS service that answers any name ending in `127.0.0.1.nip.io` with `127.0.0.1`. That way the browser connects to your own machine and still sends a server name, which it leaves out when the URL holds an IP address.

## The captures behind these pages

The hellos and header lists in these articles are files in the `fixtures/` folder of the [repository](https://github.com/epcosta17/pybrws). These tools wrote them from Firefox 157 and Chrome 155 on Windows. Every number in the articles comes from those files, from the profiles' code, or from running a command on them.

Two of the files ship in the package, so `pybrws verify --local` works from an installed wheel:

| File | What it is |
|---|---|
| `reference-firefox-157-windows-fresh.hex` | Firefox 157's ClientHello, the capture `firefox157` is compared with |
| `chrome-1.hex` | the first of six Chrome 155 ClientHellos taken in one run, the capture `chrome155` is compared with |
