# 5. Measuring without fooling yourself

!!! abstract "TL;DR"
    A page that arrives says little on its own: a server can decide on the address, the headers, the hello, the timing or JavaScript. Before crediting the fingerprint, rule out the rest with controls: a plain client, the same plain client carrying the browser's headers, the transport alone, and the address crossed with the client. `pybrws ab` runs the client controls in interleaved rounds and keeps a log. `pybrws isolate` crosses client and address. This page shows how to run them and how to read them. It publishes no result.

## What one request cannot tell you

A request that gets the page tells me that the page arrived, once, at my address, at that moment. A server can decide on much more than the hello: the address, the rate, the headers, cookies, and whatever JavaScript a browser would have run. pybrws runs none (see [No JavaScript engine](../advanced.md#no-javascript-engine)). Even the status can mislead: a challenge page can arrive with a 200.

So I never read a single request as a result. I compare arms: clients that differ from pybrws in ways I can name, each sent the same request in the same rounds.

## The arms

| Arm | What it sends | How it differs from `pybrws` |
|---|---|---|
| `pybrws` | the profile: its hello, its HTTP/2 start and its headers | |
| `httpx` | httpx, with OpenSSL's TLS and httpx's own headers | the hello, the HTTP/2 start and the headers, all at once |
| `httpx+ff` | httpx, with OpenSSL's TLS, carrying the profile's header list | the hello and the HTTP/2 start; the headers are the profile's |
| `pybrws-h3` | pybrws over QUIC, with `firefox157_quic` | the transport alone |

The plain `httpx` arm answers the first question: if a plain client is served too, the target is not telling these clients apart, and the other arms establish nothing there either way. When `pybrws` is served and `httpx` is not, the difference could be the hello or the headers, since httpx sends its own User-Agent. `httpx+ff` keeps OpenSSL's hello and carries the profile's headers, which separates the two. That arm is in the default set for this reason.

A control target is the last piece. `--control URL` names a URL every client is served by. It runs in every round, and its row reads `control`. If the control does not serve an arm, either that arm is broken from where the run is made or the control is not one, and that arm's other rows say nothing.

## Running it

The arms need httpx, from the `measure` extra:

```console
pip install "pybrws[measure]"
pybrws ab --targets https://example.com/page --control https://example.com/ --rounds 10
```

Each round sends every target one request from every arm, a second apart (`--pause`), then starts again. Interleaving matters: if the target's answers drift during the run, the drift hits every arm, not whichever one happened to go last. `--profile` sets the profile the `pybrws` arm sends and whose headers `httpx+ff` carries.

To ask whether the transport matters, add the HTTP/3 arm. It needs the `http3` extra as well:

```console
pybrws ab --arms pybrws pybrws-h3 httpx --targets https://example.com/
```

`pybrws-h3` against `pybrws` is the only pair whose single variable is the transport, and only because both send Firefox 157. ab refuses to run it where it would compare more than that. With another profile:

```console
pybrws ab --arms pybrws pybrws-h3 --profile chrome155 --targets https://example.com/
```

```text
pybrws-h3 sends Firefox 157's QUIC hello, so with --profile chrome155 the pybrws and pybrws-h3 arms would differ in browser as well as transport; drop pybrws-h3 or use --profile firefox157
```

With a proxy, which the QUIC arm cannot use:

```console
pybrws ab --arms pybrws pybrws-h3 --proxy http://proxy.example.com:8080 --targets https://example.com/
```

```text
the h3 arm has no proxy path, so --proxy would compare a proxied arm against a direct one
```

## Reading the table

For each target, ab prints one cell per arm, how many of its requests were served out of how many were sent, then a reading. `flapping` marks a cell whose statuses changed between rounds. Served means the page arrived. A 403, 429 or 503 is not served. Neither is a redirect still pending after five hops, nor a body under 100,000 bytes that carries one of a challenge page's marks.

The reading is the first of these that applies, checked in this order:

| When | ab reads |
|---|---|
| the target is the control | `control` |
| plain httpx was served every time | `host serves a plain client too -- discriminates on nothing here` |
| pybrws-h3 never got an HTTP answer | `no HTTP/3 here -- not a transport comparison` |
| pybrws never got an HTTP answer | `no answer over TCP at all -- check the network, not the host` |
| both pybrws and pybrws-h3 ran | `served on both transports`, `*** served over h3, blocked over h2 ***`, `*** served over h2, blocked over h3 ***`, `blocked on both transports -- not a transport question`, or `transport differs but neither arm is deterministic` |
| pybrws served every time, httpx never, httpx+ff every time | `*** headers alone suffice: httpx+ff served too, the fingerprint bought nothing here ***` |
| pybrws served every time, httpx never, httpx+ff never | `pybrws passes on the fingerprint: httpx+ff blocked like httpx` |
| pybrws served every time, httpx never, httpx+ff not run or not consistent | `pybrws passes, baseline blocked (add httpx+ff to attribute it)` |
| httpx+ff served every time, httpx and pybrws never | `*** fingerprint is a liability here: httpx+ff served, pybrws blocked -- the browser hello is what gets refused ***` |
| otherwise | `pybrws better, not deterministic`, `no difference` or `baseline better` |

Only two of those readings attribute anything to the hello: one where it helped, one where it hurt. Each is still one run, from one address, at one time. Rates, not verdicts: a cell of 10 out of 10 means more than one request that worked, and a flapping cell means the same request got different answers, so no single round speaks for the target.

Every sample is appended to `ab-test-log.jsonl` in the working directory, or to the file `--log` names. `--no-log` appends nothing. A line holds the run, the time, the round, the target, the arm, the status, the body's size, whether it was served, any error, the profile and whether a proxy was used. `pybrws ab --history` summarises the runs in the log, so a run next week can be read against this one, and a change shows up as a change.

## The address

`ab --proxy URL` sends the `pybrws` arm through a proxy. That changes two things at once, the address and the client, and ab says so when it starts. `pybrws isolate` crosses them instead: pybrws and httpx, each sent directly and each through the proxy.

```console
pybrws isolate --targets https://example.com/ --proxy http://user:pass@proxy.example.com:8080
```

`--proxy` defaults to `PYBRWS_PROXY`. isolate prints how many requests each of the four arms got served, then every status. Only the full square tells the address from the client:

| pybrws direct | pybrws proxy | httpx direct | httpx proxy | What it says |
|---|---|---|---|---|
| served | served | served | served | neither the client nor this address matters to the target |
| served | not served | served | not served | the address decides |
| served | served | not served | not served | the client decides, from either address |
| served | not served | not served | not served | it takes both: this client, and the direct address |

Two limits of isolate:

- **Its httpx arms carry httpx's own headers**, so along the client axis the headers move with the hello. To separate those, run ab's `httpx+ff` from each address.
- **It counts by status alone.** Anything but a 403, 429 or 503 counts as served, a challenge page with a 200 included. Read its list of statuses, and use ab where bodies matter.

When a target refuses, `pybrws waf` reads which protection's marks the response carries: a header, a cookie name, a phrase on a block page. It says what answered, not why.

## What this page leaves out

This page publishes no result. It shows how to run the measurements and how to read them. What a site does with your requests is yours to measure: only on sites you are allowed to test, with few rounds, and a pause long enough to stay polite.
