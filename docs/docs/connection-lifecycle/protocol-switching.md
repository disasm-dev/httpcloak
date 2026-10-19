---
title: Protocol Switching
sidebar_position: 3
---

# Protocol Switching

Sessions can move between HTTP/1.1, HTTP/2 and HTTP/3 mid-flight. `RefreshWithProtocol("h1" | "h2" | "h3" | "auto")` closes every live connection then re-handshakes on the protocol you pass in. The setting persists, so subsequent plain `Refresh()` calls keep using that protocol until the next switch.

For sessions that should never auto-negotiate at all, pass `WithSwitchProtocol("h2")` (or h1 / h3) to `NewSession`. Every `Refresh()` on that session lands on the configured protocol.

## Why you'd want this

**Force H2 because the target's H3 is broken.** Some CDNs ship a flaky H3 endpoint while their H2 works fine. The auto-negotiator picks H3 when the host advertises it, so the broken path stays invisible until you pin H2.

**Force H3 because the target's H2 path blocks you.** Common on Cloudflare. H2 runs through more middleware where bot detection lives, while H3 often draws lighter filtering, especially on plans where the operator hasn't enabled Bot Management for HTTP/3.

**Test which protocol the target accepts.** Anti-bot tooling sometimes scores H1, H2 and H3 traffic differently. Locking to one protocol and re-running the same scrape isolates that variable.

One useful combination: warm tickets on H3, then switch to H2 for the workload. The retained ticket means H2 starts from a resumed handshake.

:::info
Auto-negotiation runs through `raceH3H2`, which fires H3 and H2 in parallel and takes whichever wins. That's good for latency, unpredictable across runs. Locking to one protocol gives you a deterministic next-request path, which matters when debugging a site-specific issue and you need to know exactly what's about to go on the wire.
:::

## Code

import Tabs from '@theme/Tabs';
import TabItem from '@theme/TabItem';

<Tabs groupId="lang">
<TabItem value="go" label="Go">

```go
s := httpcloak.NewSession("chrome-latest")
defer s.Close()
ctx := context.Background()

// Auto-negotiate first. Most likely picks H2.
r, _ := s.Get(ctx, "https://tls.peet.ws/api/all")
fmt.Printf("auto: %s\n", r.Protocol)
r.Close()

// Force H2. Useful when a site's H3 is flaky.
s.RefreshWithProtocol("h2")
r, _ = s.Get(ctx, "https://tls.peet.ws/api/all")
fmt.Printf("h2: %s\n", r.Protocol)
r.Close()

// Force H1. Heavy, slow, sometimes the only path that works.
s.RefreshWithProtocol("h1")
r, _ = s.Get(ctx, "https://tls.peet.ws/api/all")
fmt.Printf("h1: %s\n", r.Protocol)
r.Close()

// Back to auto.
s.RefreshWithProtocol("auto")
```

</TabItem>
<TabItem value="python" label="Python">

```python
with httpcloak.Session(preset="chrome-latest") as s:
    s.get("https://tls.peet.ws/api/all")          # auto
    s.refresh(switch_protocol="h2")
    s.get("https://tls.peet.ws/api/all")          # h2
    s.refresh(switch_protocol="h1")
    s.get("https://tls.peet.ws/api/all")          # h1
```

</TabItem>
<TabItem value="nodejs" label="Node.js">

```javascript
const s = new httpcloak.Session({ preset: "chrome-latest" });
try {
  await s.get("https://tls.peet.ws/api/all");     // auto
  s.refresh("h2");
  await s.get("https://tls.peet.ws/api/all");     // h2
  s.refresh("h1");
  await s.get("https://tls.peet.ws/api/all");     // h1
} finally {
  s.close();
}
```

</TabItem>
<TabItem value="dotnet" label=".NET">

```csharp
using var s = new Session(preset: "chrome-latest");
s.Get("https://tls.peet.ws/api/all");             // auto
s.Refresh(switchProtocol: "h2");
s.Get("https://tls.peet.ws/api/all");             // h2
s.Refresh(switchProtocol: "h1");
s.Get("https://tls.peet.ws/api/all");             // h1
```

</TabItem>
</Tabs>

## Lock at construction time

To skip auto-negotiation entirely, set the protocol when the session is built. Every `Refresh()` then lands on that protocol.

```go
s := httpcloak.NewSession("chrome-latest", httpcloak.WithSwitchProtocol("h2"))
```

Python: `Session(preset=..., switch_protocol="h2")`. Node.js: `new Session({ preset, switchProtocol: "h2" })`. .NET: `new Session(preset, switchProtocol: "h2")`.

There's also `WithForceHTTP1`, `WithForceHTTP2`, `WithForceHTTP3` and `WithDisableHTTP3`, which pin the protocol from request one without needing a `Refresh()`. Use those for sessions that should never speak anything but the chosen protocol.

## H3 caveats

Three things to know before reaching for `RefreshWithProtocol("h3")`:

- The preset has to support H3. If it doesn't, the call returns `preset %q does not support HTTP/3` and the switch is refused.
- The host has to actually serve H3. Forcing H3 against a host that doesn't advertise it just times out, since there's no automatic fallback when the protocol is forced.
- H3 over a UDP-blocking proxy isn't going to work. Most corporate networks and plenty of SOCKS5 proxies don't pass UDP at all. Use `WithForceHTTP2` in those environments.

If H3 is wanted sometimes and H2 other times, keep two sessions rather than toggling. Every switch closes the active connection.

## Protocol values

`RefreshWithProtocol` accepts `"h1"`/`"http1"`/`"1"` for HTTP/1.1, `"h2"`/`"http2"`/`"2"` for HTTP/2, `"h3"`/`"http3"`/`"3"` for HTTP/3, and `"auto"` (or empty string) for auto-negotiation: H2 with fallback to H1, and H3 raced against H2 once the host has advertised it. Anything else returns an error.
