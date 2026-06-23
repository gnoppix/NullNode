## How does the bootstrap server TLS work?

Bootstrap servers now speak TLS directly on their listen port (no reverse
proxy needed). Set the cert paths via environment variables:

```bash
export NULLNODE_BOOTSTRAP_CERT=/etc/letsencrypt/live/bootstrap-eu.gnoppix.org/fullchain.pem
export NULLNODE_BOOTSTRAP_KEY=/etc/letsencrypt/live/bootstrap-eu.gnoppix.org/privkey.pem
./nullnode.sh bootstrap
```

Without the cert env vars, the server falls back to plain `ws://` (backward
compatible).

## How does the client verify the bootstrap server's identity?

On every connection to a bootstrap seed, the client performs 5 checks:

1. **Cert fingerprint (TOFU pin)** -- first-seen cert is pinned to
   `~/.nullnode/bootstrap_pin_cache.json`. Same cert = accept. Changed cert =
   check rotation rules.
2. **Cert validity window** -- accepts rotation if cert is currently valid
   AND was issued within 90 days (Let's Encrypt cycle). This handles long
   offline periods (100+ days).
3. **Domain check** -- cert SAN/CN must match `*.gnoppix.org` or
   `*.gnoppix.com`. Prevents attacker from using their own domain.
4. **CA check** -- cert issuer must be Let's Encrypt / ISRG. Prevents
   attacker from using a valid cert for our domain obtained from a
   compromised/rogue CA.
5. **TOFU rotation rules** -- if cert changed and validity window check
   fails, falls back to pin age (< 90 days = accept, >= 90 days = reject).

If all checks pass, the client trusts the bootstrap for DHT queries.

## What if the bootstrap server's Let's Encrypt cert rotates while I'm offline?

The client accepts rotation if the new cert is currently valid AND was
issued within the last 90 days. Let's Encrypt renews every 60-80 days, so
even if you're offline for 100 days, the new cert is within its validity
window and accepted automatically.

If the cert changes after 90+ days of being offline, the client rejects it
(possible MITM). Delete `~/.nullnode/bootstrap_pin_cache.json` to reset TOFU
and re-trust the new cert.

## How does bot/scanner detection work?

Suspicious connections are logged to `bot_connection.log` in the
application directory. The log detects:

- **SCANNER**: 10+ consecutive bad envelopes or stale timestamps
- **BAD_TYPE**: Unknown message types sent to the DHT port
- **SUSPECT**: 5+ consecutive failures before disconnect

Log format: `2026-06-23T14:32:01+0000 203.0.113.5:54321 SCANNER (bad_envelope x10)`

This helps identify port scanners, vulnerability probes, and misconfigured
clients hitting the bootstrap server.

## How does the bootstrap server protect against rogue CAs?

Even if an attacker obtains a valid cert for `*.gnoppix.org` from a
compromised or rogue CA, the client checks the cert's issuer. Only
certificates chaining to Let's Encrypt / ISRG are accepted. An attacker
with a cert from their own CA (or a different CA) is rejected.

Additionally, the TOFU pin means the client remembers the cert fingerprint
from the first legitimate connection. Any subsequent cert change must pass
the rotation rules (validity window + pin age), making it extremely hard
for an attacker to substitute certs even with a valid cert for the domain.

     Let me explain why STUN is used and whether it's actually needed.                                                                       
     
     ## why STUN exists in NullNode                                                                                                                            
                                                                                                                                                            
     STUN lets a client behind a NAT/router discover its public IP:port as seen from the internet. This is needed for direct P2P connections:               
                                                                                                                                                            
     Alice (behind NAT)              Bob (behind NAT)                                                                                                       
       192.168.1.5:4567  ──────►  ???  (Bob can't reach Alice)                                                                                              
                                                                                                                                                            
     Alice asks STUN server:                                                                                                                                
       "what address do you see me as?"                                                                                                                     
       STUN replies: "203.0.113.42:51234"                                                                                                                   
                                                                                                                                                            
     Alice now knows her public endpoint.                                                                                                                   
     She can share it in the DHT so Bob can connect.                                                                                                        
                                                                                                                                                            
     The flow is: STUN -> discover public endpoint -> advertise in DHT -> other peers connect via that endpoint.                                            
     Why it's questionable                                                                                                                                  
                                                                                                                                                            
     1. It leaks your IP to a third-party Google server. The STUN servers in the code are all Google (stun.l.google.com, etc.). Google sees your IP,        
     timestamp, and port. For a privacy messenger this is architecturally contradictory.                                                                    
                                                                                                                                                            
     2. DHT already provides peer discovery. The DHT stores null_id -> address mappings. If Bob is online, his address is already in the DHT. Alice         
     looks him up directly. STUN is only needed to publish that address.                                                                                    
                                                                                                                                                            
     3. Most DHT writes happen through other peers, not directly. The Kademlia lookup finds peers who are already reachable. The STUN step is a             
     bootstrap chicken-and-egg: you need STUN to publish your address, but you only need your address if others can't reach you.                            
                                                                                                                                                            
     4. It doesn't solve the harder problem. If both peers are behind symmetric NAT, STUN gives you the address but the port changes per destination.       
     That's where TURN/ICE would be needed, which NullNode doesn't do.                                                                                      
     What actually uses it right now                                                                                                                        
                                                                                                                                                            
     Looking at the code: nat.py exists but p2p.py never calls it. The P2P handshake just connects to whatever address the DHT returned. STUN is dead       
     code in practice.                                                                                                                                      
     Recommendation                                                                                                                                         
                                                                                                                                                            
     For a privacy-first messenger, STUN should be:                                                                                                         
                                                                                                                                                            
     - Made opt-in (not enabled by default)                                                                                                                 
     - Replaced with user-supplied endpoints for advanced users (e.g., --public-addr wss://my-server:9001)                                                  
     - Or removed entirely -- if you're behind NAT, you can still publish your address manually (as the DHT's advertise_address already allows) or use      
     a public VPS as a relay                                                                                                                                
                                
