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
                                
