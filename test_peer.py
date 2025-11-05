import sys
import time
from daemon.peer import Peer

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_peer.py <peer_name>")
        sys.exit(1)
        
    peer_name = sys.argv[1]
    
    # Create and start peer
    peer = Peer("127.0.0.1", 9000, 0)  # 0 = random port
    print(f"Starting peer {peer_name} (ID: {peer.peer_id})")
    print(f"Listening on port {peer.listen_port}")
    
    # Register with tracker
    if not peer.register_with_tracker():
        print("Failed to register with tracker")
        return
        
    try:
        while True:
            # Every 5 seconds, get peer list and try to connect
            peers = peer.get_active_peers()
            print(f"\nActive peers: {len(peers)}")
            
            for p in peers:
                if p["id"] not in peer.peers:  # If not already connected
                    print(f"Connecting to peer {p['id']}")
                    peer.connect_to_peer(p)
                    
            # Send broadcast message
            if len(peer.peers) > 0:
                msg = f"Hello from {peer_name}!"
                print(f"\nBroadcasting: {msg}")
                peer.broadcast_message(msg)
                
            # Check for incoming messages
            while True:
                msg = peer.get_next_message(timeout=0.1)
                if not msg:
                    break
                print(f"\nReceived message: {msg}")
                
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\nStopping peer...")
        peer.stop()

if __name__ == "__main__":
    main()