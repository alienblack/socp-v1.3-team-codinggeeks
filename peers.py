peer_table = {}  # e.g., { "server1": websocket }

def register_peer(server_id, websocket):
    peer_table[server_id] = websocket

def get_peer_for_user(username):

    return peer_table.get("server1", None)
