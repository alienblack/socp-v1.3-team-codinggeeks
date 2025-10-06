import json
from socp.core.proto import validate_envelope
from socp.core.security import verify_signature
from socp.core.router import router  
from socp.core.types import Envelope, Link 

async def on_message(websocket, message):
    try:
        
        raw = json.loads(message)
        print(f"[on_message] Received message: {raw}")

       
        validate_envelope(raw)

   
        if not verify_signature(raw):
            await websocket.send(json.dumps({"error": "Invalid signature"}))
            return

        
        env = Envelope.from_json(raw)

       
        origin = Link(websocket, ident=env.from_)

       
        await router.route(env, origin)

    except Exception as e:
        
        print(f"[on_message] Exception occurred: {e}")
        await websocket.send(json.dumps({"error": str(e)}))
