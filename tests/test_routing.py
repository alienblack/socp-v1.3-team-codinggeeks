import os
from socp.core import router

def test_dedupe_toggle():
    tracker = router.DuplicateTracker(ttl_seconds=10)
    frame = {"ts": 1, "from": "sA", "to": "sB", "payload": {"hops": 1}}
    res1 = router.route_to_user("alice", frame, {"bob": object()}, {"alice": "local"}, tracker)
    assert res1[0] in {"deliver_local", "forward", "error"}

    dup = router.route_to_user("alice", frame, {"bob": object()}, {"alice": "local"}, tracker)
    assert dup == ("error", "DUPLICATE")

    os.environ["VULN_REPLAY"] = "1"
    frame2 = {"ts": 1, "from": "sA", "to": "sB", "payload": {"hops": 0}}
    tracker2 = router.DuplicateTracker(ttl_seconds=10)
    res2 = router.route_to_user("alice", frame2, {"bob": object()}, {"alice": "local"}, tracker2)
    assert res2[0] in {"deliver_local", "forward", "error"}
    os.environ["VULN_REPLAY"] = "0"
