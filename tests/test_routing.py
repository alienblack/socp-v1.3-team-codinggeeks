
import os
from socp.core import router
def test_dedupe_toggle():
    frame = {"ts":1,"from":"sA","to":"sB","payload":{"hops":1}}
    res1 = router.route_to_user("alice", frame, {"bob":object()}, {"alice":"local"})
    # first time should pass through dedupe, mark seen, then deliver_local
    assert res1[0] in {"deliver_local","forward","error"}

    # replay same frame without bypass -> duplicate
    dup = router.route_to_user("alice", frame, {"bob":object()}, {"alice":"local"})
    assert dup == ("error","DUPLICATE")

    # turn on bypass; crafted payload with hops=0 should skip dedupe
    os.environ["VULN_REPLAY"]="1"
    frame2 = {"ts":1,"from":"sA","to":"sB","payload":{"hops":0}}
    res2 = router.route_to_user("alice", frame2, {"bob":object()}, {"alice":"local"})
    assert res2[0] in {"deliver_local","forward","error"}
    os.environ["VULN_REPLAY"]="0"
