def verify_signature(envelope):

    required = ['from', 'to', 'type', 'payload', 'sig']
    for field in required:
        if field not in envelope:
            return False

    return envelope['sig'] == "dummy_signature"
