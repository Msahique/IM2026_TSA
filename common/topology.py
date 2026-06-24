"""Static topology of the building block (who runs where).

Every server reads its peers' URLs from here (overridable via env vars),
so the independent servers can locate and call each other.
"""
import os


def _u(env, default):
    return os.getenv(env, default)

# Use 127.0.0.1 (not "localhost"): the servers bind IPv4 only, while
# "localhost" can resolve to ::1 (IPv6) first on Windows, adding a slow
# connection-refused fallback on every internal call.

# Core trust services
CA_URL = _u("IM_CA_URL", "http://127.0.0.1:9001")
TSA_URL = _u("IM_TSA_URL", "http://127.0.0.1:9002")
GLOBAL_URL = _u("IM_GLOBAL_URL", "http://127.0.0.1:9000")

# Security gateways: two IDENTICAL instances of the same gateway software,
# on separate clusters (SG1 / SG2). Neither is a fixed consumer/provider.
SG1_URL = _u("IM_SG1_URL", "http://127.0.0.1:8081")   # instance SG1 admin/app port
SG2_URL = _u("IM_SG2_URL", "http://127.0.0.1:8082")   # instance SG2 admin/app port

# Application (provider backend service + consumer client UI)
APP_URL = _u("IM_APP_URL", "http://127.0.0.1:8090")

# Information Mediator instance identifier for this federation
INSTANCE = _u("IM_INSTANCE", "GOVSTACK")

PORTS = {
    "global_server": 9000,
    "ca_server": 9001,
    "tsa_server": 9002,
    "security_gateway_sg1": 8081,
    "security_gateway_sg2": 8082,
    "application": 8090,
}
