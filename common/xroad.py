"""Information Mediator identifiers and REST message envelope helpers.

Application id :  <instance>/<entityClass>/<entityCode>/<application>
Service id     :  <instance>/<entityClass>/<entityCode>/<application>/<serviceCode>

An *entity* is a registered organisation, an *application* is one of its
information systems hosted on a *security gateway*, and a *service* is a
REST operation published by a provider application.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ApplicationId:
    instance: str
    entity_class: str
    entity_code: str
    application: Optional[str] = None

    def __str__(self) -> str:
        base = f"{self.instance}/{self.entity_class}/{self.entity_code}"
        return f"{base}/{self.application}" if self.application else base

    @staticmethod
    def parse(value: str) -> "ApplicationId":
        parts = value.strip("/").split("/")
        if len(parts) < 3:
            raise ValueError(f"Invalid application id: {value!r}")
        return ApplicationId(parts[0], parts[1], parts[2],
                             parts[3] if len(parts) > 3 else None)


@dataclass(frozen=True)
class ServiceId:
    instance: str
    entity_class: str
    entity_code: str
    application: str
    service_code: str

    def __str__(self) -> str:
        return (f"{self.instance}/{self.entity_class}/{self.entity_code}/"
                f"{self.application}/{self.service_code}")

    @property
    def provider(self) -> ApplicationId:
        return ApplicationId(self.instance, self.entity_class, self.entity_code,
                             self.application)

    @staticmethod
    def parse(value: str) -> "ServiceId":
        parts = value.strip("/").split("/")
        if len(parts) != 5:
            raise ValueError(f"Invalid service id: {value!r}")
        return ServiceId(*parts)


# Header names of the Information Mediator REST message protocol
H_CONSUMER = "IM-Consumer"        # consumer application id
H_SERVICE = "IM-Service"          # target service id
H_ID = "IM-Message-Id"            # unique message id
H_USER = "IM-User-Id"             # optional end-user id
H_ISSUE = "IM-Issue"              # optional business issue/case id
H_SIGNATURE = "IM-Signature"      # base64 RSA-SHA256 signature of the canonical message
H_SIGN_CERT = "IM-Sign-Cert"      # signing cert of the consumer application
H_AUTH_CERT = "IM-Auth-Cert"      # security gateway auth cert (transport identity)


def canonical_message(message_id: str, consumer: str, service: str, body: bytes) -> bytes:
    """Bytes that get signed/timestamped/logged for non-repudiation."""
    head = f"{message_id}\n{consumer}\n{service}\n".encode()
    return head + body
