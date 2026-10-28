"""Exchange Online admin API client. STRICTLY READ-ONLY.

Exchange has no Microsoft Graph endpoints for distribution lists, transport rules or message trace, but the Exchange Online
admin API (the one the Exchange PowerShell module uses) accepts the app's own identity when the app holds
`Exchange.ManageAsApp` and an Entra role such as Global Reader. Every call is a cmdlet invocation, so this client refuses
anything that does not start with `Get-`; there is no code path that can change the tenant.

Message trace answers "did this address receive mail": the service keeps about 90 days and only accepts windows of up to
10 days, so a list is checked in 10-day slices from now backwards (89 days at most), stopping at the first slice that has mail.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

import requests

from ._time import parse_graph_dt
from .graph import GraphError, Json, SignalUnavailable

BASE = "https://outlook.office365.com/adminapi/beta"
SCOPE = "https://outlook.office365.com/.default"
TRACE_SLICE_DAYS = 10
TRACE_WINDOW_DAYS = 89           # the service keeps ~90 days; asking for more is a 500
MAILBOX_TYPES = ("SharedMailbox", "RoomMailbox", "EquipmentMailbox")


class ExchangeClient:
    """Read-only client over `requests`: paging, 429/5xx backoff, and a hard `Get-*` guard."""

    MAX_RETRIES = 5
    RETRYABLE = {429, 502, 503, 504}

    def __init__(self, token_provider: Callable[[], str | None], tenant_id: str, session: Any | None = None) -> None:
        self._token_provider = token_provider
        self._tenant = tenant_id
        self._http = session or requests.Session()

    # ------------------------------------------------------------ transport
    def invoke(self, cmdlet: str, **params: Any) -> list[Json]:
        """Run a read-only cmdlet and return every row (all pages). Raises ValueError for anything but `Get-*`."""
        if not cmdlet.startswith("Get-"):
            raise ValueError(f"read-only client: refusing to run {cmdlet!r}")
        url: str | None = f"{BASE}/{self._tenant}/InvokeCommand"
        rows: list[Json] = []
        for _ in range(200):
            if not url:
                break
            body = self._post(url, cmdlet, params)
            rows += body.get("value", [])
            url = body.get("@odata.nextLink")
        return rows

    def _post(self, url: str, cmdlet: str, params: dict[str, Any]) -> Json:
        for attempt in range(self.MAX_RETRIES + 1):
            token = self._token_provider()
            if token is None:
                raise SignalUnavailable(401, url, "no Exchange access token")
            resp = self._http.post(
                url, timeout=300, json={"CmdletInput": {"CmdletName": cmdlet, "Parameters": params}},
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json",
                         "Accept-Encoding": "identity",   # the service sometimes sends a malformed gzip body
                         "Prefer": "odata.maxpagesize=1000",
                         "X-AnchorMailbox": f"APP:SystemMailbox{{bb558c35-97f1-4cb9-8ff7-d53741dc928c}}@{self._tenant}"})
            if resp.status_code in self.RETRYABLE and attempt < self.MAX_RETRIES:
                retry_after = resp.headers.get("Retry-After", "")
                time.sleep(float(retry_after) if retry_after.isdigit() else min(60, 2 ** attempt))
                continue
            if resp.status_code in (401, 403):
                raise SignalUnavailable(resp.status_code, url, resp.text)
            if not resp.ok:
                raise GraphError(resp.status_code, url, resp.text)
            return resp.json() if resp.content else {}  # type: ignore[no-any-return]
        raise GraphError(429, url, "retries exhausted")  # pragma: no cover

    # ---------------------------------------------------------- typed reads
    def distribution_groups(self) -> list[Json]:
        """Distribution lists and mail-enabled security groups."""
        return self.invoke("Get-DistributionGroup", ResultSize="Unlimited")

    def dynamic_distribution_groups(self) -> list[Json]:
        return self.invoke("Get-DynamicDistributionGroup", ResultSize="Unlimited")

    def transport_rules(self) -> list[Json]:
        return self.invoke("Get-TransportRule")

    def mailboxes(self, types: Iterable[str] = MAILBOX_TYPES) -> list[Json]:
        """Shared, room and equipment mailboxes (the plain mailbox list is far too large to read routinely)."""
        return self.invoke("Get-Mailbox", RecipientTypeDetails=list(types), ResultSize="Unlimited")

    def mailbox_statistics(self, identity: str) -> Json | None:
        """Last sign-in (LastLogonTime), item count and size of one mailbox, or None."""
        rows = self.invoke("Get-MailboxStatistics", Identity=identity)
        return rows[0] if rows else None

    def mailbox_permissions(self, identity: str) -> list[Json]:
        """Full Access and other mailbox permissions of one mailbox."""
        return self.invoke("Get-MailboxPermission", Identity=identity)

    def recipient_permissions(self, identity: str) -> list[Json]:
        """Send As permissions on one mailbox."""
        return self.invoke("Get-RecipientPermission", Identity=identity)

    def accepted_domains(self) -> list[str]:
        """The tenant's own mail domains."""
        return [str(d["DomainName"]).lower() for d in self.invoke("Get-AcceptedDomain") if d.get("DomainName")]

    def member_count(self, identity: str, dynamic: bool = False) -> int:
        """Number of members of a list (nested lists count as one member each)."""
        cmdlet = "Get-DynamicDistributionGroupMember" if dynamic else "Get-DistributionGroupMember"
        return len(self.invoke(cmdlet, Identity=identity, ResultSize="Unlimited"))

    def last_mail_received(self, address: str, now: datetime | None = None) -> datetime | None:
        """Newest message addressed to `address` within the last 89 days, or None if there was none.

        Walks 10-day slices from now backwards and stops at the first slice that has mail.
        """
        now = now or datetime.now(timezone.utc)
        fmt = lambda d: d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        for offset in range(0, TRACE_WINDOW_DAYS, TRACE_SLICE_DAYS):
            end = now - timedelta(days=offset)
            start = now - timedelta(days=min(offset + TRACE_SLICE_DAYS, TRACE_WINDOW_DAYS))
            rows = self.invoke("Get-MessageTraceV2", RecipientAddress=address, StartDate=fmt(start), EndDate=fmt(end), ResultSize=100)
            seen = [d for d in (parse_graph_dt(r.get("Received")) for r in rows) if d]
            if rows:
                return max(seen) if seen else end
        return None
