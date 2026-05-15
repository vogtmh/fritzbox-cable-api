"""DataUpdateCoordinator for Fritz!Box Cable DOCSIS."""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import timedelta
from xml.etree import ElementTree

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN, SCAN_INTERVAL_SECONDS

_LOGGER = logging.getLogger(__name__)


def _to_float(value: object) -> float | None:
    """Safely convert a value (string or number) to float, None on failure."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


class FritzCableCoordinator(DataUpdateCoordinator[dict]):
    """Fetches DOCSIS channel data from a Fritz!Box Cable router."""

    def __init__(
        self,
        hass: HomeAssistant,
        url: str,
        username: str,
        password: str,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=SCAN_INTERVAL_SECONDS),
        )
        self._url = url.rstrip("/")
        self._username = username
        self._password = password
        self._sid: str | None = None

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _md5_response(self, challenge: str) -> str:
        """Compute the Fritz!Box MD5 challenge-response (UTF-16LE)."""
        combined = (challenge + "-" + self._password).encode("utf-16-le")
        return f"{challenge}-{hashlib.md5(combined).hexdigest()}"

    async def _login(self) -> str:
        """Perform challenge-response login and return a valid SID."""
        session = async_get_clientsession(self.hass)
        login_url = f"{self._url}/login_sid.lua"
        params = {"username": self._username} if self._username else {}

        async with session.get(login_url, params=params) as resp:
            text = await resp.text()

        tree = ElementTree.fromstring(text)
        sid = tree.findtext("SID") or ""

        # Already have a valid session (e.g. running without auth).
        if sid and sid != "0000000000000000":
            return sid

        block_time = int(tree.findtext("BlockTime") or 0)
        if block_time > 0:
            raise UpdateFailed(
                f"Fritz!Box login is blocked for {block_time} seconds "
                "(too many failed attempts)"
            )

        challenge = tree.findtext("Challenge") or ""
        response = self._md5_response(challenge)

        async with session.post(
            login_url, data={"username": self._username, "response": response}
        ) as resp:
            text = await resp.text()

        tree = ElementTree.fromstring(text)
        sid = tree.findtext("SID") or ""

        if not sid or sid == "0000000000000000":
            raise UpdateFailed(
                "Fritz!Box login failed: check your password and username"
            )

        _LOGGER.debug("Fritz!Box login successful")
        return sid

    async def async_test_credentials(self) -> None:
        """Verify credentials by attempting a login. Raises UpdateFailed on failure."""
        await self._login()

    # ------------------------------------------------------------------
    # Data fetching
    # ------------------------------------------------------------------

    async def _fetch_docinfo(self, sid: str) -> dict:
        """POST to data.lua and return parsed JSON, or {} if session expired."""
        session = async_get_clientsession(self.hass)
        payload = {"sid": sid, "page": "docInfo", "xhrId": "all", "xhr": "1"}

        async with session.post(f"{self._url}/data.lua", data=payload) as resp:
            text = await resp.text()

        # Fritz!Box returns HTML (the login page) when the SID is invalid.
        if not text or text.lstrip().startswith("<"):
            return {}

        return json.loads(text)

    async def _async_update_data(self) -> dict:
        try:
            if not self._sid:
                self._sid = await self._login()

            raw = await self._fetch_docinfo(self._sid)

            if not raw:
                # SID expired server-side; re-authenticate once.
                _LOGGER.debug("SID expired, re-authenticating")
                self._sid = await self._login()
                raw = await self._fetch_docinfo(self._sid)

            if not raw:
                raise UpdateFailed(
                    "Fritz!Box returned no data after re-authentication"
                )

            return self._parse(raw)

        except UpdateFailed:
            raise
        except Exception as err:
            raise UpdateFailed(f"Unexpected error fetching data: {err}") from err

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse(self, raw: dict) -> dict:
        inner = raw.get("data", {})
        result: dict = {
            "ready_state": inner.get("readyState", "unknown"),
            "downstream": [],
            "upstream": [],
        }

        ch_ds = inner.get("channelDs", {})
        for standard, channels in (
            ("DOCSIS 3.1", ch_ds.get("docsis31", [])),
            ("DOCSIS 3.0", ch_ds.get("docsis30", [])),
        ):
            for ch in channels:
                result["downstream"].append(
                    {
                        "channel_id": int(ch.get("channelID", 0)),
                        "standard": standard,
                        "modulation": ch.get("modulation", ""),
                        "frequency": ch.get("frequency", ""),
                        "power_dbmv": _to_float(ch.get("powerLevel")),
                        "mer_db": _to_float(ch.get("mer")),
                        "mse_db": _to_float(ch.get("mse")),
                        "corrected_errors": int(ch.get("corrErrors") or 0),
                        "uncorrected_errors": int(ch.get("nonCorrErrors") or 0),
                        "latency_ms": float(ch.get("latency") or 0),
                        "fft": ch.get("fft", ""),
                    }
                )

        ch_us = inner.get("channelUs", {})
        for standard, channels in (
            ("DOCSIS 3.1", ch_us.get("docsis31", [])),
            ("DOCSIS 3.0", ch_us.get("docsis30", [])),
        ):
            for ch in channels:
                result["upstream"].append(
                    {
                        "channel_id": int(ch.get("channelID", 0)),
                        "standard": standard,
                        "modulation": ch.get("modulation", ""),
                        "frequency": ch.get("frequency", ""),
                        "power_dbmv": _to_float(ch.get("powerLevel")),
                    }
                )

        return result
