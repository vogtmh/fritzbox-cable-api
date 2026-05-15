"""Config flow for Fritz!Box Cable DOCSIS."""

from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import CONF_URL, CONF_USERNAME, DOMAIN
from .coordinator import FritzCableCoordinator

STEP_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_URL, default="http://192.168.1.1"): str,
        vol.Optional(CONF_USERNAME, default=""): str,
        vol.Required(CONF_PASSWORD): str,
    }
)


async def _validate(hass: HomeAssistant, data: dict) -> None:
    """Try to log in. Raises vol.Invalid on failure."""
    coordinator = FritzCableCoordinator(
        hass,
        data[CONF_URL],
        data.get(CONF_USERNAME, ""),
        data[CONF_PASSWORD],
    )
    try:
        await coordinator.async_test_credentials()
    except UpdateFailed as err:
        raise vol.Invalid(str(err)) from err


class FritzCableConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle the UI setup flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict | None = None
    ) -> config_entries.FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                await _validate(self.hass, user_input)
            except vol.Invalid:
                errors["base"] = "cannot_connect"
            except Exception:  # noqa: BLE001
                errors["base"] = "unknown"
            else:
                url = user_input[CONF_URL].rstrip("/")
                await self.async_set_unique_id(url)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=f"Fritz!Box Cable ({url})",
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_SCHEMA,
            errors=errors,
        )
