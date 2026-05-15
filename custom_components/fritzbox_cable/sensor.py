"""Sensor platform for Fritz!Box Cable DOCSIS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import FritzCableCoordinator


@dataclass(frozen=True, kw_only=True)
class FritzCableSensorDescription(SensorEntityDescription):
    """Describes a single DOCSIS channel sensor."""

    direction: str  # "downstream" or "upstream"
    channel_id: int
    data_key: str  # key inside the channel dict


def _build_descriptions(data: dict) -> list[FritzCableSensorDescription]:
    """Dynamically create sensor descriptions from coordinator data."""
    descriptions: list[FritzCableSensorDescription] = []

    for ch in data.get("downstream", []):
        ch_id: int = ch["channel_id"]
        std: str = ch["standard"]
        prefix = f"DS Ch{ch_id}"
        key_prefix = f"downstream_ch{ch_id}"

        descriptions.append(
            FritzCableSensorDescription(
                key=f"{key_prefix}_power",
                name=f"{prefix} Power",
                translation_key=None,
                direction="downstream",
                channel_id=ch_id,
                data_key="power_dbmv",
                native_unit_of_measurement="dBmV",
                state_class=SensorStateClass.MEASUREMENT,
                icon="mdi:signal",
                entity_registry_enabled_default=True,
            )
        )

        # DOCSIS 3.1 downstream: MER (Modulation Error Ratio)
        if ch.get("mer_db") is not None:
            descriptions.append(
                FritzCableSensorDescription(
                    key=f"{key_prefix}_mer",
                    name=f"{prefix} MER",
                    translation_key=None,
                    direction="downstream",
                    channel_id=ch_id,
                    data_key="mer_db",
                    native_unit_of_measurement="dB",
                    state_class=SensorStateClass.MEASUREMENT,
                    icon="mdi:sine-wave",
                )
            )

        # DOCSIS 3.0 downstream: MSE (Mean Squared Error)
        if ch.get("mse_db") is not None:
            descriptions.append(
                FritzCableSensorDescription(
                    key=f"{key_prefix}_mse",
                    name=f"{prefix} MSE",
                    translation_key=None,
                    direction="downstream",
                    channel_id=ch_id,
                    data_key="mse_db",
                    native_unit_of_measurement="dB",
                    state_class=SensorStateClass.MEASUREMENT,
                    icon="mdi:sine-wave",
                )
            )

        descriptions.append(
            FritzCableSensorDescription(
                key=f"{key_prefix}_corr_errors",
                name=f"{prefix} Corrected Errors",
                translation_key=None,
                direction="downstream",
                channel_id=ch_id,
                data_key="corrected_errors",
                native_unit_of_measurement="errors",
                state_class=SensorStateClass.TOTAL_INCREASING,
                icon="mdi:alert-circle-outline",
                entity_registry_enabled_default=False,
            )
        )

        descriptions.append(
            FritzCableSensorDescription(
                key=f"{key_prefix}_uncorr_errors",
                name=f"{prefix} Uncorrected Errors",
                translation_key=None,
                direction="downstream",
                channel_id=ch_id,
                data_key="uncorrected_errors",
                native_unit_of_measurement="errors",
                state_class=SensorStateClass.TOTAL_INCREASING,
                icon="mdi:alert-circle",
                entity_registry_enabled_default=True,
            )
        )

    for ch in data.get("upstream", []):
        ch_id = ch["channel_id"]
        prefix = f"US Ch{ch_id}"
        key_prefix = f"upstream_ch{ch_id}"

        descriptions.append(
            FritzCableSensorDescription(
                key=f"{key_prefix}_power",
                name=f"{prefix} Power",
                translation_key=None,
                direction="upstream",
                channel_id=ch_id,
                data_key="power_dbmv",
                native_unit_of_measurement="dBmV",
                state_class=SensorStateClass.MEASUREMENT,
                icon="mdi:signal",
            )
        )

    return descriptions


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up sensors from a config entry."""
    coordinator: FritzCableCoordinator = hass.data[DOMAIN][entry.entry_id]

    device_info = DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name="Fritz!Box Cable",
        manufacturer="AVM",
        model="Fritz!Box Cable",
    )

    descriptions = _build_descriptions(coordinator.data)
    async_add_entities(
        FritzCableChannelSensor(coordinator, entry, desc, device_info)
        for desc in descriptions
    )


class FritzCableChannelSensor(CoordinatorEntity[FritzCableCoordinator], SensorEntity):
    """A single DOCSIS channel sensor."""

    entity_description: FritzCableSensorDescription

    def __init__(
        self,
        coordinator: FritzCableCoordinator,
        entry: ConfigEntry,
        description: FritzCableSensorDescription,
        device_info: DeviceInfo,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.entry_id}_{description.key}"
        self._attr_device_info = device_info
        self._attr_has_entity_name = True

    @property
    def available(self) -> bool:
        if not super().available or not self.coordinator.data:
            return False
        direction = self.entity_description.direction
        ch_id = self.entity_description.channel_id
        return any(
            ch["channel_id"] == ch_id
            for ch in self.coordinator.data.get(direction, [])
        )

    @property
    def native_value(self) -> Any:
        direction = self.entity_description.direction
        ch_id = self.entity_description.channel_id
        data_key = self.entity_description.data_key

        for ch in self.coordinator.data.get(direction, []):
            if ch["channel_id"] == ch_id:
                return ch.get(data_key)
        return None
