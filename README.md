# Fritz!Box Cable DOCSIS — Home Assistant Integration

Monitor DOCSIS cable channel statistics directly from your AVM Fritz!Box Cable router. The integration connects to the Fritz!Box locally and creates one sensor per channel and data point, updated every 60 seconds.

**Supported data:**
- Downstream & upstream channels (DOCSIS 3.0 and 3.1)
- Signal power level (dBmV)
- MER — Modulation Error Ratio (DOCSIS 3.1 downstream, dB)
- MSE — Mean Squared Error (DOCSIS 3.0 downstream, dB)
- Corrected and uncorrected codeword errors
- Channel standard, modulation, and frequency as entity attributes

---

## Requirements

- AVM Fritz!Box Cable router (tested on Fritz!Box 6660 Cable)
- Fritz!OS with a configured user account (Settings → System → Fritz!Box Users)
- Home Assistant 2024.1 or later
- HACS

---

## Installation via HACS

1. Open HACS in Home Assistant
2. Go to **Integrations** → click the three-dot menu → **Custom repositories**
3. Add the repository URL: `https://github.com/yourusername/fritzbox-cable-api`
   Category: **Integration**
4. Click **Add**, then find **Fritz!Box Cable DOCSIS** in the HACS integration list and install it
5. Restart Home Assistant

---

## Setup

1. Go to **Settings → Devices & Services → Add Integration**
2. Search for **Fritz!Box Cable DOCSIS**
3. Fill in:
   - **Fritz!Box URL** — e.g. `http://192.168.1.1` (check your router's address)
   - **Username** — the Fritz!Box user account name (leave empty if you have not configured user accounts and use a single shared password)
   - **Password** — the password for that user or the shared Fritz!Box password
4. Click **Submit** — the integration will verify the credentials immediately

After a successful setup, all DOCSIS channel sensors will appear under a single **Fritz!Box Cable** device.

---

## Tips

- **Which user to use?** Create a dedicated user in Fritz!OS with access to "Fritz!Box Settings" to limit permissions. A read-only approach is not available in Fritz!OS, but the integration only ever reads data.
- **Entity naming:** Sensors are named `DS Ch33 Power`, `DS Ch15 MSE`, `US Ch5 Power`, etc. The channel ID is assigned by your ISP's CMTS and is stable as long as your ISP does not reconfigure their infrastructure.
- **Attributes:** Each sensor exposes `standard`, `modulation`, and `frequency` as extra state attributes, so you can always see whether a channel is DOCSIS 3.0 or 3.1.
- **Error sensors:** Corrected error sensors are disabled by default to reduce clutter. Enable them individually in the entity settings if needed.

---

## Optional: Go Web Server

The `server/` directory contains a standalone Go web server that provides the same DOCSIS data as a JSON API with a built-in web dashboard. It is **not required** for the Home Assistant integration — the integration talks directly to the Fritz!Box.

The Go server is useful if you want:
- A quick visual overview in a browser at `http://localhost:8080`
- A raw JSON API at `http://localhost:8080/api/status` for other tools
- Auto-generated Home Assistant `configuration.yaml` snippets at `http://localhost:8080/api/ha-config`

### Running the Go server

```bash
cd server
cp config.json.example config.json   # then edit with your credentials
go run .
```

Open `http://localhost:8080` in your browser.

**`server/config.json` fields:**

```json
{
  "fritzbox_url": "http://192.168.1.1",
  "username": "your-username",
  "password": "your-password",
  "server_port": 8080
}
```

---

## License

See [LICENSE](LICENSE).
