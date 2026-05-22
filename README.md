# pschmitt.netgear_wax

Ansible collection for managing Netgear WAX access points via their local
HTTPS management API.

## Credits

API discovery and authentication flow based on the excellent work by
**rroller** in the [netgear Home Assistant integration](https://github.com/rroller/netgear).

## Requirements

- Python 3.9+
- Ansible 2.15+
- [pywax](https://github.com/pschmitt/pywax) Python library

```sh
pip install "pywax @ git+https://github.com/pschmitt/pywax"
# or
pip install -r requirements.txt  # from the collection root
```

## Tested devices

- Netgear WAX610 (firmware 12.8.0.7)

## Modules

### `pschmitt.netgear_wax.facts`

Gathers device info and the full SSID table. Pre-shared keys are stripped
from the returned data.

```yaml
- name: Gather WAX facts
  pschmitt.netgear_wax.facts:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
  register: wax
```

### `pschmitt.netgear_wax.ssid`

Reads and enforces SSID configuration. Idempotent, supports check mode.

```yaml
- name: Ensure brkn-lan is configured
  pschmitt.netgear_wax.ssid:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
    ssid_id: SSID1
    enabled: true
    hidden: false
    psk: "{{ wifi_psk }}"
    auth_type: wpa2_wpa3   # wpa2 | wpa_wpa2 | wpa2_wpa3
    encryption: aes        # aes | tkip_aes
    vlan_id: 1
```

Look up by SSID name instead of `ssid_id`:

```yaml
- name: Disable guest network
  pschmitt.netgear_wax.ssid:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
    name: brkn-guest
    enabled: false
```

## Auth type reference

| `auth_type`  | WAX API value | Description                  |
|--------------|---------------|------------------------------|
| `wpa2`       | 32            | WPA2-PSK only                |
| `wpa_wpa2`   | 48            | WPA + WPA2 mixed             |
| `wpa2_wpa3`  | 96            | WPA2-PSK + WPA3-SAE (transition mode) |

## Installation

```yaml
# requirements.yml
collections:
  - name: https://github.com/pschmitt/ansible-collection-netgear-wax.git
    type: git
    version: main
```

## License

GPL-3.0-or-later
