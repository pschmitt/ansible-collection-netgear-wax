#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Philipp Schmitt <philipp@schmitt.co>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: ssid
short_description: Manage SSIDs on a Netgear WAX access point
description:
  - Reads and configures SSID settings on Netgear WAX access points via their
    local HTTPS management API (port 443, endpoint /socketCommunication).
  - Supports check mode and is idempotent.
  - API discovery credit goes to rroller and the netgear Home Assistant
    integration (U(https://github.com/rroller/netgear)).
options:
  host:
    description: Hostname or IP address of the access point.
    required: true
    type: str
  port:
    description: HTTPS port of the management API.
    type: int
    default: 443
  username:
    description: Admin username.
    type: str
    default: admin
  password:
    description: Admin password.
    type: str
    required: true
    no_log: true
  ssid_id:
    description:
      - Internal SSID identifier as used by the WAX API (e.g. C(SSID1)).
      - Exactly one of I(ssid_id) or I(name) must be supplied for lookup.
    type: str
  name:
    description:
      - SSID name to look up. When multiple SSIDs share the same name the
        first match is used; prefer I(ssid_id) for unambiguous targeting.
    type: str
  enabled:
    description: Whether the SSID should be active on all bands.
    type: bool
  hidden:
    description: Whether to hide the SSID from beacon broadcasts.
    type: bool
  psk:
    description: WPA pre-shared key (passphrase).
    type: str
    no_log: true
  auth_type:
    description:
      - Authentication / key-management mode.
      - C(wpa2) uses WPA2-PSK only.
      - C(wpa_wpa2) uses mixed WPA + WPA2.
      - C(wpa2_wpa3) uses WPA2-PSK + WPA3-SAE transition mode.
    type: str
    choices: [wpa2, wpa_wpa2, wpa2_wpa3]
  encryption:
    description:
      - Cipher suite. C(aes) (CCMP only) is recommended for WPA2/WPA3.
        C(tkip_aes) is required for legacy WPA mixed mode.
    type: str
    choices: [aes, tkip_aes]
  vlan_id:
    description: 802.1Q VLAN ID to tag client traffic with.
    type: int
  band_steering:
    description: Enable band steering to prefer 5 GHz for capable clients.
    type: bool
  client_isolation:
    description: Prevent wireless clients from communicating with each other.
    type: bool
  ieee80211w:
    description:
      - Management Frame Protection (802.11w). C(0)=disabled, C(1)=optional,
        C(2)=required. Required for WPA3.
    type: int
    choices: [0, 1, 2]
  fast_roaming:
    description: Enable 802.11r Fast BSS Transition (fast roaming).
    type: bool
notes:
  - The access point uses a self-signed TLS certificate; certificate
    verification is intentionally disabled.
  - Changes to the SSID profile may cause a brief (~25 s) service interruption
    while the AP applies the new configuration.
"""

EXAMPLES = r"""
- name: Ensure brkn-lan SSID is configured
  pschmitt.netgear_wax.ssid:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
    ssid_id: SSID1
    enabled: true
    hidden: false
    psk: "{{ wax_wifi_private.brkn_lan.psk }}"
    auth_type: wpa2_wpa3
    encryption: aes
    vlan_id: 1

- name: Disable guest SSID
  pschmitt.netgear_wax.ssid:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
    name: brkn-guest
    enabled: false
"""

RETURN = r"""
changed:
  description: Whether any change was made.
  returned: always
  type: bool
ssid_id:
  description: The SSID identifier that was targeted.
  returned: always
  type: str
before:
  description: SSID configuration before the module ran (first band only).
  returned: always
  type: dict
after:
  description: SSID configuration after the module ran (first band only).
  returned: always
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pschmitt.netgear_wax.plugins.module_utils.wax_client import (
    AUTH_TYPES,
    AUTH_TYPES_REV,
    ENCRYPTION_TYPES,
    ENCRYPTION_TYPES_REV,
    WaxClient,
    WaxClientError,
)


def _flatten_ssid(ssid_val):
    """Return {wlan_id: {vap_id: cfg}} from the ssidGetDetails entry."""
    bands = {}
    for key, val in ssid_val.items():
        if key.startswith("wlan"):
            bands[key] = val
    return bands


def _settable(cfg):
    """Strip fields the set endpoint rejects (list values are read-only metadata)."""
    return {k: v for k, v in cfg.items() if not isinstance(v, list)}


def _build_desired(current_cfg, params):
    """Merge desired params into a copy of current_cfg, return (merged, changed)."""
    desired = _settable(current_cfg)
    changed = False

    def _set(field, value):
        nonlocal changed
        if desired.get(field) != value:
            desired[field] = value
            changed = True

    if params["enabled"] is not None:
        _set("vapProfileStatus", 1 if params["enabled"] else 0)
    if params["hidden"] is not None:
        _set("hideNetworkName", 1 if params["hidden"] else 0)
    if params["psk"] is not None:
        _set("presharedKey", params["psk"])
    if params["auth_type"] is not None:
        _set("authenticationType", AUTH_TYPES[params["auth_type"]])
    if params["encryption"] is not None:
        _set("encryption", ENCRYPTION_TYPES[params["encryption"]])
    if params["vlan_id"] is not None:
        _set("vlanID", params["vlan_id"])
    if params["band_steering"] is not None:
        _set("bandSteeringStatus", 1 if params["band_steering"] else 0)
    if params["client_isolation"] is not None:
        _set("clientSeparation", 1 if params["client_isolation"] else 0)
    if params["ieee80211w"] is not None:
        _set("ieee80211w", params["ieee80211w"])
    if params["fast_roaming"] is not None:
        _set("11rStatus", 1 if params["fast_roaming"] else 0)

    return desired, changed


def _normalise(cfg):
    """Return a display-safe copy of a VAP config dict."""
    out = dict(cfg)
    out["authenticationType"] = AUTH_TYPES_REV.get(
        out.get("authenticationType"), out.get("authenticationType")
    )
    out["encryption"] = ENCRYPTION_TYPES_REV.get(
        out.get("encryption"), out.get("encryption")
    )
    out.pop("presharedKey", None)
    return out


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type="str", required=True),
            port=dict(type="int", default=443),
            username=dict(type="str", default="admin"),
            password=dict(type="str", required=True, no_log=True),
            ssid_id=dict(type="str"),
            name=dict(type="str"),
            enabled=dict(type="bool"),
            hidden=dict(type="bool"),
            psk=dict(type="str", no_log=True),
            auth_type=dict(type="str", choices=list(AUTH_TYPES)),
            encryption=dict(type="str", choices=list(ENCRYPTION_TYPES)),
            vlan_id=dict(type="int"),
            band_steering=dict(type="bool"),
            client_isolation=dict(type="bool"),
            ieee80211w=dict(type="int", choices=[0, 1, 2]),
            fast_roaming=dict(type="bool"),
        ),
        mutually_exclusive=[["ssid_id", "name"]],
        required_one_of=[["ssid_id", "name"]],
        supports_check_mode=True,
    )

    p = module.params
    client = WaxClient(p["host"], p["port"], p["username"], p["password"])

    try:
        client.login()
    except WaxClientError as exc:
        module.fail_json(msg=str(exc))

    try:
        _main_logged_in(module, client, p)
    finally:
        try:
            client.logout()
        except Exception:
            pass


def _main_logged_in(module, client, p):
    try:
        ssids = client.get_ssids()
    except WaxClientError as exc:
        module.fail_json(msg=str(exc))

    # Resolve ssid_id from name if needed.
    ssid_id = p["ssid_id"]
    if ssid_id is None:
        for sid, val in ssids.items():
            for wlan_val in val.values():
                if not isinstance(wlan_val, dict):
                    continue
                for cfg in wlan_val.values():
                    if isinstance(cfg, dict) and cfg.get("ssid") == p["name"]:
                        ssid_id = sid
                        break
                if ssid_id:
                    break
            if ssid_id:
                break
        if ssid_id is None:
            module.fail_json(msg="No SSID named '{0}' found on device".format(p["name"]))

    if ssid_id not in ssids:
        module.fail_json(msg="SSID '{0}' not found on device".format(ssid_id))

    bands = _flatten_ssid(ssids[ssid_id])
    if not bands:
        module.fail_json(msg="No band data for {0}".format(ssid_id))

    # Use the first VAP of the first band as the canonical current state.
    first_wlan = next(iter(bands))
    first_vap = next(iter(bands[first_wlan]))
    current_cfg = bands[first_wlan][first_vap]

    _, any_change = _build_desired(current_cfg, p)

    before = _normalise(current_cfg)

    if not any_change or module.check_mode:
        module.exit_json(
            changed=any_change,
            ssid_id=ssid_id,
            before=before,
            after=before,
        )

    # Build the full set payload for all bands/VAPs.
    set_payload = {}
    for wlan_id, vaps in bands.items():
        set_payload[wlan_id] = {}
        for vap_id, cfg in vaps.items():
            desired, _ = _build_desired(cfg, p)
            set_payload[wlan_id][vap_id] = desired

    try:
        client.set_ssid(ssid_id, set_payload)
        # Re-read to confirm.
        ssids_after = client.get_ssids()
        after_cfg = (
            ssids_after.get(ssid_id, {})
            .get(first_wlan, {})
            .get(first_vap, {})
        )
    except WaxClientError as exc:
        module.fail_json(msg=str(exc))

    module.exit_json(
        changed=True,
        ssid_id=ssid_id,
        before=before,
        after=_normalise(after_cfg),
    )


if __name__ == "__main__":
    main()
