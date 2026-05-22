#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Philipp Schmitt <philipp@schmitt.co>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: facts
short_description: Gather facts from a Netgear WAX access point
description:
  - Connects to the local HTTPS management API and returns device facts and
    the current SSID table.
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
notes:
  - The access point uses a self-signed TLS certificate; certificate
    verification is intentionally disabled.
"""

EXAMPLES = r"""
- name: Gather WAX facts
  pschmitt.netgear_wax.facts:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
  register: wax_facts

- name: Show SSID table
  ansible.builtin.debug:
    var: wax_facts.ssids
"""

RETURN = r"""
device:
  description: Device-level information.
  returned: always
  type: dict
  contains:
    ap_name:      { description: Configured AP name, type: str }
    model:        { description: Model string, type: str }
    firmware:     { description: Firmware version, type: str }
    serial:       { description: Serial number, type: str }
    mac_address:  { description: Ethernet MAC address, type: str }
    client_count: { description: Total connected clients, type: int }
ssids:
  description: >
    Current SSID table keyed by SSID identifier (SSID1, SSID2, …).
    Each entry contains per-band VAP configurations. Pre-shared keys are
    omitted from the returned data.
  returned: always
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pschmitt.netgear_wax.plugins.module_utils.wax_client import (
    AUTH_TYPES_REV,
    ENCRYPTION_TYPES_REV,
    WaxClient,
    WaxClientError,
)


def _sanitise_ssids(raw):
    """Strip PSKs and decode integer enums for human-readable output."""
    out = {}
    for ssid_id, ssid_val in raw.items():
        out[ssid_id] = {}
        for key, val in ssid_val.items():
            if not key.startswith("wlan"):
                out[ssid_id][key] = val
                continue
            out[ssid_id][key] = {}
            for vap_id, cfg in val.items():
                clean = dict(cfg)
                clean.pop("presharedKey", None)
                clean["authenticationType"] = AUTH_TYPES_REV.get(
                    clean.get("authenticationType"), clean.get("authenticationType")
                )
                clean["encryption"] = ENCRYPTION_TYPES_REV.get(
                    clean.get("encryption"), clean.get("encryption")
                )
                out[ssid_id][key][vap_id] = clean
    return out


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type="str", required=True),
            port=dict(type="int", default=443),
            username=dict(type="str", default="admin"),
            password=dict(type="str", required=True, no_log=True),
        ),
        supports_check_mode=True,
    )

    p = module.params
    client = WaxClient(p["host"], p["port"], p["username"], p["password"])

    try:
        client.login()
    except WaxClientError as exc:
        module.fail_json(msg=str(exc))

    try:
        device = client.get_facts()
        ssids_raw = client.get_ssids()
    except WaxClientError as exc:
        module.fail_json(msg=str(exc))
    finally:
        try:
            client.logout()
        except Exception:
            pass

    module.exit_json(
        changed=False,
        device=device,
        ssids=_sanitise_ssids(ssids_raw),
    )


if __name__ == "__main__":
    main()
