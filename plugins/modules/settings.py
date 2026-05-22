#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2026 Philipp Schmitt <philipp@schmitt.co>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
module: settings
short_description: Manage basic settings on a Netgear WAX access point
description:
  - Enforces basic device settings (AP name, etc.) on Netgear WAX access
    points via their local HTTPS management API.
  - Idempotent and supports check mode.
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
  ap_name:
    description: Desired AP name (hostname shown in the management UI).
    type: str
notes:
  - The access point uses a self-signed TLS certificate; certificate
    verification is intentionally disabled.
"""

EXAMPLES = r"""
- name: Enforce AP name
  pschmitt.netgear_wax.settings:
    host: 10.5.0.3
    password: "{{ wax_admin_password }}"
    ap_name: brkn-ap
  delegate_to: localhost
"""

RETURN = r"""
changed:
  description: Whether any setting was changed.
  returned: always
  type: bool
before:
  description: Settings before the module ran.
  returned: always
  type: dict
after:
  description: Settings after the module ran.
  returned: always
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.pschmitt.netgear_wax.plugins.module_utils.wax_client import (
    WaxClient,
    WaxClientError,
)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type="str", required=True),
            port=dict(type="int", default=443),
            username=dict(type="str", default="admin"),
            password=dict(type="str", required=True, no_log=True),
            ap_name=dict(type="str"),
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
        _main_logged_in(module, client, p)
    finally:
        try:
            client.logout()
        except Exception:
            pass


def _main_logged_in(module, client, p):
    before = {}
    after = {}
    changed = False

    if p["ap_name"] is not None:
        try:
            current = client.get_ap_name()
        except WaxClientError as exc:
            module.fail_json(msg=str(exc))
        before["ap_name"] = current
        desired = p["ap_name"]
        if current != desired:
            changed = True
            after["ap_name"] = desired
            if not module.check_mode:
                try:
                    client.set_ap_name(desired)
                except WaxClientError as exc:
                    module.fail_json(msg=str(exc))
        else:
            after["ap_name"] = current

    module.exit_json(changed=changed, before=before, after=after)


if __name__ == "__main__":
    main()
