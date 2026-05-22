# -*- coding: utf-8 -*-
# Copyright (c) 2026 Philipp Schmitt <philipp@schmitt.co>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# Local HTTPS API client for Netgear WAX access points.
# API discovery credit: rroller/netgear (https://github.com/rroller/netgear)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import ssl
import time
import urllib.error
import urllib.request

# authenticationType integer values returned/accepted by the WAX API.
AUTH_TYPES = {
    "wpa2":      32,
    "wpa_wpa2":  48,
    "wpa2_wpa3": 96,
}
AUTH_TYPES_REV = {v: k for k, v in AUTH_TYPES.items()}

# encryption integer values.
ENCRYPTION_TYPES = {
    "aes":      4,
    "tkip_aes": 6,
}
ENCRYPTION_TYPES_REV = {v: k for k, v in ENCRYPTION_TYPES.items()}


class WaxClientError(Exception):
    pass


class WaxClient:
    """Minimal synchronous HTTP client for the Netgear WAX local API.

    Auth flow (discovered by rroller/netgear):
      1. GET / → extract lhttpdsid cookie
      2. POST /socketCommunication with credentials → extract security_token
      3. All subsequent calls carry both cookie and security header.
    """

    def __init__(self, host, port, username, password):
        self._base = "https://{0}:{1}".format(host, port)
        self._username = username
        self._password = password
        self._cookie = None
        self._token = None
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def login(self, retries=5, retry_delay=3):
        # The device allows only one concurrent admin session. If another
        # client (e.g. the Home Assistant netgear_wax integration) holds an
        # active session the device returns status 100 and no token. Retry
        # with a short delay to wait for that session to expire.
        req = urllib.request.Request(self._base + "/")
        try:
            with urllib.request.urlopen(req, context=self._ctx) as resp:
                for header in resp.headers.get_all("Set-Cookie") or []:
                    if "lhttpdsid=" in header:
                        self._cookie = header.split("lhttpdsid=")[1].split(";")[0]
        except urllib.error.URLError as exc:
            raise WaxClientError("Cannot reach device: {0}".format(exc))

        if not self._cookie:
            raise WaxClientError("Login step 1 failed: no lhttpdsid cookie")

        payload = json.dumps({
            "system": {
                "basicSettings": {
                    "adminName": self._username,
                    "adminPasswd": self._password,
                }
            }
        }).encode()

        for attempt in range(retries):
            result, headers = self._raw_post("/socketCommunication", payload, auth=False)
            status = result.get("status", -1)

            # 401 = bad credentials or IP lockout — retrying won't help.
            if status == 401:
                raise WaxClientError(
                    "Login rejected (status 401): bad credentials or IP "
                    "temporarily locked out after too many failed attempts."
                )

            # Older firmware returns token in response header; newer in body.
            token = headers.get("security")
            if not token:
                token = (result.get("system") or {}).get("security_token")

            if token:
                self._token = token
                return

            # status 100 = concurrent session limit — wait and retry.
            if attempt < retries - 1:
                time.sleep(retry_delay)

        raise WaxClientError(
            "Login failed after {0} attempts: device may have reached its "
            "concurrent session limit (status 100). Last response: {1}".format(retries, result)
        )

    def logout(self):
        try:
            self._raw_post("/logout", json.dumps({self._username: self._username}).encode())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Low-level HTTP
    # ------------------------------------------------------------------

    def _raw_post(self, path, data, auth=True):
        headers = {"Content-Type": "application/json"}
        if self._cookie:
            headers["Cookie"] = "lhttpdsid={0}".format(self._cookie)
        if auth and self._token:
            headers["security"] = self._token

        req = urllib.request.Request(self._base + path, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, context=self._ctx) as resp:
                body = json.loads(resp.read())
                return body, resp.headers
        except urllib.error.HTTPError as exc:
            raise WaxClientError("HTTP {0} on {1}".format(exc.code, path))
        except urllib.error.URLError as exc:
            raise WaxClientError("Cannot reach device: {0}".format(exc))

    def post(self, payload):
        result, _ = self._raw_post(
            "/socketCommunication",
            json.dumps(payload).encode(),
        )
        status = result.get("status", -1)
        if status != 0:
            raise WaxClientError(
                "API returned status {0}: {1}".format(status, result)
            )
        return result

    # ------------------------------------------------------------------
    # SSID operations
    # ------------------------------------------------------------------

    def get_ssids(self):
        """Return the raw ssidGetDetails dict keyed by SSID1, SSID2, ..."""
        result = self.post({
            "system": {
                "wlanSettings": {
                    "wlanSettingTable": {"ssidGetDetails": ""}
                }
            }
        })
        return result["system"]["wlanSettings"]["wlanSettingTable"]["ssidGetDetails"]

    def set_ssid(self, ssid_id, wlan_configs):
        """Apply ssidSetDetails for one SSID across all its bands.

        wlan_configs: dict  { "wlan0": { "vap0": { field: value, ... } }, ... }
        """
        return self.post({
            "system": {
                "wlanSettings": {
                    "wlanSettingTable": {
                        "ssidSetDetails": {ssid_id: wlan_configs}
                    }
                }
            }
        })

    # ------------------------------------------------------------------
    # Device facts
    # ------------------------------------------------------------------

    def get_facts(self):
        result = self.post({
            "system": {
                "monitor": {
                    "productId": "",
                    "totalNumberOfDevices": "",
                    "sysSerialNumber": "",
                    "ethernetMacAddress": "",
                    "sysVersion": "",
                    "stats": {
                        "lan":   {"traffic": ""},
                        "wlan0": {"traffic": "", "channelUtil": ""},
                        "wlan1": {"traffic": "", "channelUtil": ""},
                    },
                },
                "basicSettings": {"apName": ""},
            }
        })
        mon = result["system"]["monitor"]
        return {
            "ap_name":        result["system"]["basicSettings"]["apName"],
            "model":          mon["productId"],
            "firmware":       mon["sysVersion"],
            "serial":         mon["sysSerialNumber"],
            "mac_address":    mon["ethernetMacAddress"],
            "client_count":   int(mon.get("totalNumberOfDevices", 0)),
        }
