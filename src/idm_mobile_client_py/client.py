"""
Reverse-engineered version of IDM Mobile app
"""

# pylint: disable=missing-function-docstring, missing-class-docstring

import datetime
import hashlib

import requests

BASE_URL = "https://api.idm.net.lb/IDM_WCF_WebAPI_VB16_SEC/Services/MobileApp.svc/rest/"

APP_VERSION_JSON = {
    "AppVersion": "100000009",
    "DeviceId": "1",
}

SOURCE_NAME_ID = "22D055F2-59E7-480C-93AC-B65FD812664F"
IDM_HASH_PREPEND = "M0b@pWeb!~20@!dM"


def hash_idm(str_to_append):
    string = f"{IDM_HASH_PREPEND}{SOURCE_NAME_ID}{str_to_append}"
    return hashlib.sha256(string.encode("utf-8")).hexdigest()


def hash_idm_userpass(user, passw):
    return hash_idm(f"{user.lower()}{passw.lower()}")


def convert_datetime_to_aspnet_json(date):
    return f"/Date({int((date - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)}+0000)/"


class Client: # pylint: disable=too-many-public-methods
    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": "okhttp/3.12.1",
                "Token": "",  # seems a bug in their code...
            }
        )
        self._profile_id = None
        self._token = None

    def set_credentials(self, profile_id, token):
        self._profile_id = profile_id
        self._token = token

    def _fail_on_no_credentials(func):  # pylint: disable=no-self-argument
        def wrapper(self, *args, **kwargs):
            if self._profile_id is None or self._token is None: # pylint: disable=protected-access
                raise Exception("No credentials set")
            return func(self, *args, **kwargs)  # pylint: disable=not-callable

        return wrapper

    def _do_request(
        self,
        url_to_append,
        *,
        request_json=None,
        method=None,
        headers=None,
    ):
        if method is None:
            method = self._session.post

        if headers is None:
            headers = {}

        url = BASE_URL + url_to_append
        request_json = request_json or {}

        with method(
            url,
            json=request_json,
            headers=headers,
        ) as response:
            return response

    @_fail_on_no_credentials
    def _request_profileid_template(self, nosig=False, include_app_json=False):
        request_json = {
            "SourceNameId": SOURCE_NAME_ID,
            "ProfileId": int(self._profile_id),
        }
        if not nosig:
            request_json["Signature"] = hash_idm(self._token + str(self._profile_id))
        if include_app_json:
            request_json.update(APP_VERSION_JSON)
        return request_json

    @_fail_on_no_credentials
    def _request_account_template(self, account_id, nosig=False):
        request_json = {
            "AccountId": int(account_id),
        }
        request_json.update(
            self._request_profileid_template(nosig=nosig, include_app_json=True)
        )
        return request_json

    def banners_get(self):
        request_json = {
            "Signature": hash_idm("BannersGET"),
            "SourceNameId": SOURCE_NAME_ID,
        }
        return self._do_request("BannersGET", request_json=request_json)

    def settings_get(self):
        request_json = {
            "Signature": hash_idm("SettingsGET"),
            "SourceNameId": SOURCE_NAME_ID,
        }
        return self._do_request("SettingsGET", request_json=request_json)

    def news_get(self):
        request_json = {
            "Signature": hash_idm("NewsGET"),
            "SourceNameId": SOURCE_NAME_ID,
        }
        return self._do_request("NewsGET", request_json=request_json)

    def products_get(self):
        request_json = {
            "Signature": hash_idm("ProductsGET"),
            "SourceNameId": SOURCE_NAME_ID,
        }
        return self._do_request("ProductsGET", request_json=request_json)

    def profile_login(self, user, passw, auto_set=True):
        request_json = {
            "Signature": hash_idm_userpass(user, passw),
            "SourceNameId": SOURCE_NAME_ID,
            "UserName": user,
            "Password": passw,
        }
        request_json.update(APP_VERSION_JSON)
        response = self._do_request("ProfileLogin", request_json=request_json)
        if auto_set:
            try:
                self.set_credentials(
                    response.json()["ProfileId"], response.json()["Token"]
                )
            except Exception:  # pylint: disable=broad-except
                pass
        return response

    def profile_get_accounts(self):
        request_json = self._request_profileid_template(
            nosig=True, include_app_json=True
        )
        request_json.update(
            {
                "Signature": hash_idm(self._token + str(self._profile_id)),
            }
        )
        return self._do_request("ProfileGETAccounts", request_json=request_json)

    def account_get_info(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETInfo", request_json=request_json)

    def account_get_consumption(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETConsumption", request_json=request_json)

    def account_get_consumption_bulk(self, account_ids):
        request_json = self._request_profileid_template(include_app_json=True)
        request_json.update(
            {
                "AccountIdList": account_ids,
            }
        )
        return self._do_request("AccountGETConsumptionBulk", request_json=request_json)

    def account_view_consumption_details(self, account_id, date=None):
        request_json = self._request_account_template(account_id)
        if date is not None:
            request_json.update(
                {
                    "Month": int(date.month),
                    "Startdate": convert_datetime_to_aspnet_json(date),
                    "Year": int(date.year),
                }
            )
        return self._do_request(
            "AccountViewConsumptionDetails", request_json=request_json
        )

    def account_view_details_per_day_per_hour(self, account_id, date):
        request_json = self._request_account_template(account_id)
        request_json.update(
            {
                "DayDate": date.strftime("%m/%d/%Y %H:%M:%S"),
            }
        )
        return self._do_request(
            "AccountViewDetailsPerDayPerHour", request_json=request_json
        )

    def account_set_economy_mode(self, account_id, economy_mode):
        request_json = self._request_account_template(account_id, nosig=True)
        request_json.update(
            {
                "Signature": hash_idm(
                    str(self._token) + str(self._profile_id) + str(economy_mode)
                ),
                "ModeValue": int(economy_mode),  # 0 = off, 1 = auto, 2 = always on
            }
        )
        return self._do_request("AccountSETEconomyMode", request_json=request_json)

    def account_get_change_quota_plans(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETChangeQuotaPlans", request_json=request_json)

    def account_get_services_info(
        self,
        account_id,
    ):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETServicesInfo", request_json=request_json)

    def account_edit_info(self, account_id, new_account_name):
        request_json = self._request_account_template(account_id)
        request_json.update(
            {
                "AccountName": new_account_name,
            }
        )
        return self._do_request("AccountEditInfo", request_json=request_json)

    def account_is_valid_tr69(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountIsValidTR69", request_json=request_json)

    def account_get_change_next_plan(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETChangeNextPlan", request_json=request_json)

    def account_get_referrals(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETReferrals", request_json=request_json)

    def account_get_refill_plans(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETRefillPlans", request_json=request_json)

    def account_get_traffic_policy_requests(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request(
            "AccountGETTrafficPolicyRequests", request_json=request_json
        )

    def account_get_service_serial(self, account_id):
        request_json = self._request_account_template(account_id)
        return self._do_request("AccountGETServiceSerial", request_json=request_json)
