"""
Reverse-engineered version of IDM Mobile app
"""

import datetime
import hashlib

import requests

BASE_URL = "https://api.idm.net.lb/IDM_WCF_WebAPI_VB16_SEC/Services/MobileApp.svc/rest/"

APP_VERSION_JSON = {
    "AppVersion": "100000009",
    "DeviceId": "1",
}


def source_name_id():
    string = "22xD05x5F2-".replace("x", "")
    string += "59xE7-".replace("x", "")
    string += "480xC-".replace("x", "")
    string += "93xAC-".replace("x", "")
    string += "B65xFD81x26x64F".replace("x", "")
    return string


def hash_idm(str_to_append):
    first = [77, 48, 98, 64, 112, 87, 101, 98, 33]
    second = [50, 48, 64, 33, 100, 77]

    string = ""

    for i in range(0, 9):
        string += chr(first[i])

    string += "~"

    for i in range(0, 6):
        string += chr(second[i])

    string += source_name_id()
    string += str_to_append

    return hashlib.sha256(string.encode("utf-8")).hexdigest()


def hash_idm_userpass(user, passw):
    return hash_idm(f"{user.lower()}{passw.lower()}")


def convert_datetime_to_aspnet_json(dt):
    return "/Date({}+0000)/".format(
        int((dt - datetime.datetime(1970, 1, 1)).total_seconds() * 1000)
    )


class Client:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": "okhttp/3.12.1",
                "Token": "",  # seems a bug in their code...
            }
        )
        self.profile_id = None
        self.token = None

    def set_credentials(self, profile_id, token):
        self.profile_id = profile_id
        self.token = token

    def fail_on_no_credentials(func):
        def wrapper(self, *args, **kwargs):
            if self.profile_id is None or self.token is None:
                raise Exception("No credentials set")
            return func(self, *args, **kwargs)

        return wrapper

    def banners_get(self):
        url = BASE_URL + "BannersGET"
        request_json = {
            "Signature": hash_idm("BannersGET"),
            "SourceNameId": source_name_id(),
        }
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    def settings_get(self):
        url = BASE_URL + "SettingsGET"
        request_json = {
            "Signature": hash_idm("SettingsGET"),
            "SourceNameId": source_name_id(),
        }
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    def profile_login(self, user, passw, auto_set=True):
        url = BASE_URL + "ProfileLogin"
        request_json = {
            "Signature": hash_idm_userpass(user, passw),
            "SourceNameId": source_name_id(),
            "UserName": user,
            "Password": passw,
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            if auto_set:
                self.set_credentials(
                    response.json()["ProfileId"], response.json()["Token"]
                )
            return response.json()

    @fail_on_no_credentials
    def profile_get_accounts(self):
        url = BASE_URL + "ProfileGETAccounts"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_get_info(self, account_id):
        url = BASE_URL + "AccountGETInfo"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_get_consumption(self, account_id):
        url = BASE_URL + "AccountGETConsumption"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_get_consumption_bulk(
        self, account_ids
    ):
        url = BASE_URL + "AccountGETConsumptionBulk"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountIdList": account_ids,
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_view_consumption_details(
        self, account_id, date=None
    ):
        """
        Returns a list of consumption details for a given account
        with the option of specifying a date to get consumption details for.

        Args:
            account_id (int): Account ID
            date (dict):
                {
                    "year": int,
                    "month": int,
                    "startdate": str,
                }

                year is the year of the date
                month is the month of the date
                startdate is in the DataContractJsonSerializer format

        Returns: dict: API response
        """
        url = BASE_URL + "AccountViewConsumptionDetails"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        if date is not None:
            request_json.update(
                {
                    "Month": int(date["month"]),
                    "Startdate": date["startdate"],
                    "Year": int(date["year"]),
                }
            )
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_view_details_per_day_per_hour(
        self, account_id, date
    ):
        url = BASE_URL + "AccountViewDetailsPerDayPerHour"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
            "DayDate": date.strftime("%m/%d/%Y %H:%M:%S"),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_set_economy_mode(
        self, account_id, economy_mode
    ):
        url = BASE_URL + "AccountSETEconomyMode"
        request_json = {
            "Signature": hash_idm(str(self.token) + str(self.profile_id) + str(economy_mode)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "ModeValue": int(economy_mode),  # 0 = off, 1 = auto, 2 = always on
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_get_change_quota_plans(
        self, account_id
    ):
        url = BASE_URL + "AccountGETChangeQuotaPlans"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_get_services_info(
        self, account_id,
    ):
        url = BASE_URL + "AccountGETServicesInfo"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_edit_info(
        self, account_id, new_account_name
    ):
        url = BASE_URL + "AccountEditInfo"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
            "AccountName": new_account_name,
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_is_valid_tr69(self, account_id):
        url = BASE_URL + "AccountIsValidTR69"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()

    @fail_on_no_credentials
    def account_get_change_next_plan(
        self, account_id
    ):
        url = BASE_URL + "AccountGETChangeNextPlan"
        request_json = {
            "Signature": hash_idm(self.token + str(self.profile_id)),
            "SourceNameId": source_name_id(),
            "ProfileId": int(self.profile_id),
            "AccountId": int(account_id),
        }
        request_json.update(APP_VERSION_JSON)
        with self.session.post(
            url,
            json=request_json,
        ) as response:
            return response.json()
