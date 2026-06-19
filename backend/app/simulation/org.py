"""The simulated organization being protected (demo identities, assets, geo)."""
from __future__ import annotations

# Geo points: country code -> (city, lat, lon). Used for impossible-travel math.
GEO: dict[str, tuple[str, float, float]] = {
    "IR": ("Tehran", 35.6892, 51.3890),
    "RU": ("Moscow", 55.7558, 37.6173),
    "US": ("New York", 40.7128, -74.0060),
    "DE": ("Frankfurt", 50.1109, 8.6821),
    "CN": ("Beijing", 39.9042, 116.4074),
    "NG": ("Lagos", 6.5244, 3.3792),
    "TR": ("Istanbul", 41.0082, 28.9784),
    "AE": ("Dubai", 25.2048, 55.2708),
    "GB": ("London", 51.5074, -0.1278),
}

# department, title, home_country, privileged
DEMO_USERS: list[dict] = [
    {"username": "a.rahimi", "display_name": "Arman Rahimi", "department": "Finance",
     "title": "Finance Manager", "home_country": "IR", "is_privileged": True},
    {"username": "s.karimi", "display_name": "Sara Karimi", "department": "HR",
     "title": "HR Specialist", "home_country": "IR", "is_privileged": False},
    {"username": "m.tehrani", "display_name": "Mehdi Tehrani", "department": "IT",
     "title": "Systems Administrator", "home_country": "IR", "is_privileged": True},
    {"username": "n.ahmadi", "display_name": "Nazanin Ahmadi", "department": "Sales",
     "title": "Account Executive", "home_country": "IR", "is_privileged": False},
    {"username": "r.mohammadi", "display_name": "Reza Mohammadi", "department": "Engineering",
     "title": "Backend Engineer", "home_country": "IR", "is_privileged": False},
    {"username": "f.hosseini", "display_name": "Fatemeh Hosseini", "department": "Legal",
     "title": "Legal Counsel", "home_country": "IR", "is_privileged": False},
    {"username": "k.jafari", "display_name": "Kamran Jafari", "department": "Executive",
     "title": "CEO", "home_country": "IR", "is_privileged": True},
    {"username": "svc-backup", "display_name": "Backup Service Account", "department": "IT",
     "title": "Service Account", "home_country": "IR", "is_privileged": True},
]

# name, type, sensitivity (1..5), owner_department
DEMO_ASSETS: list[dict] = [
    {"name": "finance-fileserver", "asset_type": "server", "sensitivity": 5, "owner_department": "Finance"},
    {"name": "hr-portal", "asset_type": "saas", "sensitivity": 4, "owner_department": "HR"},
    {"name": "exchange-online", "asset_type": "saas", "sensitivity": 4, "owner_department": "IT"},
    {"name": "sharepoint-legal", "asset_type": "data_store", "sensitivity": 5, "owner_department": "Legal"},
    {"name": "ws-rahimi", "asset_type": "endpoint", "sensitivity": 3, "owner_department": "Finance"},
    {"name": "ws-tehrani", "asset_type": "endpoint", "sensitivity": 3, "owner_department": "IT"},
    {"name": "aws-prod-vpc", "asset_type": "server", "sensitivity": 5, "owner_department": "Engineering"},
    {"name": "crm-salesforce", "asset_type": "saas", "sensitivity": 3, "owner_department": "Sales"},
]


def user_home(username: str) -> str:
    for u in DEMO_USERS:
        if u["username"] == username:
            return u["home_country"]
    return "IR"


_PRIVILEGED = {u["username"] for u in DEMO_USERS if u["is_privileged"]}


def is_privileged(username: str | None) -> bool:
    return username in _PRIVILEGED
