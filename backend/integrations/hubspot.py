# slack.py

from fastapi import Request
from redis_client import add_key_value_redis
from redis_client import get_value_redis, delete_key_redis
import secrets
import base64
import httpx
from fastapi.responses import HTMLResponse
from fastapi import HTTPException
import json
from integrations.integration_item import IntegrationItem

CLIENT_ID = "8cff2715-ed3d-4205-aa9d-60c3498cc174"
CLIENT_SECRET = "f1403c98-50a8-4271-b424-8059540e0343"
AUTH_URL = "https://app.hubspot.com/oauth/authorize"
REDIRECT_URI = "http://localhost:8000/integrations/hubspot/oauth2callback"
SCOPES = "crm.objects.contacts.read crm.schemas.contacts.read oauth"

AUTH_URL = "https://app.hubspot.com/oauth/authorize"
TOKEN_URL = "https://api.hubapi.com/oauth/v1/token"
API_BASE = "https://api.hubapi.com"

async def authorize_hubspot(user_id, org_id):
    state_data = {
        "state": secrets.token_urlsafe(32),
        "user_id": user_id,
        "org_id": org_id,
    }
    encoded_state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    await add_key_value_redis(f"hubspot_state:{org_id}:{user_id}", json.dumps(state_data), expire=600)

    url = (
        f"{AUTH_URL}"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope={SCOPES}"
        f"&state={encoded_state}"
        f"&response_type=code"
    )
    return url


async def oauth2callback_hubspot(request: Request):
    if request.query_params.get("error"):
        raise HTTPException(status_code=400, detail=request.query_params.get("error_description"))

    code = request.query_params.get("code")
    encoded_state = request.query_params.get("state")

    state_data = json.loads(base64.urlsafe_b64decode(encoded_state.encode()).decode())
    user_id = state_data.get("user_id")
    org_id = state_data.get("org_id")
    original_state = state_data.get("state")

    saved_state = await get_value_redis(f"hubspot_state:{org_id}:{user_id}")
    if not saved_state or original_state != json.loads(saved_state).get("state"):
        raise HTTPException(status_code=400, detail="State mismatch.")

    await delete_key_redis(f"hubspot_state:{org_id}:{user_id}")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "redirect_uri": REDIRECT_URI,
                "code": code,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to exchange code.")

    await add_key_value_redis(f"hubspot_credentials:{org_id}:{user_id}", response.text, expire=600)

    return HTMLResponse("<html><script>window.close();</script></html>")

async def get_hubspot_credentials(user_id, org_id):
    credentials = await get_value_redis(f"hubspot_credentials:{org_id}:{user_id}")
    if not credentials:
        raise HTTPException(status_code=400, detail="No credentials found.")
    await delete_key_redis(f"hubspot_credentials:{org_id}:{user_id}")
    return json.loads(credentials)

async def create_integration_item_metadata_object(response_json):
    return IntegrationItem(
        id=response_json.get("id"),
        name=response_json.get("properties", {}).get("firstname", "Unknown"),
        type="Contact",
        parent_id=None,
        parent_path_or_name=None,
    )

async def get_items_hubspot(credentials):
    credentials = json.loads(credentials)
    access_token = credentials["access_token"]

    url = f"{API_BASE}/crm/v3/objects/contacts"
    headers = {"Authorization": f"Bearer {access_token}"}
    response = httpx.get(url, headers=headers)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to fetch HubSpot items")

    items = []
    for record in response.json().get("results", []):
        item = await create_integration_item_metadata_object(record)
        items.append(item)

    print("HubSpot contacts response:", response.json())

    items = []
    for record in response.json().get("results", []):
        item = await create_integration_item_metadata_object(record)
        items.append(item)

    return items