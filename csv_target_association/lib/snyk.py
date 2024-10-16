"""Snyk API Wrapper Functions
"""

# ===== IMPORTS =====

import json
import time

import requests
from rich import print

# ===== CONSTANTS =====

SNYK_V1_API_BASE_URL      = 'https://api.snyk.io/v1'

SNYK_REST_API_BASE_URL      = 'https://api.snyk.io'
SNYK_REST_API_VERSION       = '2024-09-04'
SNYK_API_TIMEOUT_DEFAULT    = 90

RESPONSE_SUCCESS            = 200
RESPONSE_ERROR_RATE_LIMIT   = 429

RATE_LIMIT_BACKOFF_SEC      = 60

# ===== GLOBALS =====

# ===== METHODS =====

def get_all_targets_in_org(snyk_token, org_id, source_types):
    targets = []

    headers = {
        'Authorization': f'token {snyk_token}'
    }

    base_url = SNYK_REST_API_BASE_URL

    url = f'{base_url}/rest/orgs/{org_id}/targets?version={SNYK_REST_API_VERSION}&limit=100&exclude_empty=false'

    if source_types is not '':
        url = f'{url}&source_types={source_types}'

    while True:
        response = requests.request(
            'GET',
            url,
            headers=headers,
            timeout=SNYK_API_TIMEOUT_DEFAULT)

        if response.status_code == RESPONSE_SUCCESS:
            # ---------- SUCCESS BLOCK ----------

            response_json = json.loads(response.content)

            if 'data' in response_json:
                targets = targets + response_json['data']

            if 'next' not in response_json['links'] or response_json['links']['next'] == '':
                return targets

            url = f"{base_url}{response_json['links']['next']}"
            response_json = None

        else:
            # ---------- FAIL BLOCK ----------
            if response.status_code == RESPONSE_ERROR_RATE_LIMIT:
                print("WARNING - Snyk rate limit hit, waiting 60 seconds then retrying call")
                time.sleep(RATE_LIMIT_BACKOFF_SEC)
            else:
                print(f"ERROR - Response code: {response.status_code}")
                break

            return None

def get_all_projects_in_target(snyk_token, org_id, target_id):
    projects = []

    headers = {
        'Authorization': f'token {snyk_token}'
    }

    base_url = SNYK_REST_API_BASE_URL

    url = f'{base_url}/rest/orgs/{org_id}/projects?version={SNYK_REST_API_VERSION}&limit=100&target_id={target_id}'

    while True:
        response = requests.request(
            'GET',
            url,
            headers=headers,
            timeout=SNYK_API_TIMEOUT_DEFAULT)

        if response.status_code == RESPONSE_SUCCESS:
            # ---------- SUCCESS BLOCK ----------

            response_json = json.loads(response.content)

            if 'data' in response_json:
                projects = projects + response_json['data']

            if 'next' not in response_json['links'] or response_json['links']['next'] == '':
                return projects
                break

            url = f"{base_url}{response_json['links']['next']}"
            response_json = None

        else:
            # ---------- FAIL BLOCK ----------
            if response.status_code == RESPONSE_ERROR_RATE_LIMIT:
                print("WARNING - Snyk rate limit hit, waiting 60 seconds then retrying call")
                time.sleep(RATE_LIMIT_BACKOFF_SEC)
            else:
                print(f"ERROR - Response code: {response.status_code}")
                break

def apply_component_tag(snyk_token, org_id, project_id, component_tag_value):
    headers = {
        'Authorization': f'token {snyk_token}',
    }

    base_url = SNYK_V1_API_BASE_URL

    url = f'{base_url}/org/{org_id}/project/{project_id}/tags'

    tag = {
        "key": "component",
        "value": f"pkg:{component_tag_value}"
    }

    response = requests.request(
        'POST',
        headers=headers,
        url=url,
        json=tag
    )

    if response.status_code == RESPONSE_SUCCESS:
        # ---------- SUCCESS BLOCK ----------
        pass
    else:
        # ---------- FAILURE BLOCK ----------
        if response.status_code == 422:
            print(f'{component_tag_value} already exists for project: {project_id}')
        else:
            print(f'ERROR: Could not apply tag: {component_tag_value} to project: {project_id}, reason: {response.status_code}')

