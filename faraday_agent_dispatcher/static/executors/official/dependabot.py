import http

import requests
import os

def main():
    DEPENDABOT_OWNER = os.getenv("DEPENDABOT_OWNER")
    DEPENDABOT_REPO = os.getenv("DEPENDABOT_REPO")
    DEPENDABOT_TOKEN = os.getenv("EXECUTOR_CONFIG_DEPENDABOT_TOKEN")

    # TODO: should validate config?
    dependabot_url = f"https://api.github.com/repos/{DEPENDABOT_OWNER}/{DEPENDABOT_REPO}/dependabot/alerts"
    dependabot_auth = {'Authorization': f"Bearer {DEPENDABOT_TOKEN}"}

    print(dependabot_url)
    print(dependabot_auth)

    response = requests.get(dependabot_url, headers=dependabot_auth)
    if response.status_code == http.HTTPStatus.OK:
        print(response.json())


if __name__ == '__main__':
    main()
