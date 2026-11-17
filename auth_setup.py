#!/usr/bin/env python3
"""
Headless OAuth 2.0 Setup Helper for Google Drive.
Generates an authorization URL, accepts the redirected URL or auth code,
and saves the resulting credentials to token.json.
"""

import argparse
import json
import os
import sys
import urllib.parse
from dotenv import load_dotenv
from google_auth_oauthlib.flow import InstalledAppFlow

load_dotenv()

SCOPES = ["https://www.googleapis.com/auth/drive"]


def run_auth_flow(credentials_path: str, token_path: str):
    # Allow http://localhost redirect in oauthlib
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

    if not os.path.exists(credentials_path):
        print(f"Error: Credentials file not found at '{credentials_path}'.")
        print("\nTo obtain credentials.json:")
        print("1. Go to Google Cloud Console: https://console.cloud.google.com/apis/credentials")
        print("2. Create an OAuth 2.0 Client ID with Application Type 'Desktop app'.")
        print("3. Download the JSON file and save it as 'credentials.json' in this folder.")
        sys.exit(1)

    try:
        with open(credentials_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {credentials_path}: {e}")
        sys.exit(1)

    config_type = "installed" if "installed" in data else "web" if "web" in data else None
    if not config_type:
        print("Error: Invalid client credentials format (missing 'installed' or 'web' section).")
        sys.exit(1)

    redirect_uris = data[config_type].get("redirect_uris", [])
    redirect_uri = redirect_uris[0] if redirect_uris else "http://localhost"

    try:
        flow = InstalledAppFlow.from_client_secrets_file(
            credentials_path,
            scopes=SCOPES,
            redirect_uri=redirect_uri,
        )
    except Exception as e:
        print(f"Error creating OAuth flow: {e}")
        sys.exit(1)

    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
    )

    print("\n" + "=" * 70)
    print("GOOGLE DRIVE HEADLESS OAUTH SETUP")
    print("=" * 70)
    print("\n1. Visit this authorization URL in your browser:\n")
    print(auth_url)
    print("\n2. Log in and click 'Allow' to grant Google Drive permissions.")
    print("3. Your browser will redirect to a URL (such as http://localhost/?code=...)")
    print("   Copy either the ENTIRE redirected URL or just the code parameter value.")
    print("=" * 70 + "\n")

    try:
        user_input = input("Enter the redirected URL or authorization code: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.")
        sys.exit(1)

    if not user_input:
        print("Error: No code or URL entered.")
        sys.exit(1)

    code = None
    if "code=" in user_input:
        parsed = urllib.parse.urlparse(user_input)
        qs = urllib.parse.parse_qs(parsed.query)
        if "code" in qs:
            code = qs["code"][0]
    if not code:
        code = user_input

    try:
        flow.fetch_token(code=code)
        creds = flow.credentials
        with open(token_path, "w") as f:
            f.write(creds.to_json())
        print(f"\n[SUCCESS] Authentication token saved to: {token_path}")
        print("Bucketloader is now authenticated with Google Drive!")
    except Exception as e:
        print(f"\n[ERROR] Failed to exchange authorization code for tokens: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Headless Google Drive OAuth Setup")
    parser.add_argument(
        "--credentials",
        default=os.getenv("GOOGLE_CREDENTIALS_FILE", "credentials.json"),
        help="Path to Google OAuth credentials.json (default: credentials.json)",
    )
    parser.add_argument(
        "--token",
        default=os.getenv("GOOGLE_TOKEN_FILE", "token.json"),
        help="Path to save token.json (default: token.json)",
    )
    args = parser.parse_args()
    run_auth_flow(args.credentials, args.token)


if __name__ == "__main__":
    main()
