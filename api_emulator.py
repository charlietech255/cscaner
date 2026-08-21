#!/usr/bin/env python3
"""Entry point for the real local API emulator."""

from modules.api_emulator import DEFAULT_HOST, DEFAULT_PORT, run_api_emulator, scan_api_contract

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Start or scan a real API contract against a local or hosted backend.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--base-url", default=None, help="Base URL of a hosted API to scan, e.g. https://api.example.com")
    parser.add_argument("--token", default=None, help="Bearer token for hosted API access")
    parser.add_argument("--username", default=None, help="API login username when login route is required")
    parser.add_argument("--password", default=None, help="API login password when login route is required")
    parser.add_argument("--login-route", default="/auth/login", help="Login endpoint relative to the base URL")
    parser.add_argument("--scan", action="store_true", help="Exercise the API contract against the local emulator or hosted API")
    parser.add_argument("--state-file", default="api_emulator_state.json")
    args = parser.parse_args()

    if args.scan:
        target_url = args.base_url or f"http://{args.host}:{args.port}"
        result = scan_api_contract(
            target_url,
            username=args.username,
            password=args.password,
            token=args.token,
            login_route=args.login_route,
        )
        import json
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result.get("contract_ok") else 1)

    run_api_emulator(host=args.host, port=args.port, state_file=args.state_file)
