import ipaddress

from flask import current_app, request


def client_ip():
    """The caller's address, used for audit rows and rate limits.

    Behind Render, request.remote_addr is one of the platform's internal addresses.
    Cloudflare sits in front of Render and sets CF-Connecting-IP to the real caller,
    but the header is only believed when TRUST_CF_CONNECTING_IP is switched on:
    anywhere else, a caller could send it themselves.
    """
    if current_app.config.get("TRUST_CF_CONNECTING_IP"):
        raw = request.headers.get("CF-Connecting-IP", "").strip()
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            pass  # missing or not an address: fall back
    return request.remote_addr