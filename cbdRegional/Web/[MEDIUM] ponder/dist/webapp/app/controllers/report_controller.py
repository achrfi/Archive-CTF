from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from flask import Blueprint, current_app, flash, render_template, request


report_bp = Blueprint("report", __name__)


@report_bp.route("/report", methods=("GET", "POST"))
def report():
    url = request.values.get("url", "").strip()

    if request.method == "POST" or url:
        if not url.startswith(("http://", "https://")):
            flash("Report URL must start with http:// or https://.", "error")
        elif report_to_bot(url, forwarded_for_header()):
            flash("Report sent to the bot.", "success")
        else:
            flash("Bot could not visit that URL.", "error")

    return render_template("report.html", url=url)


def forwarded_for_header():
    remote_addr = normalized_ip(request.remote_addr or "")

    if is_trusted_forwarding_proxy(remote_addr):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        client_ip = client_ip_from_forwarded_for(
            forwarded_for,
            current_app.config.get("TRUSTED_PROXY_COUNT", 0),
        )

        if client_ip:
            return client_ip

    return remote_addr


def client_ip_from_forwarded_for(forwarded_for, trusted_proxy_count):
    forwarded_ips = [
        ip
        for ip in (
            normalized_ip(part)
            for part in forwarded_for.split(",")
        )
        if ip
    ]

    if not forwarded_ips:
        return ""

    try:
        trusted_proxy_count = max(0, int(trusted_proxy_count))
    except (TypeError, ValueError):
        trusted_proxy_count = 0

    if trusted_proxy_count:
        if len(forwarded_ips) >= trusted_proxy_count:
            return forwarded_ips[-trusted_proxy_count]
        return ""

    return forwarded_ips[0]


def normalized_ip(value):
    value = value.strip().strip("\"'")
    if not value:
        return ""

    try:
        return ip_address(value).compressed
    except ValueError:
        return ""


def is_trusted_forwarding_proxy(value):
    try:
        ip = ip_address(value)
    except ValueError:
        return False

    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
    )


def report_to_bot(url, forwarded_for):
    bot_url = current_app.config["BOT_URL"].rstrip("/")
    visit_url = f"{bot_url}/visit?{urlencode({'url': url})}"
    headers = {}
    if forwarded_for:
        headers["X-Forwarded-For"] = forwarded_for

    try:
        with urlopen(Request(visit_url, headers=headers), timeout=30) as response:
            return 200 <= response.status < 300
    except (HTTPError, URLError, TimeoutError, ValueError):
        return False
