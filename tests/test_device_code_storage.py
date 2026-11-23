"""Device-code lures on regional cloud storage (an_01M84AKR3MCZN6S9GFAJTP823H).

An "Adobe Acrobat shared document" page on kit.s3.us-east-1.amazonaws.com showed an
"access code" and opened login.microsoftonline.com/common/oauth2/deviceauth. Regional
S3 hosts used to count as the site amazonaws.com, which is on the Tranco allowlist, so
every Microsoft and lookalike rule skipped the page. The code below is a placeholder.
"""

import pytest

from sandbox.analysis.domains import free_hosting, site
from tests.test_detections import _cap, _dc_page, _hits

_KIT = "https://adobe-kit123.s3.us-east-1.amazonaws.com/index.html"
_DEVICEAUTH = "https://login.microsoftonline.com/common/oauth2/deviceauth"
_TEXT = (
    "A document was shared with you. Shared by IT Administrator. ACCESS CODE QX7TK2MB9 "
    "Copy access code. To open this document 1. Click Review document 2. Enter the access "
    "code when prompted 3. Complete sign-in to unlock the PDF"
)


@pytest.mark.parametrize(
    ("host", "platform"),
    [
        ("kit.s3.us-east-1.amazonaws.com", "s3.us-east-1.amazonaws.com"),
        ("kit.s3-website-eu-west-1.amazonaws.com", "s3-website-eu-west-1.amazonaws.com"),
        ("kit.s3-website.eu-central-1.amazonaws.com", "s3-website.eu-central-1.amazonaws.com"),
        ("kit.s3.dualstack.us-east-1.amazonaws.com", "s3.dualstack.us-east-1.amazonaws.com"),
        ("kit.s3.us-gov-west-1.amazonaws.com", "s3.us-gov-west-1.amazonaws.com"),
        ("kit.s3.cn-north-1.amazonaws.com.cn", "s3.cn-north-1.amazonaws.com.cn"),
        ("kit.s3.amazonaws.com", "s3.amazonaws.com"),
    ],
)
def test_regional_s3_buckets_are_their_own_site(host, platform):
    assert free_hosting(host) == platform
    assert site(host) == host


@pytest.mark.parametrize(
    "host",
    [
        "ec2-1-2-3-4.compute-1.amazonaws.com",
        "api.execute-api.us-east-1.amazonaws.com",
        "amazonaws.com",
    ],
)
def test_other_aws_hosts_are_not_storage(host):
    assert free_hosting(host) is None
    assert site(host) == "amazonaws.com"


def test_device_code_lure_on_regional_s3_fires_with_amazonaws_allowlisted():
    data = _cap(_KIT, [_dc_page(_KIT, _TEXT, links=(_DEVICEAUTH,))], allowlisted=["amazonaws.com"])
    assert {"device_code_handoff", "device_code_phishing_lure"} <= _hits(data)


def test_access_code_wording_without_a_hand_off_is_quiet():
    """A gift-card or event page that shows an access code but never sends anyone to
    Microsoft's device-code sign-in."""
    url = "https://tickets.example.net/redeem"
    hits = _hits(_cap(url, [_dc_page(url, _TEXT, links=())]))
    assert not {"device_code_handoff", "device_code_phishing_lure"} & hits
