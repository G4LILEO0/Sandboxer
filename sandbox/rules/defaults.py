"""Built-in rules, weights, brands and feeds, seeded into Postgres on first start.

Everything here is ordinary data once seeded: admins can disable or re-weight it.
Seeding adds what is missing and refreshes the bodies of built-in rules (which admins
cannot edit, only disable), so rule fixes reach existing installations. Built-in brand
domains are merged into existing brand rows; nothing an admin set is removed.
"""

import json
from typing import Any

BUILTIN_SOURCE = "builtin"


def _rule(name, severity, tags, attack, description, condition, evidence=()) -> dict[str, Any]:
    return {
        "name": name,
        "severity": severity,
        "tags": list(tags),
        "attack_ids": list(attack),
        "description": description,
        "body": json.dumps({"condition": condition, "evidence": list(evidence)}, indent=1),
    }


# ANA-4 behaviour rules. Each has a fixture-based test in tests/test_analysis.py.
# A rule reads facts built by sandbox.analysis.facts.build_facts; "evidence" lists extra
# fact paths copied into the hit so the report shows why it fired.
_CLICKFIX_LIKE = {
    "any": [
        {"fact": "clipboard.clickfix_like", "op": "gt", "value": 0},
        {
            "all": [
                {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                {"fact": "lure.run_dialog_instructions", "op": "gt", "value": 0},
            ]
        },
    ]
}

BEHAVIOUR_RULES = [
    _rule(
        "form_posts_cross_domain",
        "high",
        ["phishing", "credential-harvest"],
        ["T1566.002", "T1056.003"],
        "A form with a password field submits to a different site than the page (sites of "
        "one brand, such as live.com and microsoftonline.com, count as the same site).",
        {"fact": "forms.cross_domain_credential", "op": "gt", "value": 0},
        ["forms.cross_domain_credential_forms"],
    ),
    _rule(
        "obfuscated_javascript",
        "medium",
        ["obfuscation"],
        ["T1027"],
        "A script uses several obfuscation techniques (eval of decoded strings, packers, "
        "long encoded blobs).",
        {"fact": "scripts.max_obfuscation_score", "op": "gte", "value": 3},
        ["scripts.obfuscated"],
    ),
    _rule(
        "automatic_download",
        "high",
        ["malware-download"],
        ["T1189", "T1204.002"],
        "The page started a download of an executable, archive or disguised file without "
        "the analyst clicking anything.",
        {"fact": "downloads.unprompted_risky", "op": "gt", "value": 0},
        ["downloads.files"],
    ),
    _rule(
        "executable_download",
        "high",
        ["malware-download"],
        ["T1204.002"],
        "A downloaded file is an executable, script or disk image.",
        {"fact": "downloads.executable", "op": "gt", "value": 0},
        ["downloads.files"],
    ),
    _rule(
        "disguised_download",
        "high",
        ["malware-download", "masquerading"],
        ["T1036.007", "T1036.008"],
        "A downloaded file hides its type: a double extension (invoice.pdf.exe) or a "
        "document extension on an executable.",
        {"fact": "downloads.disguised", "op": "gt", "value": 0},
        ["downloads.files"],
    ),
    _rule(
        "clickfix_clipboard_command",
        "critical",
        ["clickfix"],
        ["T1204.004", "T1059"],
        "The page put a ClickFix-style command on the clipboard (download cradle, hidden or "
        "encoded PowerShell, mshta of a URL, a finger.exe or for /f fetch-and-run, caret "
        "obfuscation, or a fake-CAPTCHA comment or padded decoy), or a command "
        "together with instructions to paste it into the Run dialog or a terminal.",
        _CLICKFIX_LIKE,
        ["clipboard.commands", "lure.run_dialog_pages"],
    ),
    _rule(
        "clipboard_command_write",
        "medium",
        ["suspicious-clipboard"],
        ["T1204.004"],
        "The page wrote a shell command to the clipboard without other ClickFix traits "
        "(developer docs with copy buttons do this too).",
        {
            "all": [
                {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                {"not": _CLICKFIX_LIKE},
            ]
        },
        ["clipboard.commands"],
    ),
    _rule(
        "newly_registered_domain",
        "medium",
        ["newly-registered"],
        ["T1583.001"],
        "The submitted, redirect or final domain was registered less than 30 days ago "
        "(third-party resources are not counted).",
        {"fact": "domains.chain_youngest_age_days", "op": "lt", "value": 30},
        ["domains.young"],
    ),
    _rule(
        "credential_form_on_new_domain",
        "high",
        ["phishing", "newly-registered"],
        ["T1566.002", "T1583.001"],
        "A page asks for a password and the final domain is less than 30 days old.",
        {
            "all": [
                {"fact": "forms.password_forms", "op": "gt", "value": 0},
                {"fact": "domains.final_age_days", "op": "lt", "value": 30},
            ]
        },
        ["final.domain"],
    ),
    _rule(
        "punycode_domain",
        "medium",
        ["punycode"],
        ["T1583.001", "T1036"],
        "A domain is an internationalised name that mixes Latin with another script or "
        "uses only Latin-lookalike characters.",
        {"fact": "domains.punycode_confusable", "op": "gt", "value": 0},
        ["domains.punycode_hosts"],
    ),
    _rule(
        "lookalike_domain",
        "high",
        ["lookalike", "phishing"],
        ["T1583.001", "T1036"],
        "A domain imitates a known brand's domain.",
        {"fact": "domains.lookalike", "op": "gt", "value": 0},
        ["domains.lookalikes"],
    ),
    _rule(
        "suspicious_redirect_chain",
        "medium",
        ["suspicious-redirect", "cloaking"],
        ["T1608.005"],
        "Three or more cross-site redirects, a long chain through several sites, or an "
        "https to http downgrade.",
        {
            "any": [
                {"fact": "redirects.cross_domain", "op": "gte", "value": 3},
                {"fact": "redirects.https_downgrade", "op": "eq", "value": True},
                {
                    "all": [
                        {"fact": "redirects.count", "op": "gte", "value": 5},
                        {"fact": "redirects.cross_domain", "op": "gte", "value": 2},
                    ]
                },
            ]
        },
        ["redirects.chain"],
    ),
    _rule(
        "brand_impersonation",
        "high",
        ["phishing", "brand-impersonation"],
        ["T1656"],
        "A page presents a known brand and asks for credentials, but is not hosted on "
        "that brand's domains.",
        {
            "all": [
                {"fact": "brand.confidence", "op": "gte", "value": 60},
                {"fact": "brand.credential_prompt", "op": "eq", "value": True},
            ]
        },
        ["brand"],
    ),
    _rule(
        "brand_on_free_hosting",
        "high",
        ["phishing", "brand-impersonation", "free-hosting"],
        ["T1583.006", "T1656"],
        "A page on a free hosting or site-builder platform (pages.dev, typedream.app, "
        "web.app, blob.core.windows.net, ...) has a brand plus login, wallet, support or "
        "verification wording in its title: the SEO and smishing landing pages that send "
        "victims on to a harvester.",
        {"fact": "brand.free_hosting_lure", "op": "eq", "value": True},
        ["brand"],
    ),
    _rule(
        "government_lookalike_domain",
        "high",
        ["phishing", "government-impersonation"],
        ["T1583.001", "T1656"],
        "A domain dresses up as a government site without being under a government suffix "
        "(absher-gov-sa.com, moi.gov.sa.verify-id.com, govsa-fines.net).",
        {"fact": "domains.government_lookalike", "op": "gt", "value": 0},
        ["domains.government_lookalikes"],
    ),
    _rule(
        "payment_card_harvest",
        "high",
        ["phishing", "card-harvest"],
        ["T1566.002", "T1056.003"],
        "A page asks for card details (number with CVV or expiry) and has another phishing "
        "trait: a delivery-fee, customs or fine pretext, a lookalike or government-lookalike "
        "domain, free hosting, or a domain under 30 days old.",
        {
            "all": [
                {"fact": "forms.payment_card_forms", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "lure.payment_pretext", "op": "gt", "value": 0},
                        {"fact": "domains.lookalike", "op": "gt", "value": 0},
                        {"fact": "domains.government_lookalike", "op": "gt", "value": 0},
                        {"fact": "final.free_hosting", "op": "exists", "value": True},
                        {"fact": "domains.final_age_days", "op": "lt", "value": 30},
                    ]
                },
            ]
        },
        ["forms.sensitive_prompt_pages", "lure.payment_pretexts"],
    ),
    _rule(
        "otp_harvest",
        "high",
        ["phishing", "otp-harvest"],
        ["T1566.002", "T1111"],
        "A page asks for a one-time code (SMS, Absher, Nafath or bank OTP) and presents a "
        "brand, a payment pretext, a lookalike or government-lookalike domain, free hosting, "
        "or a domain under 30 days old.",
        {
            "all": [
                {"fact": "forms.otp_forms", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "brand.confidence", "op": "gte", "value": 35},
                        {"fact": "lure.payment_pretext", "op": "gt", "value": 0},
                        {"fact": "domains.lookalike", "op": "gt", "value": 0},
                        {"fact": "domains.government_lookalike", "op": "gt", "value": 0},
                        {"fact": "final.free_hosting", "op": "exists", "value": True},
                        {"fact": "domains.final_age_days", "op": "lt", "value": 30},
                    ]
                },
            ]
        },
        ["forms.sensitive_prompt_pages", "brand"],
    ),
    _rule(
        "seed_phrase_harvest",
        "high",
        ["phishing", "crypto", "wallet-drainer"],
        ["T1566.002", "T1056.003"],
        "A page outside any known wallet's domains asks for a wallet recovery (seed) phrase.",
        {"fact": "forms.seed_phrase_forms", "op": "gt", "value": 0},
        ["forms.sensitive_prompt_pages"],
    ),
    _rule(
        "payment_card_form",
        "low",
        ["card-form"],
        [],
        "A page outside known brands and allowlisted sites asks for card details. On its "
        "own this is any checkout page; it adds weight to other findings.",
        {"fact": "forms.payment_card_forms", "op": "gt", "value": 0},
        ["forms.sensitive_prompt_pages"],
    ),
    _rule(
        "internal_network_probe",
        "medium",
        ["internal-probe"],
        ["T1046"],
        "The page tried to reach internal or cloud-metadata addresses (blocked).",
        {"fact": "network.blocked_internal", "op": "gt", "value": 0},
        ["network.blocked"],
    ),
    _rule(
        "hidden_iframe",
        "low",
        ["hidden-iframe"],
        [],
        "The page embeds an invisible iframe.",
        {"fact": "frames.hidden_iframes", "op": "gt", "value": 0},
        ["frames.hidden_iframe_urls"],
    ),
    _rule(
        "password_over_http",
        "low",
        ["insecure-form"],
        [],
        "A password form is served or submitted over plain http.",
        {"fact": "forms.password_over_http", "op": "gt", "value": 0},
    ),
    # --- exfiltration channels (DE-PHI-001/002) -------------------------------------
    _rule(
        "telegram_bot_exfil",
        "critical",
        ["phishing", "exfil-telegram"],
        ["T1567", "T1102.002", "T1056.003"],
        "The page called the Telegram Bot API (api.telegram.org/bot<token>/sendMessage or "
        "similar) from the browser: phishing kits use a Telegram bot as their drop.",
        {"fact": "exfil.telegram_count", "op": "gt", "value": 0},
        ["exfil.telegram", "forms.password_forms", "final.url"],
    ),
    _rule(
        "discord_webhook_exfil",
        "high",
        ["phishing", "exfil"],
        ["T1567", "T1102.002"],
        "The page posted to a Discord webhook (discord.com/api/webhooks/...) from the "
        "browser: webhooks are a server-side drop, not something a normal web page uses.",
        {"fact": "exfil.discord_count", "op": "gt", "value": 0},
        ["exfil.discord", "forms.password_forms", "final.url"],
    ),
    # --- Microsoft 365 / Entra (DE-M365-001/002/003/006/007/011) --------------------
    _rule(
        "ms_signin_clone_foreign_host",
        "high",
        ["phishing", "aitm", "brand-impersonation"],
        ["T1566.002", "T1056.003", "T1656"],
        "A non-Microsoft page carries Microsoft sign-in structural markers (ESTS $Config, "
        "i0116/idSIButton9 ids, AADCDN assets) and shows a credential prompt: a cloned or "
        "proxied Microsoft login.",
        {"fact": "idp.ms_clone_pages", "op": "gt", "value": 0},
        ["idp.ms_clone_page_details", "final.url"],
    ),
    _rule(
        "idp_cdn_assets_foreign_page",
        "high",
        ["phishing", "aitm"],
        ["T1566.002", "T1656"],
        "A page that is not the identity provider loads IdP sign-in branding from the IdP's "
        "CDN (AADCDN, Okta CDN) and shows a credential prompt.",
        {"fact": "idp.cdn_assets_on_foreign_page", "op": "eq", "value": True},
        ["idp.cdn_assets", "final.url"],
    ),
    _rule(
        "aitm_ms_paths_foreign_host",
        "critical",
        ["phishing", "aitm"],
        ["T1557", "T1539", "T1566.002"],
        "Microsoft login endpoints (oauth2/authorize, GetCredentialType, kmsi) are served "
        "from a non-Microsoft host with ESTS markers or ESTS cookies: an AiTM reverse proxy.",
        {"fact": "idp.ms_paths_on_foreign_host", "op": "gt", "value": 0},
        ["idp.ms_foreign_paths", "final.url"],
    ),
    _rule(
        "oauth_error_redirect_abuse",
        "high",
        ["phishing", "redirector-abuse"],
        ["T1566.002", "T1204.001"],
        "An OAuth authorize request with prompt=none bounced off a real identity provider "
        "(error=interaction_required/access_denied) to a non-IdP redirect host.",
        {
            "all": [
                {"fact": "redirects.oauth_error_bounce_count", "op": "gt", "value": 0},
                {"not": {"fact": "final.allowlisted", "op": "eq", "value": True}},
            ]
        },
        ["redirects.oauth_error_bounce", "redirects.chain"],
    ),
    _rule(
        "illicit_consent_grant",
        "high",
        ["consent-phishing", "aitm"],
        ["T1528", "T1566.002", "T1550.001"],
        "An Entra authorize/consent request names a non-first-party client id and asks for "
        "high-risk Graph scopes (Mail.ReadWrite, Files.ReadWrite.All, offline_access).",
        {"fact": "idp.high_risk_consent", "op": "gt", "value": 0},
        ["idp.oauth_authorize_requests", "final.url"],
    ),
    # --- ConsentFix / AuthCodeFix (DE-M365-013, DE-M365-014) -------------------------
    _rule(
        "consentfix_authcode_paste_back",
        "critical",
        ["consent-phishing", "clickfix", "aitm"],
        ["T1528", "T1566.002", "T1204.004"],
        "A non-Microsoft page surfaces a real Entra authorize URL for a first-party "
        "(pre-consented) app such as Azure CLI with a localhost redirect_uri, and tells the "
        "visitor to paste the resulting URL or code back into a box on that page: the "
        "authorization code is handed to the attacker (ConsentFix / AuthCodeFix). A page "
        "that only describes the step (a tutorial) gets the medium rule. Tenant check: a "
        "first-party app's service principal is owned by Microsoft's tenant "
        "f8cdef31-a31e-4b4a-93e4-5f571e91255a.",
        {
            "all": [
                {"fact": "idp.firstparty_loopback_authorize", "op": "gt", "value": 0},
                {"fact": "lure.paste_back_with_input", "op": "eq", "value": True},
            ]
        },
        ["idp.firstparty_loopback_details", "capture.gated", "final.url"],
    ),
    _rule(
        "firstparty_app_loopback_authorize",
        "medium",
        ["consent-phishing"],
        ["T1528"],
        "A non-Microsoft, non-allowlisted page surfaces an Entra authorize URL for a "
        "first-party app with a localhost redirect_uri: the structural half of ConsentFix, "
        "seen even when the paste-back instruction is not rendered.",
        {"fact": "idp.firstparty_loopback_authorize", "op": "gt", "value": 0},
        ["idp.firstparty_loopback_details", "final.url"],
    ),
    # --- OAuth device-code phishing (DE-M365-004) -----------------------------------
    _rule(
        "device_code_phishing_lure",
        "high",
        ["consent-phishing", "phishing"],
        ["T1566.002", "T1528"],
        "A non-Microsoft page sends the visitor to Microsoft's real device-code sign-in "
        "(microsoft.com/devicelogin, aka.ms/devicelogin, oauth2/deviceauth) and shows a "
        "code to enter, or a shared-document pretext with an email-only form: the victim "
        "authorises the attacker's device on Microsoft itself, so no clone is present.",
        {
            "all": [
                {"fact": "idp.device_code_handoff", "op": "gt", "value": 0},
                {"fact": "idp.device_code_lure", "op": "eq", "value": True},
            ]
        },
        ["idp.device_code_sources", "final.url"],
    ),
    _rule(
        "device_code_handoff",
        "medium",
        ["consent-phishing"],
        ["T1528"],
        "A non-Microsoft, non-allowlisted page links to, opens or navigates to Microsoft's "
        "device-code sign-in. On its own this can be an IT help page; with a displayed "
        "code it is device_code_phishing_lure.",
        {"fact": "idp.device_code_handoff", "op": "gt", "value": 0},
        ["idp.device_code_sources", "final.url"],
    ),
    _rule(
        "ms_session_cookie_foreign_host",
        "critical",
        ["phishing", "aitm"],
        ["T1539", "T1557"],
        "A non-Microsoft host set a Microsoft Entra session cookie (ESTSAUTH*): the sign of "
        "a relayed Microsoft login in an AiTM proxy.",
        {"fact": "idp.cookies_on_foreign_host", "op": "gt", "value": 0},
        ["idp.idp_cookies", "final.url"],
    ),
    # --- EtherHiding / web3 (DE-W3B-001/004) ----------------------------------------
    _rule(
        "web3_rpc_from_non_wallet_page",
        "high",
        ["etherhiding", "web3"],
        ["T1102.001", "T1105", "T1189"],
        "A page that is not a wallet/web3 app (no wallet UI, no wallet use) read a smart "
        "contract over JSON-RPC (eth_call / eth_getStorageAt): the EtherHiding dead-drop "
        "loader pattern. Fires on allowlisted sites too, since EtherHiding runs on "
        "compromised legitimate ones.",
        {"fact": "web3.etherhiding_rpc", "op": "eq", "value": True},
        ["web3.rpc_calls", "final.url"],
    ),
    # --- EtherHiding payload executed (DE-W3B-002) ----------------------------------
    _rule(
        "etherhiding_payload_executed",
        "critical",
        ["etherhiding", "web3", "obfuscation"],
        ["T1102.001", "T1027", "T1059.007"],
        "A page read a smart contract whose answer was a kilobyte-sized string, and that "
        "string (or its base64 layer) became eval/Function code: the contract is the "
        "next-stage script store (ClearFake / EtherHiding). Without the direct link it "
        "needs 1 KB+ of code-only exec (innerHTML/document.write do not count), and on an "
        "allowlisted site a fake update/CAPTCHA lure.",
        {"fact": "web3.rpc_result_executed", "op": "eq", "value": True},
        ["web3.rpc_calls", "web3.rpc_large_string_results", "js.code_exec_max_len", "final.url"],
    ),
    _rule(
        "web3_known_malicious_contract",
        "high",
        ["etherhiding", "web3", "known-bad"],
        ["T1102.001"],
        "The page read a smart contract address published in EtherHiding research.",
        {"fact": "web3.known_malicious_contract", "op": "gt", "value": 0},
        ["web3.known_contracts", "final.url"],
    ),
    # --- ClickFix extensions (DE-CFX-002/004) ---------------------------------------
    _rule(
        "fake_captcha_clipboard_command",
        "critical",
        ["clickfix"],
        ["T1204.004", "T1059.001", "T1218.005"],
        "A fake CAPTCHA / verification page wrote a command to the clipboard, or did so "
        "with Run-dialog instructions. When genuine Turnstile/reCAPTCHA resources loaded, "
        "verification wording alone is not enough: it then needs Run-dialog instructions "
        "or an unambiguous ClickFix trait.",
        {
            "all": [
                {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "lure.run_dialog_instructions", "op": "gt", "value": 0},
                        {
                            "all": [
                                {"fact": "lure.verification_wording", "op": "eq", "value": True},
                                {
                                    "any": [
                                        {
                                            "fact": "clipboard.clickfix_unambiguous",
                                            "op": "gt",
                                            "value": 0,
                                        },
                                        {
                                            "not": {
                                                "fact": "lure.genuine_challenge",
                                                "op": "eq",
                                                "value": True,
                                            }
                                        },
                                    ]
                                },
                            ]
                        },
                    ]
                },
            ]
        },
        ["lure.fake_captcha_evidence", "clipboard.commands", "final.url"],
    ),
    _rule(
        "filefix_command_disguised_as_path",
        "critical",
        ["clickfix", "filefix"],
        ["T1204.004", "T1059.001"],
        "The clipboard holds a shell command padded and then commented out with a decoy "
        "Windows file path (FileFix: the victim pastes it into Explorer's address bar).",
        {"fact": "clipboard.path_disguised", "op": "gt", "value": 0},
        ["clipboard.commands", "final.url"],
    ),
    # --- clipboard tampering booster (DE-CFX-006) -----------------------------------
    _rule(
        "clipboard_command_tampering",
        "medium",
        ["clickfix"],
        ["T1204.004", "T1070"],
        "The page wrote a shell-like command to the clipboard with no user gesture, or "
        "overwrote/blanked a command it had written: ClickFix kits do both, copy buttons "
        "on documentation pages do neither.",
        {
            "any": [
                {"fact": "clipboard.no_gesture_commands", "op": "gt", "value": 0},
                {"fact": "clipboard.overwritten_command", "op": "gt", "value": 0},
            ]
        },
        ["clipboard.commands", "final.url"],
    ),
    # --- protocol-handler lure (L2-NEW-6) --------------------------------------------
    _rule(
        "protocol_handler_lure",
        "high",
        ["protocol-handler", "webdav", "malware-download"],
        ["T1204.001", "T1221"],
        "The page opens Windows search (search-ms:) or a WebDAV share with a document "
        "pretext, a renamed results view (displayname) or a tunnel host: Explorer shows "
        "the attacker's remote files as if they were the visitor's own.",
        {
            "all": [
                {"fact": "navigation.protocol_handler_attempts", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "navigation.protocol_handler_pretext", "op": "eq", "value": True},
                        {
                            "fact": "navigation.protocol_handler_masquerade",
                            "op": "eq",
                            "value": True,
                        },
                        {"fact": "navigation.protocol_handler_tunnel", "op": "eq", "value": True},
                    ]
                },
            ]
        },
        ["navigation.protocol_handler_targets", "navigation.protocol_handler_hosts"],
    ),
    _rule(
        "protocol_handler_attempt",
        "medium",
        ["protocol-handler"],
        ["T1204.001"],
        "A non-allowlisted page tries to open Windows search (search-ms:) or a WebDAV "
        "share; ordinary web pages do not invoke Explorer.",
        {"fact": "navigation.protocol_handler_attempts", "op": "gt", "value": 0},
        ["navigation.protocol_handler_targets", "final.url"],
    ),
    # --- cache smuggling (L2-NEW-1) ---------------------------------------------------
    _rule(
        "cache_smuggled_payload",
        "high",
        ["filefix", "cache-smuggling", "malware-download"],
        ["T1027.006", "T1204.004", "T1564"],
        "A response served as an image is really an archive or executable, and the page "
        "gives FileFix/ClickFix steps: the browser cached a payload with no download "
        "prompt for a later File Explorer or Run step to pick up.",
        {
            "all": [
                {"fact": "downloads.mislabeled_image", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "clipboard.path_disguised", "op": "gt", "value": 0},
                        {"fact": "lure.run_dialog_instructions", "op": "gt", "value": 0},
                        {"fact": "clipboard.clickfix_like", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["downloads.mislabeled_images", "clipboard.commands", "lure.run_dialog_pages"],
    ),
    _rule(
        "mislabeled_image_payload",
        "medium",
        ["cache-smuggling"],
        ["T1027.006", "T1036"],
        "A response served as an image is really an archive or executable (ZIP, RAR, 7z, "
        "PE, CAB, OLE). Real CDNs that mislabel content serve another image type, not this.",
        {"fact": "downloads.mislabeled_image", "op": "gt", "value": 0},
        ["downloads.mislabeled_images", "final.url"],
    ),
    # --- fake browser update (DE-DLD-005) -------------------------------------------
    _rule(
        "fake_browser_update",
        "critical",
        ["fake-update", "malware-download"],
        ["T1189", "T1204.002", "T1036.005"],
        "A non-vendor page shows a browser/software update lure and either downloads a "
        "risky file or writes a clipboard command (ClearFake / SocGholish).",
        {
            "all": [
                {"fact": "lure.fake_update_pages", "op": "exists", "value": True},
                {
                    "any": [
                        {"fact": "downloads.unprompted_risky", "op": "gt", "value": 0},
                        {"fact": "downloads.executable", "op": "gt", "value": 0},
                        {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                        {"fact": "web3.etherhiding_rpc", "op": "eq", "value": True},
                    ]
                },
            ]
        },
        ["lure.fake_update_pages", "final.url"],
    ),
    # --- CrashFix fake crash-repair lure (DE-CFX-010) --------------------------------
    _rule(
        "crashfix_repair_lure",
        "high",
        ["clickfix", "crashfix"],
        ["T1176.001", "T1204.004"],
        "A non-vendor page shows a fake browser-crash / 'security issues detected' repair "
        "popup and writes a command to the clipboard or tells the visitor to paste one "
        "into Run (CrashFix / KongTuke, often after a malicious extension freezes the "
        "browser).",
        {
            "all": [
                {"fact": "lure.crash_repair_pages", "op": "exists", "value": True},
                {
                    "any": [
                        {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                        {"fact": "lure.run_dialog_instructions", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["lure.crash_repair_pages", "clipboard.commands", "evasion.devtools_blocked", "final.url"],
    ),
    # --- HTML smuggling credential page (DE-OBF-006) --------------------------------
    _rule(
        "smuggled_credential_page",
        "high",
        ["phishing", "smuggling"],
        ["T1027.006", "T1566.002"],
        "A blob: or about: document created by the page carries a credential form: an "
        "HTML-smuggled phishing page assembled in the browser.",
        {"fact": "frames.smuggled_credential_pages", "op": "gt", "value": 0},
        ["frames.smuggled_credential_urls", "final.url"],
    ),
    # --- IPFS credential page (DE-PHI-009) ------------------------------------------
    _rule(
        "ipfs_credential_page",
        "high",
        ["phishing"],
        ["T1566.002", "T1583.006"],
        "The final page is served from an IPFS gateway and asks for credentials.",
        {
            "all": [
                {"fact": "final.ipfs", "op": "exists", "value": True},
                {
                    "any": [
                        {"fact": "forms.password_forms", "op": "gt", "value": 0},
                        {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                        {"fact": "forms.otp_forms", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["final.ipfs", "final.url"],
    ),
    # --- client-side IP/geo lookup (DE-EVA-004) -------------------------------------
    _rule(
        "client_side_ip_geo_lookup",
        "medium",
        ["evasion", "geofencing"],
        ["T1614", "T1497"],
        "The page queried a client-side IP/ASN/geo lookup service and also showed a "
        "credential, ClickFix or download lure: geofencing or sandbox filtering.",
        {
            "all": [
                {"fact": "network.ip_lookups", "op": "exists", "value": True},
                {
                    "any": [
                        {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                        {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                        {"fact": "downloads.unprompted_risky", "op": "gt", "value": 0},
                        {"fact": "forms.sensitive_prompt_pages", "op": "exists", "value": True},
                    ]
                },
            ]
        },
        ["network.ip_lookups", "final.url"],
    ),
    # --- real-time credential relay over WebSocket (DE-M365-010, booster) -----------
    _rule(
        "credential_relay_websocket",
        "high",
        ["aitm", "exfil"],
        ["T1557", "T1056.003"],
        "A brand credential-prompt page opened a WebSocket, or a Socket.IO long-polling "
        "channel, to a host it does not own: the real-time relay AiTM kits (Mamba/Tycoon) "
        "use to pass typed credentials on.",
        {
            "all": [
                {
                    "any": [
                        {"fact": "websocket.foreign_count", "op": "gt", "value": 0},
                        {"fact": "websocket.socketio_polling", "op": "gt", "value": 0},
                    ]
                },
                {
                    "any": [
                        {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                        {"fact": "idp.ms_clone_pages", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["websocket.connections", "websocket.polling_connections", "final.url"],
    ),
    # --- script-posted credentials (DE-PHI-003, needs A3 request log) ---------------
    _rule(
        "script_posted_credentials",
        "high",
        ["phishing", "credential-harvest"],
        ["T1056.003", "T1041"],
        "A page with a password field and no real form action posted (fetch/XHR/beacon) to "
        "another site, and either the body carries a credential field or the page is a "
        "brand credential prompt / Microsoft clone: the script-posted credential path that "
        "form-action rules miss.",
        {
            "any": [
                {"fact": "forms.script_posted_credentials", "op": "gt", "value": 0},
                {
                    "all": [
                        {"fact": "forms.script_posts", "op": "gt", "value": 0},
                        {
                            "any": [
                                {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                                {"fact": "idp.ms_clone_pages", "op": "gt", "value": 0},
                            ]
                        },
                    ]
                },
            ]
        },
        ["forms.script_posted_targets", "final.url"],
    ),
    # --- runtime obfuscated execution (DE-OBF-002, needs A1 exec hook) --------------
    _rule(
        "runtime_dynamic_execution",
        "medium",
        ["obfuscation"],
        ["T1027", "T1059.007"],
        "The page ran large, high-entropy strings through eval/Function/setTimeout at "
        "runtime (packed code that only appears after decoding).",
        {
            "all": [
                {"fact": "js.code_exec_count", "op": "gte", "value": 2},
                {"fact": "js.code_exec_max_len", "op": "gt", "value": 1024},
                {"fact": "js.code_exec_max_entropy", "op": "gt", "value": 4.5},
            ]
        },
        ["js.dynamic_exec_count", "final.url"],
    ),
    # --- HTML smuggling binary (DE-OBF-005, needs A1 blob hook) ---------------------
    _rule(
        "html_smuggling_binary_blob",
        "high",
        ["smuggling", "malware-download"],
        ["T1027.006", "T1204.002"],
        "The page built a large Blob/File and a risky file download happened in the same "
        "session: HTML smuggling that assembles the payload in the browser.",
        {
            "all": [
                {"fact": "js.blob_constructs", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "downloads.executable", "op": "gt", "value": 0},
                        {"fact": "downloads.disguised", "op": "gt", "value": 0},
                        {"fact": "downloads.archive", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["js.blob_details", "downloads.files"],
    ),
    # --- archive deliveries (DE-DLD-001/002, needs A10 archive listing) -------------
    _rule(
        "risky_archive_contents",
        "high",
        ["malware-download"],
        ["T1204.002", "T1105"],
        "A downloaded archive contains an executable, script or shortcut.",
        {"fact": "downloads.archive_inner_risky", "op": "gt", "value": 0},
        ["downloads.archives"],
    ),
    _rule(
        "password_protected_archive_with_password",
        "high",
        ["malware-download", "defense-evasion"],
        ["T1027.013", "T1204.002"],
        "A downloaded archive is encrypted and the page prints the password: the pattern "
        "that stops SEGs and browsers scanning the contents.",
        {
            "all": [
                {"fact": "downloads.archive_encrypted", "op": "gt", "value": 0},
                {"fact": "downloads.archive_password_on_page", "op": "eq", "value": True},
            ]
        },
        ["downloads.archives", "final.url"],
    ),
    # --- tech-support / push / history scams (DE-SCM-001/002/003, A1 hooks) ---------
    _rule(
        "tech_support_browser_locker",
        "high",
        ["tech-support-scam", "scam"],
        ["T1656", "T1204.001"],
        "The page used lock-in APIs (fullscreen re-entry, pointer/keyboard lock, forced "
        "audio) and shows a support phone number with scare wording.",
        {
            "all": [
                {
                    "any": [
                        {"fact": "js.fullscreen", "op": "gt", "value": 0},
                        {"fact": "js.pointer_lock", "op": "gt", "value": 0},
                        {"fact": "js.keyboard_lock", "op": "gt", "value": 0},
                    ]
                },
                {"fact": "lure.tech_support_phone", "op": "gt", "value": 0},
            ]
        },
        ["lure.tech_support_phones", "final.url"],
    ),
    _rule(
        "history_flooding",
        "medium",
        ["scam", "browser-hijack"],
        ["T1185"],
        "The page flooded session history (many pushState/replaceState calls): back-button "
        "hijacking used by browser lockers.",
        {"fact": "js.history_floods", "op": "gte", "value": 20},
        ["js.history_floods", "final.url"],
    ),
    _rule(
        "push_notification_bait",
        "medium",
        ["scam", "push-abuse"],
        ["T1204.001", "T1566"],
        "The page asked for notification permission with 'click Allow to continue/verify' "
        "coercion wording.",
        {
            "all": [
                {"fact": "js.notification_prompt", "op": "gt", "value": 0},
                {"fact": "lure.allow_notifications_bait", "op": "eq", "value": True},
            ]
        },
        ["final.url"],
    ),
    # --- cloaking bounce to a decoy (DE-EVA-005) ------------------------------------
    _rule(
        "cloaking_scripted_bounce",
        "medium",
        ["cloaking", "evasion"],
        ["T1497", "T1036"],
        "A script bounced the top-level page to a decoy (about:blank, a 404, a big brand "
        "homepage) on a young, free-hosted or obfuscated submitted site.",
        {
            "all": [
                {"fact": "navigation.scripted_bounce", "op": "gt", "value": 0},
                {
                    "any": [
                        {"fact": "domains.chain_youngest_age_days", "op": "lt", "value": 90},
                        {"fact": "final.free_hosting", "op": "exists", "value": True},
                        {"fact": "scripts.max_obfuscation_score", "op": "gte", "value": 3},
                    ]
                },
            ]
        },
        ["navigation.scripted_bounces", "final.url"],
    ),
    # --- trusted redirector wrapper + a lure (DE-PHI-010, booster) ------------------
    _rule(
        "trusted_redirector_to_lure",
        "medium",
        ["redirector-abuse", "phishing"],
        ["T1566.002", "T1204.001"],
        "A trusted redirector / open redirect (Google AMP, ad click, Safe Links, a URL "
        "shortener) was in the chain and the run also tripped a phishing/ClickFix/download "
        "signal.",
        {
            "all": [
                {"fact": "network.trusted_redirectors", "op": "exists", "value": True},
                {
                    "any": [
                        {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                        {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                        {"fact": "downloads.unprompted_risky", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["network.trusted_redirectors", "final.url"],
    ),
    # --- CAPTCHA-gated credential page (DE-PHI-011, booster) ------------------------
    _rule(
        "captcha_gated_credential_page",
        "medium",
        ["phishing", "evasion"],
        ["T1497", "T1566.002"],
        "A CAPTCHA/Turnstile gate preceded a credential prompt on a non-allowlisted host: "
        "antibot gating used to keep crawlers off the harvester.",
        {
            "all": [
                {"fact": "capture.gated", "op": "eq", "value": True},
                {
                    "any": [
                        {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                        {"fact": "idp.ms_clone_pages", "op": "gt", "value": 0},
                        {"fact": "forms.password_forms", "op": "gt", "value": 0},
                    ]
                },
                {"not": {"fact": "final.allowlisted", "op": "eq", "value": True}},
            ]
        },
        ["final.url"],
    ),
    # --- DevTools / context-menu blocking (DE-EVA-001, booster) ---------------------
    _rule(
        "devtools_blocking",
        "medium",
        ["evasion", "anti-analysis"],
        ["T1622", "T1497"],
        "The page cancelled DevTools shortcuts (F12, Ctrl+U, Ctrl+Shift+I/J/C) or the "
        "context menu while also showing a credential, ClickFix or download lure.",
        {
            "all": [
                {
                    "any": [
                        {"fact": "evasion.devtools_blocked", "op": "gt", "value": 0},
                        {"fact": "evasion.context_menu_blocked", "op": "eq", "value": True},
                    ]
                },
                {
                    "any": [
                        {"fact": "brand.credential_prompt", "op": "eq", "value": True},
                        {"fact": "clipboard.command_like", "op": "gt", "value": 0},
                        {"fact": "downloads.unprompted_risky", "op": "gt", "value": 0},
                    ]
                },
            ]
        },
        ["evasion.devtools_blocked_keys", "final.url"],
    ),
    # --- crypto wallet drainer (DE-W3B-005), only fires when the fake wallet provider
    # is enabled and records signing requests (off by default, see config flags) ------
    _rule(
        "wallet_drainer_signature",
        "high",
        ["crypto", "wallet-drainer"],
        ["T1657", "T1566.002"],
        "A page asked the (instrumented) wallet to sign a Permit/approval or an unlimited "
        "token approval right after connect, on a non-allowlisted domain: a drainer.",
        {
            "all": [
                {"fact": "web3.wallet_drainer", "op": "gt", "value": 0},
                {"not": {"fact": "final.allowlisted", "op": "eq", "value": True}},
            ]
        },
        ["web3.wallet_requests", "final.url"],
    ),
]

# Starter YARA set for web content (DOM snapshots, scripts, downloads). Severity and
# ATT&CK ids come from each rule's meta block.
BUILTIN_YARA = {
    "clickfix_powershell_lure": r"""
rule clickfix_powershell_lure : clickfix
{
    meta:
        description = "Fake verification page: paste a command into the Run dialog or a terminal"
        severity = "critical"
        mitre_attack = "T1204.004"
    strings:
        $run1 = /Win(dows)?\s{0,3}(key\s{0,3}|logo\s{0,3})?\+\s{0,3}R\b/ nocase
        $run2 = { E2 8A 9E }
        $run3 = /open\s{1,3}(the\s{1,3})?(run\s{1,3}dialog|terminal|powershell)/ nocase
        $paste = /\b(ctrl|cmd)\s{0,3}\+\s{0,3}v\b/ nocase
        $cmd1 = "powershell" nocase fullword
        $cmd2 = "mshta" nocase fullword
        $cmd3 = /\b(iex|iwr|irm)\b/ nocase
        $cmd4 = /\b(curl|wget)\b[^\n|]{1,200}\|\s{0,3}(ba|z)?sh\b/ nocase
        $cmd5 = "clipboard.writeText"
        $cmd6 = /execCommand\s{0,3}\(\s{0,3}["']copy["']/
        $lure1 = /not\s{1,3}a\s{1,3}robot/ nocase
        $lure2 = /verif(y|ication)[^\n]{0,40}(human|robot|captcha|steps?)/ nocase
        $lure3 = "captcha" nocase
        $lure4 = "Ray ID" nocase
    condition:
        1 of ($run*) and $paste and 1 of ($cmd*) and 1 of ($lure*)
}
""",
    "js_eval_decoded_payload": r"""
rule js_eval_decoded_payload : obfuscation
{
    meta:
        description = "JavaScript evaluating a decoded string"
        severity = "medium"
        mitre_attack = "T1027"
    strings:
        $a = /eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(/ nocase
        $b = /new\s+Function\s*\(\s*(atob|unescape)\s*\(/ nocase
        $c = "eval(function(p,a,c,k,e," nocase
    condition:
        any of them
}
""",
    "phishkit_credential_exfil": r"""
rule phishkit_credential_exfil : phishing
{
    meta:
        description = "Phishing-kit exfiltration to a Telegram bot or Discord webhook"
        severity = "high"
        mitre_attack = "T1056.003 T1567"
    strings:
        $tg_token = /api\.telegram\.org\/bot\d{6,12}:[A-Za-z0-9_-]{30,}/
        $tg_api = "api.telegram.org/bot" nocase
        $tg_send = "sendMessage"
        $tg_chat = "chat_id"
        $discord = /discord(app)?\.com\/api\/webhooks\/\d{15,22}\//
    condition:
        $tg_token or $discord or ($tg_api and ($tg_send or $tg_chat))
}
""",
    "html_smuggling_blob_download": r"""
rule html_smuggling_blob_download : malware_download
{
    meta:
        description = "HTML smuggling: Blob of an embedded payload or risky file, auto-clicked"
        severity = "high"
        mitre_attack = "T1027.006"
    strings:
        $blob = /new\s{0,3}Blob\s{0,3}\(/
        $url = "createObjectURL"
        $dl = /(\.download\s{0,3}=|setAttribute\s{0,3}\(\s{0,3}["']download["'])/
        $click = /(\.click\s{0,3}\(\s{0,3}\)|dispatchEvent\s{0,3}\()/
        $risky1 = /download["']?\s{0,3}[=,]\s{0,3}["'][^"'\n]{1,120}\.(exe|scr|msi|msix|appx|dll|cpl)["']/ nocase
        $risky2 = /download["']?\s{0,3}[=,]\s{0,3}["'][^"'\n]{1,120}\.(js|jse|vbs|vbe|wsf|hta|bat|cmd|ps1)["']/ nocase
        $risky3 = /download["']?\s{0,3}[=,]\s{0,3}["'][^"'\n]{1,120}\.(lnk|iso|img|vhdx?|zip|rar|7z|one)["']/ nocase
        // A base64 literal of 1000+ characters (YARA caps how long a regex match can be).
        $b64 = /["'][A-Za-z0-9+\/]{1000}/
        $dec1 = /atob\s{0,3}\(/
        $dec2 = /charCodeAt\s{0,3}\(/
    condition:
        $blob and $url and $dl and $click and (1 of ($risky*) or ($b64 and 1 of ($dec*)))
}
""",
    "bip39_wordlist_embedded": r"""
rule bip39_wordlist_embedded : crypto
{
    meta:
        description = "Page or script embeds the BIP39 seed-phrase word list, used by wallet drainers to validate stolen recovery phrases"
        severity = "medium"
        mitre_attack = "T1056.003"
    strings:
        $start = /abandon["',\s]{1,6}ability["',\s]{1,6}able["',\s]{1,6}about["',\s]{1,6}above/
        $end = /zero["',\s]{1,6}zone["',\s]{1,6}zoo/
    condition:
        $start and $end
}
""",
    "hta_application": r"""
rule hta_application : malware_download
{
    meta:
        description = "HTML Application (HTA), which mshta runs outside the browser sandbox"
        severity = "high"
        mitre_attack = "T1218.005"
    strings:
        $hta = "<hta:application" nocase
    condition:
        $hta
}
""",
    "tycoon2fa_web": r"""
rule tycoon2fa_web : phishing aitm
{
    meta:
        description = "Tycoon 2FA AiTM phishing kit fingerprint (relay handlers, autofill helpers, hardcoded CryptoJS key)"
        severity = "critical"
        mitre_attack = "T1557 T1566.002 T1027"
    strings:
        $relay1 = "recieveid" nocase
        $relay2 = "send_to_browser" nocase
        $relay3 = "response_from_browser" nocase
        $auto1 = "emailsectionelecheck" nocase
        $auto2 = "tryfindingele" nocase
        $auto3 = ".btn-blue-next-btn" nocase
        $kit1 = "twofaselected" nocase
        $key = "1234567890123456"
        $crypto = "CryptoJS" nocase
        $randexp = "randexp" nocase
        $checkpass = "checkpass" nocase
    condition:
        2 of ($relay*, $auto*, $kit1)
        or ($key and $crypto)
        or ($randexp and $checkpass)
}
""",
    "crypto_decrypt_then_write": r"""
rule crypto_decrypt_then_write : obfuscation
{
    meta:
        description = "Client-side CryptoJS/SubtleCrypto decrypt whose output is written into the document (encrypted page delivery)"
        severity = "high"
        mitre_attack = "T1027 T1140"
    strings:
        $dec1 = /CryptoJS\.(AES|DES|TripleDES|RC4|Rabbit)\.decrypt/ nocase
        $dec2 = "crypto.subtle.decrypt" nocase
        $sink1 = /document\.write(ln)?\s{0,3}\(/ nocase
        $sink2 = /\.(inner|outer)HTML\s{0,3}=/ nocase
        $sink3 = "decodeURIComponent" nocase
        $sink4 = /\.srcdoc\s{0,3}=/ nocase
        // a single long base64 run (YARA caps match length; use a fixed prefix)
        $b64 = /["'][A-Za-z0-9+\/]{1000}/
    condition:
        1 of ($dec*) and 1 of ($sink*) and $b64
}
""",
    "windows_executable": r"""
rule windows_executable : executable
{
    meta:
        description = "Windows PE executable"
        severity = "medium"
    condition:
        uint16(0) == 0x5A4D and uint32(0x3C) < filesize and uint32(uint32(0x3C)) == 0x00004550
}
""",
}

# ANA-7 weights. Rule names and "severity:<level>" fall-backs; "indicator" scales feed hits.
DEFAULT_WEIGHTS = {
    "severity:info": 0,
    "severity:low": 10,
    "severity:medium": 25,
    "severity:high": 45,
    "severity:critical": 75,
    "indicator": 60,
    "suricata:alert": 20,
    "clickfix_clipboard_command": 80,
    "form_posts_cross_domain": 50,
    "seed_phrase_harvest": 60,
    "telegram_bot_exfil": 80,
    "discord_webhook_exfil": 65,
    "ms_signin_clone_foreign_host": 60,
    "idp_cdn_assets_foreign_page": 45,
    "aitm_ms_paths_foreign_host": 80,
    "oauth_error_redirect_abuse": 55,
    "illicit_consent_grant": 50,
    "consentfix_authcode_paste_back": 75,
    "firstparty_app_loopback_authorize": 30,
    "device_code_phishing_lure": 55,
    "device_code_handoff": 30,
    "cache_smuggled_payload": 55,
    "protocol_handler_lure": 50,
    "protocol_handler_attempt": 30,
    "clipboard_command_tampering": 25,
    "mislabeled_image_payload": 30,
    "ms_session_cookie_foreign_host": 80,
    "web3_rpc_from_non_wallet_page": 55,
    "etherhiding_payload_executed": 80,
    "web3_known_malicious_contract": 60,
    "fake_captcha_clipboard_command": 80,
    "filefix_command_disguised_as_path": 80,
    "fake_browser_update": 70,
    "crashfix_repair_lure": 55,
    "smuggled_credential_page": 55,
    "ipfs_credential_page": 45,
    "client_side_ip_geo_lookup": 20,
    "credential_relay_websocket": 50,
    "wallet_drainer_signature": 60,
    "devtools_blocking": 20,
    "script_posted_credentials": 50,
    "runtime_dynamic_execution": 25,
    "html_smuggling_binary_blob": 60,
    "risky_archive_contents": 50,
    "password_protected_archive_with_password": 50,
    "tech_support_browser_locker": 60,
    "history_flooding": 20,
    "push_notification_bait": 30,
    "cloaking_scripted_bounce": 30,
    "trusted_redirector_to_lure": 20,
    "captcha_gated_credential_page": 25,
}

# (name, keywords, domains). Keywords match whole words, case-insensitively. A domain
# entry covers the domain and all subdomains; a bare label ("google") is a brand
# top-level domain (doodles.google); "label.*" is the label under any country-code
# suffix (google.de, amazon.co.jp). See sandbox.analysis.domains.normalise_brand_domain.
DEFAULT_BRANDS = [
    (
        "Microsoft",
        ["microsoft", "office 365", "outlook", "onedrive", "sharepoint", "office365"],
        [
            "microsoft",
            "microsoft.com",
            "live.com",
            "live.net",
            "office.com",
            "office.net",
            "microsoftonline.com",
            "outlook.com",
            "sharepoint.com",
            "office365.com",
            "windows.net",
            "windows.com",
            "msauth.net",
            "msftauth.net",
            "msn.com",
            "bing.com",
            "azure.com",
            "skype.com",
            "xbox.com",
            "microsoft.us",
            "microsoft.*",
        ],
    ),
    (
        "Google",
        ["google", "gmail"],
        [
            "google",
            "google.com",
            "google.*",
            "gmail.com",
            "googleusercontent.com",
            "gstatic.com",
            "googleapis.com",
            "googlevideo.com",
            "youtube.com",
            "youtu.be",
            "ggpht.com",
            "withgoogle.com",
            "android.com",
            "chrome.com",
            "blogger.com",
            "goo.gl",
            "g.co",
        ],
    ),
    (
        "Apple",
        ["apple id", "apple account", "icloud"],
        ["apple", "apple.com", "icloud.com", "me.com", "mzstatic.com", "cdn-apple.com"],
    ),
    ("PayPal", ["paypal"], ["paypal.com", "paypal.me", "paypalobjects.com", "paypal.*"]),
    (
        "Amazon",
        ["amazon"],
        [
            "amazon",
            "amazon.com",
            "amazon.*",
            "media-amazon.com",
            "ssl-images-amazon.com",
            "amazontrust.com",
            "a2z.com",
            "primevideo.com",
        ],
    ),
    ("DHL", ["dhl"], ["dhl", "dhl.com", "dhl.*"]),
    ("Netflix", ["netflix"], ["netflix", "netflix.com", "netflix.net", "nflxext.com"]),
    (
        "Meta",
        ["facebook", "instagram", "whatsapp"],
        [
            "facebook.com",
            "facebook.net",
            "fb.com",
            "fb.me",
            "fbcdn.net",
            "instagram.com",
            "cdninstagram.com",
            "whatsapp.com",
            "whatsapp.net",
            "meta.com",
            "messenger.com",
            "threads.net",
        ],
    ),
    ("LinkedIn", ["linkedin"], ["linkedin", "linkedin.com", "licdn.com", "lnkd.in"]),
    ("DocuSign", ["docusign"], ["docusign.com", "docusign.net"]),
    ("Adobe", ["adobe", "acrobat"], ["adobe.com", "adobelogin.com", "adobe.io", "typekit.net"]),
    ("Dropbox", ["dropbox"], ["dropbox.com", "dropboxstatic.com"]),
    ("Wells Fargo", ["wells fargo"], ["wellsfargo.com"]),
    ("Chase", ["chase bank", "jpmorgan chase"], ["chase", "chase.com", "jpmorganchase.com"]),
    ("Bank of America", ["bank of america"], ["bankofamerica.com", "bofa.com"]),
    # --- delivery and messaging: the most impersonated in SMS phishing -----------------
    ("USPS", ["usps", "postal service"], ["usps.com"]),
    ("FedEx", ["fedex"], ["fedex.com"]),
    ("UPS", ["ups tracking", "united parcel service", "acronym:UPS"], ["ups.com"]),
    ("Aramex", ["aramex", "أرامكس"], ["aramex.com"]),
    ("SMSA Express", ["smsa express", "smsa", "سمسا"], ["smsaexpress.com"]),
    ("Naqel Express", ["naqel", "ناقل إكسبرس", "ناقل اكسبرس"], ["naqelexpress.com"]),
    ("Telegram", ["telegram", "تيليجرام"], ["telegram", "telegram.org", "t.me", "telegram.me"]),
    ("Snapchat", ["snapchat", "سناب شات"], ["snapchat.com", "snap.com", "sc-cdn.net"]),
    ("TikTok", ["tiktok", "تيك توك"], ["tiktok.com", "tiktokcdn.com", "tiktokv.com"]),
    ("X (Twitter)", ["twitter"], ["twitter.com", "x.com", "twimg.com", "t.co"]),
    ("Yahoo", ["yahoo"], ["yahoo.com", "yahoo.*", "yimg.com"]),
    # --- crypto wallets and exchanges: SEO-spam and drainer targets ---------------------
    ("Trezor", ["trezor"], ["trezor.io"]),
    ("Ledger", ["ledger live", "ledger wallet", "ledger nano"], ["ledger.com"]),
    ("MetaMask", ["metamask"], ["metamask.io"]),
    ("Coinbase", ["coinbase"], ["coinbase.com"]),
    ("Binance", ["binance"], ["binance.com", "binance.us", "bnbchain.org"]),
    ("Trust Wallet", ["trust wallet", "trustwallet"], ["trustwallet.com"]),
    ("Exodus", ["exodus wallet"], ["exodus.com"]),
    ("Phantom", ["phantom wallet"], ["phantom.app"]),
    # --- Saudi Arabia: government. Every entry owns all of gov.sa, which only government
    # bodies can register, so one government site referencing another is never flagged.
    ("Absher", ["absher", "أبشر"], ["absher.sa", "gov.sa"]),
    ("Nafath", ["nafath", "النفاذ الوطني الموحد", "النفاذ الوطني"], ["gov.sa"]),
    ("Tawakkalna", ["tawakkalna", "توكلنا"], ["gov.sa"]),
    (
        "ZATCA (Zakat, Tax and Customs)",
        ["zatca", "saudi customs", "هيئة الزكاة والضريبة والجمارك", "الجمارك السعودية"],
        ["gov.sa"],
    ),
    (
        "Ministry of Interior (MOI / Traffic)",
        ["ministry of interior", "وزارة الداخلية", "الإدارة العامة للمرور", "muroor"],
        ["gov.sa"],
    ),
    ("Saudi National Portal", ["my.gov.sa", "المنصة الوطنية الموحدة"], ["gov.sa"]),
    ("Najiz (Ministry of Justice)", ["najiz", "ناجز", "وزارة العدل"], ["najiz.sa", "gov.sa"]),
    ("Qiwa", ["qiwa", "منصة قوى"], ["qiwa.sa", "gov.sa"]),
    ("GOSI", ["gosi", "التأمينات الاجتماعية"], ["gov.sa"]),
    ("Musaned", ["musaned", "منصة مساند"], ["musaned.com.sa", "gov.sa"]),
    ("Nusuk (Hajj and Umrah)", ["nusuk", "منصة نسك", "تطبيق نسك"], ["nusuk.sa", "gov.sa"]),
    ("Sehhaty", ["sehhaty", "تطبيق صحتي", "وزارة الصحة"], ["gov.sa"]),
    ("Etimad", ["etimad", "منصة اعتماد"], ["etimad.sa", "gov.sa"]),
    ("Saudi Central Bank (SAMA)", ["saudi central bank", "البنك المركزي السعودي"], ["gov.sa"]),
    (
        "Ministry of Commerce",
        [
            "ministry of commerce",
            "وزارة التجارة",
            "saudi business center",
            "المركز السعودي للأعمال",
        ],
        ["gov.sa"],
    ),
    # --- Saudi Arabia: post, payments, banks, telecoms, travel --------------------------
    (
        "Saudi Post (SPL)",
        ["saudi post", "splonline", "spl logistics", "البريد السعودي", "سبل للخدمات اللوجستية"],
        ["splonline.com.sa"],
    ),
    ("SADAD", ["sadad", "نظام سداد", "مدفوعات سداد"], ["sadad.com"]),
    ("mada", ["mada pay", "بطاقة مدى", "مدى باي"], ["mada.com.sa"]),
    (
        "Al Rajhi Bank",
        ["al rajhi", "alrajhi", "الراجحي"],
        ["alrajhibank.com.sa", "alrajhibank.com"],
    ),
    (
        "Saudi National Bank (SNB)",
        ["saudi national bank", "alahli", "البنك الأهلي"],
        ["alahli.com"],
    ),
    ("Riyad Bank", ["riyad bank", "riyadbank", "بنك الرياض"], ["riyadbank.com"]),
    ("SAB (Saudi Awwal Bank)", ["saudi awwal bank", "البنك السعودي الأول"], ["sab.com"]),
    ("Alinma Bank", ["alinma", "مصرف الإنماء", "مصرف الانماء"], ["alinma.com"]),
    ("Bank Albilad", ["bank albilad", "albilad", "بنك البلاد"], ["bankalbilad.com"]),
    (
        "Banque Saudi Fransi",
        ["saudi fransi", "alfransi", "البنك السعودي الفرنسي"],
        ["alfransi.com.sa"],
    ),
    ("Arab National Bank", ["arab national bank", "البنك العربي الوطني"], ["anb.com.sa"]),
    ("STC Bank / STC Pay", ["stc bank", "stc pay", "stcpay"], ["stcbank.com.sa", "stcpay.com.sa"]),
    ("STC", ["mystc", "stc", "اس تي سي"], ["stc.com.sa", "stc.sa"]),
    ("Mobily", ["mobily", "موبايلي"], ["mobily.com.sa"]),
    ("Zain KSA", ["zain ksa", "زين السعودية"], ["sa.zain.com", "zain.com"]),
    (
        "Saudia",
        ["saudia airlines", "الخطوط السعودية", "الخطوط الجوية العربية السعودية"],
        ["saudia.com"],
    ),
]

# FED-1 feeds. Check each feed's current terms and key requirements before enabling in
# production; abuse.ch services may require a free Auth-Key.
DEFAULT_FEEDS = [
    {
        "name": "urlhaus",
        "kind": "indicators",
        "parser": "urlhaus_csv",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "schedule_s": 3600,
        "default_confidence": 80,
        "ttl_days": 30,
        "enabled": True,
        "licence_note": "abuse.ch URLhaus, CC0. May require an abuse.ch Auth-Key.",
    },
    {
        "name": "threatfox",
        "kind": "indicators",
        "parser": "threatfox_json",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "schedule_s": 3600,
        "default_confidence": 75,
        "ttl_days": 30,
        "enabled": True,
        "licence_note": "abuse.ch ThreatFox, CC0. May require an abuse.ch Auth-Key.",
    },
    {
        "name": "openphish",
        "kind": "indicators",
        "parser": "plain_urls",
        "url": "https://openphish.com/feed.txt",
        "schedule_s": 43200,
        "default_confidence": 80,
        "ttl_days": 7,
        "enabled": True,
        "licence_note": "OpenPhish community feed: non-commercial use; check current terms.",
    },
    {
        "name": "phishing_database",
        "kind": "indicators",
        "parser": "plain_domains",
        "url": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
        "phishing-domains-ACTIVE.txt",
        "schedule_s": 86400,
        "default_confidence": 60,
        "ttl_days": 7,
        "enabled": True,
        "licence_note": "Phishing.Database, MIT licence.",
    },
    {
        "name": "malwarebazaar",
        "kind": "indicators",
        "parser": "malwarebazaar_csv",
        "url": "https://bazaar.abuse.ch/export/csv/recent/",
        "schedule_s": 3600,
        "default_confidence": 85,
        "ttl_days": 90,
        "enabled": True,
        "licence_note": "abuse.ch MalwareBazaar, CC0. May require an abuse.ch Auth-Key.",
    },
    {
        "name": "phishtank",
        "kind": "indicators",
        "parser": "phishtank_json",
        "url": "http://data.phishtank.com/data/{key}/online-valid.json",
        "schedule_s": 21600,
        "default_confidence": 80,
        "ttl_days": 7,
        "enabled": False,
        "licence_note": "PhishTank: needs an application key; registration may be closed.",
    },
    {
        "name": "tranco",
        "kind": "allowlist",
        "parser": "tranco_csv",
        "url": "https://tranco-list.eu/top-1m.csv.zip",
        "schedule_s": 7 * 86400,
        "default_confidence": 0,
        "ttl_days": 30,
        "enabled": True,
        "licence_note": "Tranco research ranking; top 10,000 kept as allowlist.",
    },
    {
        "name": "mitre_attack",
        "kind": "attack",
        "parser": "attack_stix",
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/"
        "enterprise-attack.json",
        "schedule_s": 7 * 86400,
        "default_confidence": 0,
        "ttl_days": 365,
        "enabled": True,
        "licence_note": "MITRE ATT&CK, terms of use at attack.mitre.org.",
    },
    {
        "name": "et_open",
        "kind": "suricata",
        "parser": "rule_archive",
        "url": "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
        "schedule_s": 86400,
        "default_confidence": 0,
        "ttl_days": 365,
        "enabled": True,
        "licence_note": "Emerging Threats Open, GPLv2 / BSD; see rules.emergingthreats.net.",
    },
    {
        "name": "signature_base",
        "kind": "yara",
        "parser": "rule_archive",
        "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        "schedule_s": 86400,
        "default_confidence": 0,
        "ttl_days": 365,
        "enabled": False,
        "licence_note": "Detection Rule License 1.1; mostly file and memory rules.",
    },
]
