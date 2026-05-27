function FindProxyForURL(url, host) {
    var proxy = "PROXY 192.168.218.150:8080";

    host = host.toLowerCase();

    // ── ChatGPT / OpenAI ──────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "chatgpt.com")        ||
        dnsDomainIs(host, "chat.openai.com")    ||
        dnsDomainIs(host, "auth.openai.com")    ||
        dnsDomainIs(host, "openai.com")
    ) {
        return proxy;
    }

    // ChatGPT file storage — actual file bytes are PUT here (Azure CDN)
    // e.g. sdmntprkoreacentral.oaiusercontent.com, files.oaiusercontent.com
    if (dnsDomainIs(host, "oaiusercontent.com")) {
        return proxy;
    }

    // ── Claude / Anthropic ────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "claude.ai")          ||
        dnsDomainIs(host, "anthropic.com")
    ) {
        return proxy;
    }

    // ── mitmproxy certificate install page ────────────────────────────────────
    if (dnsDomainIs(host, "mitm.it")) {
        return proxy;
    }

    return "DIRECT";
}
