function FindProxyForURL(url, host) {
    var proxy = "PROXY 192.168.218.150:8080";

    host = host.toLowerCase();

    // ── ChatGPT / OpenAI ──────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "chatgpt.com")           ||
        dnsDomainIs(host, "chat.openai.com")        ||
        dnsDomainIs(host, "auth.openai.com")        ||
        dnsDomainIs(host, "openai.com")
    ) {
        return proxy;
    }

    // OpenAI file storage — actual PDF/DOCX bytes are PUT here (Azure CDN)
    // e.g. sdmntprkoreacentral.oaiusercontent.com, files.oaiusercontent.com
    if (dnsDomainIs(host, "oaiusercontent.com")) {
        return proxy;
    }

    // ── Gemini / Google ───────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "gemini.google.com")      ||
        dnsDomainIs(host, "bard.google.com")        ||
        dnsDomainIs(host, "googleapis.com")
    ) {
        return proxy;
    }

    // Google Cloud Storage — Gemini file uploads land here
    if (dnsDomainIs(host, "storage.googleapis.com")) {
        return proxy;
    }

    // ── Claude / Anthropic ────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "claude.ai")              ||
        dnsDomainIs(host, "anthropic.com")
    ) {
        return proxy;
    }

    // ── Perplexity ────────────────────────────────────────────────────────────
    if (dnsDomainIs(host, "perplexity.ai")) {
        return proxy;
    }

    // ── Microsoft Copilot ─────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "copilot.microsoft.com")  ||
        dnsDomainIs(host, "bing.com")               ||
        dnsDomainIs(host, "edgeservices.bing.com")
    ) {
        return proxy;
    }

    // ── DeepSeek ──────────────────────────────────────────────────────────────
    if (
        dnsDomainIs(host, "deepseek.com")           ||
        dnsDomainIs(host, "chat.deepseek.com")
    ) {
        return proxy;
    }

    // ── mitmproxy cert install page ───────────────────────────────────────────
    if (dnsDomainIs(host, "mitm.it")) {
        return proxy;
    }

    return "DIRECT";
}
