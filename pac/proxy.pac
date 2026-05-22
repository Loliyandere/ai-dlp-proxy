function FindProxyForURL(url, host) {
    var proxy = "PROXY 192.168.218.150:8080";

    host = host.toLowerCase();

    // ChatGPT / OpenAI web
    if (
        dnsDomainIs(host, "chatgpt.com") ||
        dnsDomainIs(host, "chat.openai.com") ||
        dnsDomainIs(host, "auth.openai.com")
    ) {
        return proxy;
    }

    // Gemini
    if (
        dnsDomainIs(host, "gemini.google.com") ||
        dnsDomainIs(host, "bard.google.com")
    ) {
        return proxy;
    }

    // Claude
    if (
        dnsDomainIs(host, "claude.ai")
    ) {
        return proxy;
    }

    // Perplexity
    if (
        dnsDomainIs(host, "perplexity.ai")
    ) {
        return proxy;
    }

    // Microsoft Copilot
    if (
        dnsDomainIs(host, "copilot.microsoft.com")
    ) {
        return proxy;
    }

    //deep seek
    if (
        dnsDomainIs(host, "deepseek.com")||
        dnsDomainIs(host,"chat.deepseek.com")
    ) {
        return proxy;
    }
    if (
        dnsDomainIs(host, "mitm.it")
    ) {
        return proxy;
    }

    return "DIRECT";
}