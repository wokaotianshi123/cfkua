// _workerkua.js

// 限制配置
const UNSAFE_RESPONSE_HEADERS = new Set(["content-security-policy", "content-security-policy-report-only", "x-frame-options", "x-xss-protection", "x-content-type-options"]);
const STRIP_REQUEST_HEADERS = new Set(["cf-connecting-ip", "x-forwarded-for", "x-real-ip", "client-ip", "x-forwarded-proto", "via", "forwarded", "x-client-ip"]);

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 1. 豆瓣图片代理
        if (url.pathname === '/proxy') {
            const targetUrl = url.searchParams.get('url');
            if (targetUrl && targetUrl.includes('doubanio.com')) {
                const cache = caches.default;
                let response = await cache.match(request);
                if (!response) {
                    const imageRes = await fetch(targetUrl, { headers: { 'Referer': 'https://movie.douban.com/', 'User-Agent': 'Mozilla/5.0' } });
                    if (imageRes.ok) {
                        const newHeaders = new Headers(imageRes.headers);
                        newHeaders.set('Access-Control-Allow-Origin', '*');
                        newHeaders.set('Cache-Control', 'public, s-maxage=2592000, max-age=604800');
                        newHeaders.delete('Set-Cookie');
                        response = new Response(imageRes.body, { status: imageRes.status, headers: newHeaders });
                        ctx.waitUntil(cache.put(request, response.clone()));
                    }
                }
                return response || new Response('Error', { status: 502 });
            }
        }

        // 2. 根目录 UI
        if (url.pathname === "/") {
            return new Response(getRootHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
        }

        // 3. 核心代理逻辑
        let path = url.pathname.slice(1);
        try { path = decodeURIComponent(path); } catch (e) {}
        if (!path) return new Response("Invalid Request", { status: 400 });

        // 规范化目标 URL
        let actualUrlStr = (path.startsWith("http") ? path : "https://" + path) + url.search + url.hash;
        const targetUrl = new URL(actualUrlStr);

        // 请求头清洗
        const newHeaders = new Headers();
        for (const [key, value] of request.headers) {
            const lowerKey = key.toLowerCase();
            if (lowerKey.startsWith("cf-") || lowerKey.startsWith("sec-") || lowerKey === "cookie" || STRIP_REQUEST_HEADERS.has(lowerKey)) continue;
            newHeaders.set(key, value);
        }
        newHeaders.set("Host", targetUrl.host);
        // 关键：强制设置 Referer 以防止 403
        newHeaders.set("Referer", targetUrl.origin + "/");

        let response = await fetch(actualUrlStr, { method: request.method, headers: newHeaders, body: request.body, redirect: "manual" });

        const responseHeaders = new Headers(response.headers);
        UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
        responseHeaders.set("Access-Control-Allow-Origin", "*");

        const contentType = responseHeaders.get("Content-Type") || "";

        // 4. M3U8 流媒体极致兼容处理
        if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
            const text = await response.text();
            const baseUrl = targetUrl.toString().substring(0, targetUrl.toString().lastIndexOf("/") + 1);
            
            // 确保所有的 URL 都被代理，包括 #EXT-X-STREAM-INF 后面的 URL
            const newText = text.replace(/(https?:\/\/[^\s"'()]+|[^#\s"']+\.ts|[^#\s"']+\.m3u8)/g, (match) => {
                const absUrl = new URL(match, baseUrl).href;
                return url.origin + "/" + encodeURIComponent(absUrl);
            });
            return new Response(newText, { headers: responseHeaders });
        }

        // 5. HTML 内容注入 (解决 JS 导航导致跳出代理的问题)
        if (contentType.includes("text/html")) {
            const injectScript = `
            <script>
            (function(){
                const proxyOrigin = window.location.origin;
                // 劫持所有动态请求
                const originalFetch = window.fetch;
                window.fetch = function(u, n) {
                    if (typeof u === 'string' && u.startsWith('http')) return originalFetch(proxyOrigin + '/' + encodeURIComponent(u), n);
                    return originalFetch(u, n);
                };
                // 劫持所有 History API，防止页面路径跳出代理
                const historyPush = window.history.pushState;
                window.history.pushState = function(s, t, url) {
                    console.log('History blocked or proxied', url);
                    return historyPush.apply(this, [s, t, url]);
                };
            })();
            </script>`;

            const rewriter = new HTMLRewriter()
                .on("head", { element(e) { e.append(injectScript, { html: true }); } })
                .on("a, link, script, img, iframe, form, source, video, audio, object, base", new AttrRewriter(url.origin));
            
            return rewriter.transform(new Response(response.body, { headers: responseHeaders }));
        }

        return new Response(response.body, { headers: responseHeaders });
    }
};

class AttrRewriter {
    constructor(proxy) { this.proxy = proxy; }
    element(el) {
        const attr = el.tagName === 'form' ? 'action' : (el.tagName === 'link' || el.tagName === 'a' || el.tagName === 'base' ? 'href' : 'src');
        const val = el.getAttribute(attr);
        if (val && val.startsWith('http')) {
            el.setAttribute(attr, this.proxy + "/" + encodeURIComponent(val));
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html><html><body style="font-family:sans-serif;padding:50px;">
    <h2>Secure Proxy</h2><form onsubmit="event.preventDefault();window.location.href=location.origin+'/'+encodeURIComponent(document.getElementById('u').value)">
    <input type="text" id="u" placeholder="输入网址" style="width:300px;padding:10px;">
    <button type="submit">Go</button></form></body></html>`;
}
