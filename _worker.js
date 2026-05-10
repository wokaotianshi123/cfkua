// _workerkua.js

// 限制配置
const UNSAFE_RESPONSE_HEADERS = new Set(["content-security-policy", "content-security-policy-report-only", "x-frame-options", "x-xss-protection", "x-content-type-options"]);
const STRIP_REQUEST_HEADERS = new Set(["cf-connecting-ip", "x-forwarded-for", "x-real-ip", "client-ip", "x-forwarded-proto", "via", "forwarded", "x-client-ip"]);

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 1. 豆瓣图片代理功能 (高性能缓存)
        if (url.pathname === '/proxy') {
            const targetUrl = url.searchParams.get('url');
            if (targetUrl && targetUrl.includes('doubanio.com')) {
                const cache = caches.default;
                let response = await cache.match(request);
                if (!response) {
                    const imageRes = await fetch(targetUrl, {
                        headers: {
                            'Referer': 'https://movie.douban.com/',
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
                        }
                    });
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

        // 2. 主页面 (HTML Proxy 入口)
        if (url.pathname === "/") {
            return new Response(getRootHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
        }

        // 3. HTML/Proxy 逻辑
        let path = url.pathname.slice(1);
        try { path = decodeURIComponent(path); } catch (e) {}

        let actualUrlStr = (path.startsWith("http") ? path : "https://" + path) + url.search + url.hash;

        if (request.method === "OPTIONS") {
            return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*", "Access-Control-Allow-Headers": "*" } });
        }

        const targetUrl = new URL(actualUrlStr);
        const newHeaders = new Headers();
        for (const [key, value] of request.headers) {
            const lowerKey = key.toLowerCase();
            if (lowerKey.startsWith("cf-") || lowerKey.startsWith("sec-") || lowerKey === "cookie" || STRIP_REQUEST_HEADERS.has(lowerKey)) continue;
            newHeaders.set(key, value);
        }
        newHeaders.set("Host", targetUrl.host);

        let response = await fetch(actualUrlStr, { method: request.method, headers: newHeaders, body: request.body, redirect: "manual" });

        const responseHeaders = new Headers(response.headers);
        UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
        responseHeaders.set("Access-Control-Allow-Origin", "*");

        const contentType = responseHeaders.get("Content-Type") || "";

        // M3U8 处理 (修复流媒体播放)
        if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
            const text = await response.text();
            // 使用更稳健的baseUrl计算方式
            const baseUrl = targetUrl.origin + targetUrl.pathname.substring(0, targetUrl.pathname.lastIndexOf("/") + 1);
            const newText = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
                const urlObj = new URL(match.trim(), baseUrl);
                return url.origin + "/" + urlObj.href;
            });
            return new Response(newText, { headers: responseHeaders });
        }

        // HTML 内容重写 (使用内置 HTMLRewriter)
        if (contentType.includes("text/html")) {
            const rewriter = new HTMLRewriter()
                .on("a, link, script, img, iframe, form, source, video, audio, object, base", new AttrRewriter(url.origin, targetUrl.href));
            return rewriter.transform(new Response(response.body, { headers: responseHeaders }));
        }

        return new Response(response.body, { headers: responseHeaders });
    }
};

/** 助手类与函数 **/
class AttrRewriter {
    constructor(proxy, target) { this.proxy = proxy; this.target = target; }
    element(el) {
        const attr = el.tagName === 'form' ? 'action' : (el.tagName === 'link' || el.tagName === 'a' || el.tagName === 'base' ? 'href' : 'src');
        const val = el.getAttribute(attr);
        if (val && !val.match(/^(data|#|javascript):/)) {
            try { el.setAttribute(attr, this.proxy + "/" + new URL(val, this.target).href); } catch (e) {}
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html><html><body><div style="text-align:center;padding:50px;">
    <h2>Secure Proxy</h2><form onsubmit="event.preventDefault();window.open(location.origin+'/'+encodeURIComponent(document.getElementById('u').value),'_blank')">
    <input type="text" id="u" placeholder="输入网址" style="width:300px;padding:10px;">
    <button type="submit">Go</button></form></div></body></html>`;
}
