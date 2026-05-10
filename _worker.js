/**
 * _workerkua.js
 * 融合了通用网页代理与豆瓣图片代理
 */

// --- 通用代理的常量定义 ---
const UNSAFE_RESPONSE_HEADERS = new Set([
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options"
]);

const STRIP_REQUEST_HEADERS = new Set([
    "cf-connecting-ip",
    "x-forwarded-for",
    "x-real-ip",
    "client-ip",
    "x-forwarded-proto",
    "via",
    "forwarded",
    "x-client-ip"
]);

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 1. 豆瓣图片代理优先处理 (/proxy)
        if (url.pathname === '/proxy') {
            return await handleDoubanProxy(request, env, ctx);
        }

        // 2. 访问根目录返回通用 UI
        if (url.pathname === "/") {
            return new Response(getRootHtml(), {
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });
        }

        // 3. 通用网页代理处理
        return await handleGeneralProxy(request, url, env);
    }
};

// --- 功能模块 1: 豆瓣图片性能代理 ---
async function handleDoubanProxy(request, env, ctx) {
    const url = new URL(request.url);
    const targetUrl = url.searchParams.get('url');

    if (!targetUrl) {
        return new Response('Missing "url" parameter', { status: 400 });
    }

    if (!targetUrl.includes('doubanio.com')) {
        return new Response('Forbidden: Only Douban images are allowed', { status: 403 });
    }

    const cache = caches.default;
    let response = await cache.match(request);

    if (!response) {
        const doubanHeaders = new Headers();
        doubanHeaders.set('Referer', 'https://movie.douban.com/');
        doubanHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36');

        const imageRes = await fetch(targetUrl, { headers: doubanHeaders });

        if (!imageRes.ok) {
            return new Response('Failed to fetch from source', { status: imageRes.status });
        }

        const newHeaders = new Headers(imageRes.headers);
        newHeaders.set('Access-Control-Allow-Origin', '*');
        // 激进缓存：边缘 30 天，浏览器 7 天
        newHeaders.set('Cache-Control', 'public, s-maxage=2592000, max-age=604800');
        newHeaders.delete('Set-Cookie');

        response = new Response(imageRes.body, { status: imageRes.status, headers: newHeaders });
        ctx.waitUntil(cache.put(request, response.clone()));
    }
    return response;
}

// --- 功能模块 2: 通用网页代理 ---
async function handleGeneralProxy(request, url, env) {
    let path = url.pathname.slice(1);
    try { path = decodeURIComponent(path); } catch (e) {}
    
    let actualUrlStr = path + url.search + url.hash;
    if (actualUrlStr.startsWith("http") && !/^https?:\/\//.test(actualUrlStr)) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    if (request.method === "OPTIONS") {
        return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "*" } });
    }

    let targetUrl;
    try {
        targetUrl = new URL(actualUrlStr);
    } catch (e) {
        // 如果是 Pages 且无法解析 URL，尝试访问静态资源
        if (env.ASSETS) return env.ASSETS.fetch(request);
        return new Response("Invalid URL", { status: 400 });
    }

    const newHeaders = new Headers();
    for (const [key, value] of request.headers) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith("cf-") || lowerKey.startsWith("sec-") || lowerKey === "cookie" || STRIP_REQUEST_HEADERS.has(lowerKey)) continue;
        newHeaders.set(key, value);
    }
    if (!newHeaders.has("User-Agent")) newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
    newHeaders.set("Host", targetUrl.host);

    let response = await fetch(targetUrl.href, { method: request.method, headers: newHeaders, body: request.body, redirect: "manual" });
    const responseHeaders = new Headers(response.headers);
    UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    const contentType = responseHeaders.get("Content-Type") || "";
    
    // HTML 处理
    if (contentType.includes("text/html")) {
        const rewriter = new HTMLRewriter()
            .on("head", { element(e) { e.append(`<script>(function(){${getInjectJs(targetUrl.href)}})();</script>`, { html: true }); } })
            .on("a", new AttrRewriter("href", url.origin, targetUrl.href))
            .on("img", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("link", new AttrRewriter("href", url.origin, targetUrl.href))
            .on("script", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("form", new AttrRewriter("action", url.origin, targetUrl.href));

        return rewriter.transform(new Response(response.body, { status: response.status, headers: responseHeaders }));
    }

    return new Response(response.body, { status: response.status, headers: responseHeaders });
}

// --- 辅助工具 ---
function getInjectJs(targetBase) {
    return `const P=window.location.origin, B='${targetBase}';
    function W(u){if(!u||u.startsWith(P)||u.match(/^(data|blob|javascript):/))return u;
    try{return P+'/'+new URL(u,B).href}catch(e){return u}}
    const F=window.fetch; window.fetch=function(i,n){return F(typeof i==='string'?W(i):i,n)};`;
}

class AttrRewriter {
    constructor(attr, proxy, target) { this.attr = attr; this.proxy = proxy; this.target = target; }
    element(el) {
        const val = el.getAttribute(this.attr);
        if (val && !val.match(/^(data|#|javascript):/)) {
            try { el.setAttribute(this.attr, this.proxy + "/" + new URL(val, this.target).href); } catch (e) {}
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>Secure Proxy</title></head><body>
    <form onsubmit="event.preventDefault();location.href='/'+encodeURIComponent(document.getElementById('u').value)">
    <input type="text" id="u" placeholder="输入网址"><button type="submit">跳转</button></form>
    </body></html>`;
}
