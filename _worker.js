/* ----------------------------------------------------
 * 合并后的 _worker.js
 * 功能: 通用代理 + M3U8处理 + HTML注入 + 豆瓣图片缓存代理
 * ---------------------------------------------------- */

// ==========================================
// 常量定义
// ==========================================
const UNSAFE_RESPONSE_HEADERS = new Set([
    "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "x-xss-protection", "x-content-type-options"
]);

const STRIP_REQUEST_HEADERS = new Set([
    "cf-connecting-ip", "x-forwarded-for", "x-real-ip",
    "client-ip", "x-forwarded-proto", "via", "forwarded", "x-client-ip"
]);

// ==========================================
// 核心导出
// ==========================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // 1. 优先处理豆瓣图片代理
        if (url.pathname === '/proxy') {
            return handleDoubanProxy(request, url, ctx);
        }

        // 2. 访问根目录，返回 UI
        if (url.pathname === "/") {
            return new Response(getRootHtml(), {
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });
        }

        // 3. 通用 KUAYUAN 代理服务
        return handleKuayuanProxy(request, env, ctx, url);
    }
};

// ==========================================
// 功能模块: 豆瓣图片缓存代理
// ==========================================
async function handleDoubanProxy(request, url, ctx) {
    const targetUrl = url.searchParams.get('url');
    if (!targetUrl) return new Response('Missing "url" parameter', { status: 400 });
    if (!targetUrl.includes('doubanio.com')) return new Response('Forbidden: Only Douban images are allowed', { status: 403 });

    const cache = caches.default;
    let response = await cache.match(request);
    if (!response) {
        const doubanHeaders = new Headers({
            'Referer': 'https://movie.douban.com/',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
        });

        const imageRes = await fetch(targetUrl, { headers: doubanHeaders });
        if (!imageRes.ok) return new Response('Failed to fetch from source', { status: imageRes.status });

        const newHeaders = new Headers(imageRes.headers);
        newHeaders.set('Access-Control-Allow-Origin', '*');
        newHeaders.set('Cache-Control', 'public, s-maxage=2592000, max-age=604800');
        newHeaders.delete('Set-Cookie');

        response = new Response(imageRes.body, { status: imageRes.status, headers: newHeaders });
        ctx.waitUntil(cache.put(request, response.clone()));
    }
    return response;
}

// ==========================================
// 功能模块: 通用代理 (KUAYUAN 原逻辑)
// ==========================================
async function handleKuayuanProxy(request, env, ctx, url) {
    let path = url.pathname.slice(1);
    try { path = decodeURIComponent(path); } catch (e) {}
    let actualUrlStr = path + url.search + url.hash;

    // 协议补全与Referer智能处理
    if (actualUrlStr.startsWith("http") && !/^https?:\/\//.test(actualUrlStr)) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    if (!actualUrlStr.startsWith("http")) {
        const referer = request.headers.get("Referer");
        if (referer) {
            try {
                const refererObj = new URL(referer);
                if (refererObj.origin === url.origin) {
                    let refererPath = decodeURIComponent(refererObj.pathname.slice(1));
                    if (/^https?:\/+/.test(refererPath)) refererPath = refererPath.replace(/^(https?):\/+/, "$1://");
                    if (refererPath.startsWith("http")) {
                        const targetBase = new URL(refererPath + refererObj.search);
                        actualUrlStr = new URL(url.pathname + url.search, targetBase).href;
                    }
                }
            } catch (e) {}
        }
    }

    if (request.method === "OPTIONS") {
        return new Response(null, {
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                "Access-Control-Allow-Headers": "*"
            }
        });
    }

    let targetUrl;
    try { targetUrl = new URL(actualUrlStr); } catch (e) { return new Response("Invalid URL: " + actualUrlStr, { status: 400 }); }

    const newHeaders = new Headers();
    for (const [key, value] of request.headers) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith("cf-") || lowerKey.startsWith("sec-") || lowerKey === "cookie" || STRIP_REQUEST_HEADERS.has(lowerKey)) continue;
        newHeaders.set(key, value);
    }
    if (!newHeaders.has("User-Agent")) newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
    newHeaders.set("Host", targetUrl.host);

    let response;
    try {
        response = await fetch(actualUrlStr, { method: request.method, headers: newHeaders, body: request.body, redirect: "manual" });
    } catch (e) { return new Response("Proxy Error: " + e.message, { status: 502 }); }

    const responseHeaders = new Headers(response.headers);
    UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
    responseHeaders.set("Access-Control-Allow-Origin", "*");
    responseHeaders.set("Access-Control-Allow-Credentials", "true");

    const location = responseHeaders.get("Location");
    if (location) {
        try { responseHeaders.set("Location", url.origin + "/" + encodeURIComponent(new URL(location, targetUrl.href).href)); } catch (e) {}
    }

    const contentType = responseHeaders.get("Content-Type") || "";

    // M3U8 处理
    if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
        const text = await response.text();
        const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
        return new Response(text.replace(/^(?!#)(?!\s)(.+)$/gm, (m) => {
            m = m.trim();
            try { return url.origin + "/" + (m.startsWith("http") ? m : new URL(m, baseUrl).href); } catch (e) { return m; }
        }), { status: response.status, headers: responseHeaders });
    }

    // HTML 处理
    if (contentType.includes("text/html")) {
        const injectScript = `(function(){const P=window.location.origin,B='${targetUrl.href}';function W(u){if(!u||u.startsWith(P)||u.match(/^(data|blob|javascript):/))return u;try{return P+'/'+new URL(u,B).href}catch(e){return u}}const H=history,pS=H.pushState,rS=H.replaceState;function wA(a){if(a.length>=3&&typeof a[2]==='string')a[2]=W(a[2]);return a}H.pushState=function(){return pS.apply(this,wA(arguments))};H.replaceState=function(){return rS.apply(this,wA(arguments))};const O=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u,...a){return O.call(this,m,W(u),...a)};const F=window.fetch;window.fetch=function(i,n){return F(typeof i==='string'?W(i):i,n)};[HTMLAnchorElement,HTMLImageElement,HTMLLinkElement,HTMLScriptElement,HTMLIFrameElement,HTMLSourceElement,HTMLVideoElement,HTMLAudioElement,HTMLFormElement].forEach(E=>{if(!E)return;const p=E.prototype,a=(E===HTMLAnchorElement||E===HTMLLinkElement||E===HTMLBaseElement)?'href':(E===HTMLFormElement?'action':'src');const d=Object.getOwnPropertyDescriptor(p,a);if(d&&d.set){Object.defineProperty(p,a,{set:function(v){d.set.call(this,W(v))},get:d.get,enumerable:true,configurable:true});}});if(navigator.serviceWorker){navigator.serviceWorker.register=()=>new Promise(()=>{});navigator.serviceWorker.getRegistrations().then(r=>r.forEach(s=>s.unregister()))}})();`;
        const rewriter = new HTMLRewriter()
            .on("head", { element(e) { e.append(`<script>${injectScript}</script>`, { html: true }); } })
            .on("a", new AttrRewriter("href", url.origin, targetUrl.href))
            .on("img", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("link", new AttrRewriter("href", url.origin, targetUrl.href))
            .on("script", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("form", new AttrRewriter("action", url.origin, targetUrl.href))
            .on("iframe", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("video", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("audio", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("source", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("meta", new MetaRewriter(url.origin, targetUrl.href));
        return rewriter.transform(new Response(response.body, { status: response.status, headers: responseHeaders }));
    }

    return new Response(response.body, { status: response.status, headers: responseHeaders });
}

// ==========================================
// 辅助类与 UI 生成
// ==========================================
class AttrRewriter {
    constructor(attr, proxy, target) { this.attr = attr; this.proxy = proxy; this.target = target; }
    element(el) {
        const val = el.getAttribute(this.attr);
        if (val && !val.match(/^(data|#|javascript):/)) try { el.setAttribute(this.attr, this.proxy + "/" + new URL(val, this.target).href); } catch (e) {}
        if (el.tagName === "img") {
            const srcset = el.getAttribute("srcset");
            if (srcset) el.setAttribute("srcset", srcset.split(",").map(p => { const ps = p.trim().split(/\s+/); try { ps[0] = this.proxy + "/" + new URL(ps[0], this.target).href; return ps.join(" "); } catch(e) { return p; } }).join(", "));
            const dSrc = el.getAttribute("data-src");
            if (dSrc) try { el.setAttribute("data-src", this.proxy + "/" + new URL(dSrc, this.target).href); } catch(e){}
        }
    }
}

class MetaRewriter {
    constructor(proxy, target) { this.proxy = proxy; this.target = target; }
    element(el) {
        if (el.getAttribute("http-equiv")?.toLowerCase() === "refresh") {
            const content = el.getAttribute("content");
            const match = content?.match(/url\s*=\s*['"]?([^'";]+)['"]?/i);
            if (match && match[1]) try { el.setAttribute("content", content.replace(match[1], this.proxy + "/" + new URL(match[1], this.target).href)); } catch(e) {}
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Secure Proxy</title><style>body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#f0f2f5;font-family:sans-serif}.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,0.1);width:100%;max-width:400px}.title{text-align:center;font-size:1.5rem;margin-bottom:1.5rem;color:#1a1a1a;font-weight:600}input{width:100%;padding:12px;margin-bottom:1rem;border:1px solid #ddd;border-radius:6px;box-sizing:border-box}button{width:100%;padding:12px;background:#0070f3;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600}</style></head><body><div class="card"><div class="title">Proxy Everything</div><form onsubmit="event.preventDefault();const u=document.getElementById('u').value.trim();if(u)window.open(location.origin+'/'+encodeURIComponent(u),'_blank')"><input type="text" id="u" placeholder="输入目标网址" required><button type="submit">跳转</button></form></div></body></html>`;
}
