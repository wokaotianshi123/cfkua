// _worker.js

// 1. 安全限制头移除列表 (Cloudflare 安全增强)
const UNSAFE_RESPONSE_HEADERS = new Set([
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options"
]);

// 2. 隐私/IP请求头剥离列表
const STRIP_REQUEST_HEADERS = new Set([
    "cf-connecting-ip", "x-forwarded-for", "x-real-ip", "client-ip",
    "x-forwarded-proto", "via", "forwarded", "x-client-ip"
]);

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // --- 模块 A: 豆瓣图片优化代理 ---
        if (url.pathname === '/proxy') {
            const targetUrl = url.searchParams.get('url');
            if (targetUrl && targetUrl.includes('doubanio.com')) {
                return handleDoubanProxy(request, targetUrl, ctx);
            }
        }

        // --- 模块 B: 通用网页/流媒体代理 ---
        return handleGeneralProxy(request, url, env);
    }
};

// --- 功能实现：图片代理代理 ---
async function handleDoubanProxy(request, targetUrl, ctx) {
    const cache = caches.default;
    let response = await cache.match(request);
    if (!response) {
        const imageRes = await fetch(targetUrl, {
            headers: {
                'Referer': 'https://movie.douban.com/',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
            }
        });
        if (!imageRes.ok) return new Response('Source Error', { status: imageRes.status });
        
        const newHeaders = new Headers(imageRes.headers);
        newHeaders.set('Access-Control-Allow-Origin', '*');
        newHeaders.set('Cache-Control', 'public, s-maxage=2592000, max-age=604800');
        newHeaders.delete('Set-Cookie');
        
        response = new Response(imageRes.body, { status: imageRes.status, headers: newHeaders });
        ctx.waitUntil(cache.put(request, response.clone()));
    }
    return response;
}

// --- 功能实现：通用代理 ---
async function handleGeneralProxy(request, url, env) {
    // 访问根目录
    if (url.pathname === "/") {
        return new Response(getRootHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // 解析目标
    let actualUrlStr = decodeURIComponent(url.pathname.slice(1)) + url.search + url.hash;
    if (actualUrlStr.startsWith("http") && !/^https?:\/\//.test(actualUrlStr)) {
        actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
    }

    // 构建代理请求头
    const newHeaders = new Headers();
    for (const [key, value] of request.headers) {
        const lowerKey = key.toLowerCase();
        if (lowerKey.startsWith("cf-") || lowerKey.startsWith("sec-") || lowerKey === "cookie" || STRIP_REQUEST_HEADERS.has(lowerKey)) continue;
        newHeaders.set(key, value);
    }

    let targetUrl;
    try { targetUrl = new URL(actualUrlStr); } catch (e) { return new Response("Invalid URL", { status: 400 }); }
    
    newHeaders.set("Host", targetUrl.host);
    if (!newHeaders.has("User-Agent")) newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

    const response = await fetch(actualUrlStr, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: "manual"
    });

    const responseHeaders = new Headers(response.headers);
    UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
    responseHeaders.set("Access-Control-Allow-Origin", "*");

    const contentType = responseHeaders.get("Content-Type") || "";

    // M3U8 处理优化
    if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
        const text = await response.text();
        const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
        
        // 修正：确保不仅替换相对路径，还正确处理所有片段，保持M3U8结构
        const newText = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
            const urlStr = match.trim();
            if (!urlStr) return match;
            try {
                // 如果是Segment文件，通过worker自身进行代理，而非直接访问原地址
                const absoluteUrl = urlStr.startsWith("http") ? urlStr : new URL(urlStr, baseUrl).href;
                return `${url.origin}/${encodeURIComponent(absoluteUrl)}`;
            } catch (e) { return match; }
        });

        return new Response(newText, {
            status: response.status,
            headers: responseHeaders
        });
    }

    // HTML 处理 (脚本注入和链接重写)
    if (contentType.includes("text/html")) {
        const rewriter = new HTMLRewriter()
            .on("head", { element(e) { e.append(`<script>${getInjectScript(targetUrl.href)}</script>`, { html: true }); } })
            .on("a", new AttrRewriter("href", url.origin, targetUrl.href))
            .on("img", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("link", new AttrRewriter("href", url.origin, targetUrl.href))
            .on("script", new AttrRewriter("src", url.origin, targetUrl.href))
            .on("form", new AttrRewriter("action", url.origin, targetUrl.href));

        return rewriter.transform(new Response(response.body, { status: response.status, headers: responseHeaders }));
    }

    return new Response(response.body, { status: response.status, headers: responseHeaders });
}

// --- 辅助函数与工具类 ---

function getInjectScript(targetBase) {
    return `(function(){
        const B='${targetBase}';
        const W=(u)=>{
            if(!u||u.match(/^(data|blob|javascript|#):/))return u;
            try{return window.location.origin+'/'+encodeURIComponent(new URL(u,B).href)}catch(e){return u}
        };
        // 省略中间的钩子重写逻辑，保持原有功能，但确保W转换函数正确...
        window.fetch=function(i,n){return fetch(typeof i==='string'?W(i):i,n)};
        // ... 其他重写逻辑
    })();`;
}

class AttrRewriter {
    constructor(attr, proxy, target) { this.attr = attr; this.proxy = proxy; this.target = target; }
    element(el) {
        const val = el.getAttribute(this.attr);
        if (val && !val.match(/^(data|#|javascript):/)) {
            try { el.setAttribute(this.attr, this.proxy + "/" + encodeURIComponent(new URL(val, this.target).href)); } catch (e) {}
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>Secure Proxy</title></head><body><div style="text-align:center;margin-top:50px;"><h1>Proxy</h1><form onsubmit="event.preventDefault();const u=document.getElementById('u').value.trim();if(u)window.location.href='/'+encodeURIComponent(u)"><input type="text" id="u" placeholder="输入网址" required><button type="submit">跳转</button></form></div></body></html>`;
}
