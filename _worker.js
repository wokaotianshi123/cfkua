// _worker.js

// 1. 定义需要从响应中移除的安全限制头 (解决 CSP, Frame 限制等)
const UNSAFE_RESPONSE_HEADERS = new Set([
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "x-xss-protection",
    "x-content-type-options"
]);

// 2. 定义需要从请求中移除的隐私/IP相关头 (IP 隐藏)
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

        // 1. 访问根目录，返回 UI
        if (url.pathname === "/") {
            return new Response(getRootHtml(), {
                headers: { "Content-Type": "text/html; charset=utf-8" }
            });
        }

        // 2. 解析目标 URL
        let path = url.pathname.slice(1);
        try { path = decodeURIComponent(path); } catch (e) {}

        let actualUrlStr = path + url.search + url.hash;

        // 补全协议
        if (actualUrlStr.startsWith("http") && !/^https?:\/\//.test(actualUrlStr)) {
            actualUrlStr = actualUrlStr.replace(/^(https?):\/+/, "$1://");
        }

        // 处理 Referer 修正 (用于相对路径资源加载)
        if (!actualUrlStr.startsWith("http")) {
            const referer = request.headers.get("Referer");
            if (referer) {
                try {
                    const refererObj = new URL(referer);
                    if (refererObj.origin === url.origin) {
                        let refererPath = refererObj.pathname.slice(1);
                        try { refererPath = decodeURIComponent(refererPath); } catch (e) {}
                        
                        // 修正 Referer 协议
                        if (/^https?:\/+/.test(refererPath)) {
                             refererPath = refererPath.replace(/^(https?):\/+/, "$1://");
                        }
                        
                        // 提取 Referer 的真实 Base URL
                        if (refererPath.startsWith("http")) {
                            const targetBase = new URL(refererPath + refererObj.search);
                            // 基于 Referer 的真实地址解析当前相对路径
                            actualUrlStr = new URL(url.pathname + url.search, targetBase).href;
                        }
                    }
                } catch (e) {}
            }
        }

        // 3. 处理 OPTIONS 预检请求 (CORS)
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
                    "Access-Control-Allow-Headers": "*"
                }
            });
        }

        // 4. 准备代理请求
        let targetUrl;
        try {
            targetUrl = new URL(actualUrlStr);
        } catch (e) {
            return new Response("Invalid URL: " + actualUrlStr, { status: 400 });
        }

        // 构建请求头 (核心：过滤 IP 和隐私信息)
        const newHeaders = new Headers();
        for (const [key, value] of request.headers) {
            const lowerKey = key.toLowerCase();
            // 过滤 CF 内部头、隐私头、Cookie
            if (lowerKey.startsWith("cf-") || 
                lowerKey.startsWith("sec-") || 
                lowerKey === "cookie" ||
                STRIP_REQUEST_HEADERS.has(lowerKey)) {
                continue;
            }
            newHeaders.set(key, value);
        }

        // 补全必要头
        if (!newHeaders.has("User-Agent")) {
            newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36");
        }
        newHeaders.set("Host", targetUrl.host);

        // 智能 Referer 处理 (欺骗目标服务器)
        const clientReferer = request.headers.get("Referer");
        if (clientReferer && clientReferer.startsWith(url.origin)) {
            try {
                const realRefererPart = clientReferer.slice(url.origin.length + 1);
                let decodedReferer = decodeURIComponent(realRefererPart);
                if (/^https?:\/\//.test(decodedReferer)) {
                    newHeaders.set("Referer", decodedReferer);
                }
            } catch(e){}
        }

        // 5. 发起请求
        let response;
        try {
            response = await fetch(actualUrlStr, {
                method: request.method,
                headers: newHeaders,
                body: request.body,
                redirect: "manual"
            });
        } catch (e) {
            return new Response("Proxy Error: " + e.message, { status: 502 });
        }

        // 6. 处理响应头
        const responseHeaders = new Headers(response.headers);
        
        // 移除安全限制
        UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));

        // 添加 CORS
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        responseHeaders.set("Access-Control-Allow-Credentials", "true");
        responseHeaders.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");

        // 重写重定向 Location
        const location = responseHeaders.get("Location");
        if (location) {
            try {
                const absoluteLocation = new URL(location, targetUrl.href).href;
                responseHeaders.set("Location", url.origin + "/" + encodeURIComponent(absoluteLocation));
            } catch (e) {}
        }

        const contentType = responseHeaders.get("Content-Type") || "";

        // 7. 内容重写处理

        // A. M3U8 视频流处理
        if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
            const text = await response.text();
            const baseUrl = actualUrlStr.substring(0, actualUrlStr.lastIndexOf("/") + 1);
            
            // 使用正则替换 M3U8 内部链接，不持有过多对象引用
            const newText = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
                match = match.trim();
                if (!match) return match;
                try {
                    // 如果是绝对路径直接用，相对路径则拼接 BaseURL
                    const absoluteUrl = match.startsWith("http") ? match : new URL(match, baseUrl).href;
                    return url.origin + "/" + absoluteUrl;
                } catch (e) {
                    return match;
                }
            });

            return new Response(newText, {
                status: response.status,
                statusText: response.statusText,
                headers: responseHeaders
            });
        }

        // B. HTML 内容处理 (注入脚本 + 重写链接)
        if (contentType.includes("text/html")) {
            // 压缩后的注入脚本
            const injectScript = `
            (function(){
                const P=window.location.origin, B='${targetUrl.href}';
                function W(u){
                    if(!u||u.startsWith(P)||u.match(/^(data|blob|javascript):/))return u;
                    try{return P+'/'+new URL(u,B).href}catch(e){return u}
                }
                const H=history, pS=H.pushState, rS=H.replaceState;
                function wA(a){if(a.length>=3&&typeof a[2]==='string')a[2]=W(a[2]);return a}
                H.pushState=function(){return pS.apply(this,wA(arguments))};
                H.replaceState=function(){return rS.apply(this,wA(arguments))};
                const O=XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open=function(m,u,...a){return O.call(this,m,W(u),...a)};
                const F=window.fetch;
                window.fetch=function(i,n){return F(typeof i==='string'?W(i):i,n)};
                [HTMLAnchorElement,HTMLImageElement,HTMLLinkElement,HTMLScriptElement,HTMLIFrameElement,HTMLSourceElement,HTMLVideoElement,HTMLAudioElement,HTMLFormElement].forEach(E=>{
                    if(!E)return;
                    const p=E.prototype, a=(E===HTMLAnchorElement||E===HTMLLinkElement||E===HTMLBaseElement)?'href':(E===HTMLFormElement?'action':'src');
                    const d=Object.getOwnPropertyDescriptor(p,a);
                    if(d&&d.set){
                        Object.defineProperty(p,a,{set:function(v){d.set.call(this,W(v))},get:d.get,enumerable:true,configurable:true});
                    }
                });
                if(navigator.serviceWorker){navigator.serviceWorker.register=()=>new Promise(()=>{});navigator.serviceWorker.getRegistrations().then(r=>r.forEach(s=>s.unregister()))}
            })();
            `;

            const rewriter = new HTMLRewriter()
                .on("head", { element(e) { e.append(`<script>${injectScript}</script>`, { html: true }); } })
                .on("a", new AttrRewriter("href", url.origin, targetUrl.href))
                .on("img", new AttrRewriter("src", url.origin, targetUrl.href)) // img 另外处理 srcset
                .on("link", new AttrRewriter("href", url.origin, targetUrl.href))
                .on("script", new AttrRewriter("src", url.origin, targetUrl.href))
                .on("form", new AttrRewriter("action", url.origin, targetUrl.href))
                .on("iframe", new AttrRewriter("src", url.origin, targetUrl.href))
                .on("video", new AttrRewriter("src", url.origin, targetUrl.href))
                .on("audio", new AttrRewriter("src", url.origin, targetUrl.href))
                .on("source", new AttrRewriter("src", url.origin, targetUrl.href))
                .on("object", new AttrRewriter("data", url.origin, targetUrl.href))
                .on("base", new AttrRewriter("href", url.origin, targetUrl.href))
                .on("meta", new MetaRewriter(url.origin, targetUrl.href));

            return rewriter.transform(new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: responseHeaders
            }));
        }

        // 普通透传
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    }
};

// 属性重写类
class AttrRewriter {
    constructor(attr, proxy, target) {
        this.attr = attr;
        this.proxy = proxy;
        this.target = target;
    }
    element(el) {
        const val = el.getAttribute(this.attr);
        if (val && !val.match(/^(data|#|javascript):/)) {
            try {
                el.setAttribute(this.attr, this.proxy + "/" + new URL(val, this.target).href);
            } catch (e) {}
        }
        // 特殊处理 srcset
        if (el.tagName === "img") {
            const srcset = el.getAttribute("srcset");
            if (srcset) {
                const newSrcset = srcset.split(",").map(p => {
                    const parts = p.trim().split(/\s+/);
                    try {
                        parts[0] = this.proxy + "/" + new URL(parts[0], this.target).href;
                        return parts.join(" ");
                    } catch(e) { return p; }
                }).join(", ");
                el.setAttribute("srcset", newSrcset);
            }
            // 处理懒加载 data-src
            const dSrc = el.getAttribute("data-src");
            if (dSrc) {
                try {
                    el.setAttribute("data-src", this.proxy + "/" + new URL(dSrc, this.target).href);
                } catch(e){}
            }
        }
    }
}

// Meta 刷新重写类
class MetaRewriter {
    constructor(proxy, target) {
        this.proxy = proxy;
        this.target = target;
    }
    element(el) {
        const equiv = el.getAttribute("http-equiv");
        if (equiv && equiv.toLowerCase() === "refresh") {
            const content = el.getAttribute("content");
            if (content) {
                const match = content.match(/url\s*=\s*['"]?([^'";]+)['"]?/i);
                if (match && match[1]) {
                    try {
                        const abs = new URL(match[1], this.target).href;
                        el.setAttribute("content", content.replace(match[1], this.proxy + "/" + abs));
                    } catch(e) {}
                }
            }
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Proxy</title>
<style>
body{margin:0;height:100vh;display:flex;align-items:center;justify-content:center;background:#f0f2f5;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 8px 24px rgba(0,0,0,0.1);width:100%;max-width:400px}
.title{text-align:center;font-size:1.5rem;margin-bottom:1.5rem;color:#1a1a1a;font-weight:600}
input{width:100%;padding:12px;margin-bottom:1rem;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;outline:none;transition:border-color .2s}
input:focus{border-color:#0070f3}
button{width:100%;padding:12px;background:#0070f3;color:#fff;border:none;border-radius:6px;cursor:pointer;font-weight:600;transition:background .2s}
button:hover{background:#0051a2}
@media(prefers-color-scheme:dark){body{background:#121212}.card{background:#1e1e1e}input{background:#2c2c2c;border-color:#444;color:#fff}.title{color:#fff}}
</style>
</head>
<body>
<div class="card">
<div class="title">Proxy Everything</div>
<form onsubmit="event.preventDefault();const u=document.getElementById('u').value.trim();if(u)window.open(location.origin+'/'+encodeURIComponent(u),'_blank')">
<input type="text" id="u" placeholder="输入目标网址 (e.g., https://google.com)" required>
<button type="submit">跳转</button>
</form>
</div>
</body>
</html>`;
}
