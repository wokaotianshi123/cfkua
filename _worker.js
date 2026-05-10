// _workerkua.js

// 限制配置：移除安全头以免浏览器阻塞代理内容
const UNSAFE_RESPONSE_HEADERS = new Set([
    "content-security-policy", "content-security-policy-report-only", 
    "x-frame-options", "x-xss-protection", "x-content-type-options"
]);

// 隐私保护：移除客户端的敏感IP头
const STRIP_REQUEST_HEADERS = new Set([
    "cf-connecting-ip", "x-forwarded-for", "x-real-ip", 
    "client-ip", "x-forwarded-proto", "via", "forwarded", "x-client-ip"
]);

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

        // 3. 复杂 HTML/Proxy 逻辑解析
        // 尝试从 pathname 中提取目标 URL
        let path = url.pathname.slice(1);
        if (!path) return new Response(getRootHtml(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
        
        try { path = decodeURIComponent(path); } catch (e) {}

        // 如果路径不是以 http 开头，自动补全协议
        let actualUrlStr = (path.startsWith("http") ? path : "https://" + path) + url.search + url.hash;

        if (request.method === "OPTIONS") {
            return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*", "Access-Control-Allow-Headers": "*" } });
        }

        const targetUrl = new URL(actualUrlStr);
        const newHeaders = new Headers();
        
        // 过滤和构建请求头
        for (const [key, value] of request.headers) {
            const lowerKey = key.toLowerCase();
            if (lowerKey.startsWith("cf-") || lowerKey.startsWith("sec-") || lowerKey === "cookie" || STRIP_REQUEST_HEADERS.has(lowerKey)) continue;
            newHeaders.set(key, value);
        }
        
        // 伪造关键头，确保流媒体请求通畅
        newHeaders.set("Host", targetUrl.host);
        newHeaders.set("Referer", targetUrl.origin + "/"); 
        newHeaders.set("Origin", targetUrl.origin);

        // 代理请求
        let response = await fetch(actualUrlStr, { 
            method: request.method, 
            headers: newHeaders, 
            body: request.body, 
            redirect: "manual" 
        });

        const responseHeaders = new Headers(response.headers);
        UNSAFE_RESPONSE_HEADERS.forEach(h => responseHeaders.delete(h));
        responseHeaders.set("Access-Control-Allow-Origin", "*");

        const contentType = responseHeaders.get("Content-Type") || "";

        // 4. M3U8 流处理 (增强逻辑)
        if (contentType.includes("mpegurl") || actualUrlStr.endsWith(".m3u8")) {
            const text = await response.text();
            // 计算资源根目录用于补全相对路径
            const baseUrl = targetUrl.origin + targetUrl.pathname.substring(0, targetUrl.pathname.lastIndexOf("/") + 1);
            
            // 使用正则修正所有非注释行的链接，并进行编码
            const newText = text.replace(/^(?!#)(?!\s)(.+)$/gm, (match) => {
                const segmentUrl = new URL(match.trim(), baseUrl).href;
                return `${url.origin}/${encodeURIComponent(segmentUrl)}`;
            });
            
            return new Response(newText, { headers: responseHeaders });
        }

        // 5. HTML 内容重写 (增强交互)
        if (contentType.includes("text/html")) {
            const rewriter = new HTMLRewriter()
                .on("a, link, script, img, iframe, form, source, video, audio, object, base", new AttrRewriter(url.origin, targetUrl.href));
            return rewriter.transform(new Response(response.body, { headers: responseHeaders }));
        }

        // 普通资源透传
        return new Response(response.body, { headers: responseHeaders });
    }
};

/** 辅助功能 **/

class AttrRewriter {
    constructor(proxy, target) { 
        this.proxy = proxy; 
        this.target = target; 
    }
    element(el) {
        const attr = el.tagName === 'form' ? 'action' : (el.tagName === 'link' || el.tagName === 'a' || el.tagName === 'base' ? 'href' : 'src');
        const val = el.getAttribute(attr);
        if (val && !val.startsWith("data:") && !val.startsWith("#") && !val.startsWith("javascript:")) {
            try { 
                const absoluteUrl = new URL(val, this.target).href;
                el.setAttribute(attr, `${this.proxy}/${encodeURIComponent(absoluteUrl)}`); 
            } catch (e) {}
        }
        
        // 针对懒加载元素
        if (el.getAttribute("data-src")) {
            try {
                const abs = new URL(el.getAttribute("data-src"), this.target).href;
                el.setAttribute("data-src", `${this.proxy}/${encodeURIComponent(abs)}`);
            } catch(e) {}
        }
    }
}

function getRootHtml() {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><title>Secure Proxy</title>
    <style>body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;background:#f4f4f4;}
    .box{text-align:center;padding:20px;background:#fff;border-radius:10px;box-shadow:0 4px 6px rgba(0,0,0,0.1);}</style></head>
    <body><div class="box">
    <h2>URL 代理工具</h2>
    <form onsubmit="event.preventDefault();window.open(location.origin+'/'+encodeURIComponent(document.getElementById('u').value),'_blank')">
    <input type="text" id="u" placeholder="输入完整网址" style="width:300px;padding:8px;">
    <button type="submit">跳转</button></form></div></body></html>`;
}
