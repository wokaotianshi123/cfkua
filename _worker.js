/**
 * Cloudflare Pages Worker - CORS Proxy
 * 移植自 cors-anywhere (https://github.com/Rob--W/cors-anywhere)
 * 适配 Cloudflare Runtime
 */

'use strict';

// ========================== 配置区域 ==========================

// 阻断的关键字 (原代码中的 keywordBlacklist)
const KEYWORD_BLOCKLIST = [".m3u8", ".mpd", ".m4v", ".ts"];

// 阻断的域名 (原代码中的 originBlacklist)
const ORIGIN_BLOCKLIST = [];

// 白名单 (原代码中的 originWhitelist)，如果非空，则只允许列表内的域名
const ORIGIN_WHITELIST = [];

// 需要从请求中移除的 Headers (原代码中的 removeHeaders)
// 注意：Cloudflare 会自动处理部分 Header，这里主要移除可能引起冲突的自定义 Header
const REMOVE_HEADERS = [
    'x-heroku-queue-wait-time',
    'x-heroku-queue-depth',
    'x-heroku-dynos-in-use',
    'x-request-start',
    'x-forwarded-for', // 通常由 CF 管理，避免伪造
];

// ========================== 核心逻辑 ==========================

/**
 * 添加 CORS 响应头
 */
function withCORS(headers, request) {
    headers.set('Access-Control-Allow-Origin', '*');
    headers.set('Access-Control-Allow-Credentials', 'true');
    
    // 处理预检请求的 Header
    const acrh = request.headers.get('Access-Control-Request-Headers');
    if (acrh) {
        headers.set('Access-Control-Allow-Headers', acrh);
    }
    
    const acrm = request.headers.get('Access-Control-Request-Method');
    if (acrm) {
        headers.set('Access-Control-Allow-Methods', acrm);
    }

    // 暴露所有返回的 Headers
    const exposeHeaders = [];
    for (const key of headers.keys()) {
        exposeHeaders.push(key);
    }
    if (exposeHeaders.length > 0) {
        headers.set('Access-Control-Expose-Headers', exposeHeaders.join(','));
    }

    return headers;
}

/**
 * 检查 URL 是否在黑名单/白名单中
 */
function isListed(urlStr, list) {
    return list.some(keyword => urlStr.includes(keyword));
}

export default {
    async fetch(request, env, ctx) {
        const urlObj = new URL(request.url);
        let path = urlObj.pathname + urlObj.search;

        // 1. 处理 OPTIONS 预检请求
        if (request.method === 'OPTIONS') {
            const corsHeaders = new Headers();
            withCORS(corsHeaders, request);
            return new Response(null, {
                status: 200,
                headers: corsHeaders
            });
        }

        // 2. 根目录访问，显示使用说明
        if (path === '/' || path === '') {
            return new Response(JSON.stringify({
                usage: "https://" + urlObj.hostname + "/{Target_URL}",
                source: "https://github.com/netnr/proxy (Ported to Cloudflare Pages)",
                message: "Append the URL you want to proxy to the end of this URL."
            }), {
                status: 200,
                headers: { "Content-Type": "application/json" }
            });
        }

        // 3. 处理特殊的验证路径
        if (path === '/iscorsneeded') {
            return new Response('no', { status: 200, headers: { 'Content-Type': 'text/plain' } });
        }

        // 4. 解析目标 URL
        // 移除开头的 /
        let targetUrlStr = path.slice(1);

        // 补全协议 (如果用户只输了 www.google.com)
        if (!targetUrlStr.startsWith('http://') && !targetUrlStr.startsWith('https://')) {
            // 简单的判断，如果看起来像域名，默认走 https
            // 原代码逻辑比较复杂，这里简化处理：Cloudflare 环境通常访问 HTTPS 资源
            // 如果只有 // 开头
            if (targetUrlStr.startsWith('//')) {
                targetUrlStr = 'https:' + targetUrlStr;
            } else {
                targetUrlStr = 'https://' + targetUrlStr;
            }
        }

        let targetUrl;
        try {
            targetUrl = new URL(targetUrlStr);
        } catch (e) {
            return new Response('Invalid URL: ' + targetUrlStr, { status: 400 });
        }

        // 5. 检查黑白名单
        
        // 检查端口
        if (targetUrl.port && parseInt(targetUrl.port) > 65535) {
            return new Response('Port number too large', { status: 400 });
        }

        // 检查关键字黑名单
        if (isListed(targetUrl.href, KEYWORD_BLOCKLIST)) {
             return new Response('The keyword was blacklisted by the operator of this proxy.', { status: 403 });
        }

        // 检查域名黑名单
        if (ORIGIN_BLOCKLIST.includes(targetUrl.hostname)) {
            return new Response('The origin was blacklisted by the operator of this proxy.', { status: 403 });
        }

        // 检查域名白名单
        if (ORIGIN_WHITELIST.length > 0 && !ORIGIN_WHITELIST.includes(targetUrl.hostname)) {
            return new Response('The origin was not whitelisted by the operator of this proxy.', { status: 403 });
        }

        // 6. 构建新的请求
        // 过滤掉不需要的 Header
        const newHeaders = new Headers();
        const requestHeaders = request.headers;
        
        for (const [key, value] of requestHeaders) {
            // 移除特定 Header
            if (REMOVE_HEADERS.includes(key.toLowerCase())) continue;
            // 移除 Origin 和 Referer，防止目标服务器拒绝请求 (或根据需要保留)
            // 原代码逻辑通常会修改 Origin，这里我们选择不发送 Origin 给目标服务器，
            // 除非你需要伪造 Origin。
            if (key.toLowerCase() === 'origin') continue;
            if (key.toLowerCase() === 'referer') continue;
            if (key.toLowerCase() === 'host') continue; // Host 由 fetch 自动设置
            if (key.toLowerCase() === 'cookie') continue; // 为了隐私通常不透传 Cookie
            
            newHeaders.set(key, value);
        }

        // 设置 User-Agent (可选，保持原请求或设置默认)
        if (!newHeaders.has('user-agent')) {
            newHeaders.set('User-Agent', 'Mozilla/5.0 (Compatible; Cloudflare-CORS-Proxy)');
        }

        const proxyRequest = new Request(targetUrl.toString(), {
            method: request.method,
            headers: newHeaders,
            body: request.body, // 直接透传流
            redirect: 'follow' // Cloudflare 自动处理重定向
        });

        // 7. 发起请求并处理响应
        try {
            const response = await fetch(proxyRequest);

            // 构建新的响应 Headers
            const responseHeaders = new Headers(response.headers);
            
            // 移除可能引起问题的响应头
            responseHeaders.delete('Content-Security-Policy');
            responseHeaders.delete('Content-Security-Policy-Report-Only');
            responseHeaders.delete('Clear-Site-Data');
            // 移除 Set-Cookie，避免代理将 Cookie 种在代理域名下
            responseHeaders.delete('Set-Cookie');

            // 添加 CORS 头
            withCORS(responseHeaders, request);

            // 添加调试信息
            responseHeaders.set('x-final-url', targetUrl.href);

            // 返回响应 (保持流式传输)
            return new Response(response.body, {
                status: response.status,
                statusText: response.statusText,
                headers: responseHeaders
            });

        } catch (e) {
            return new Response('Proxy request failed: ' + e.message, { 
                status: 502,
                headers: { 'Access-Control-Allow-Origin': '*' }
            });
        }
    }
};
