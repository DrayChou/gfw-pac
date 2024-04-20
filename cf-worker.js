export default {
    async fetch(request) {
        // 当前 URL: https://pac.newfuture.cc/SOCKS5%3A%2F%2Flocalhost%3A1080%3BHTTP%3A%2F%2Flocalhost%3A1111.pac
        // 解析 URL
        const location = new URL(request.url);
        if (!location.pathname.endsWith(".pac") || location.pathname === "/") {
            return new Response("Not Found", { status: 404 });
        }
        const pacName = location.pathname.slice(1, -4);

        // decodeURIComponent 解码并以 ; 分割，然后去掉前后的空格，再用 ; 连接
        const proxyString = decodeURIComponent(pacName)
            .split(";")
            .map((s) => s.trim())
            .join(";");

        // 下载 https://raw.githubusercontent.com/DrayChou/gfw-pac/master/gfw.template.pac 文件，下载的时候使用缓存，至少缓存一个小时
        // 替换 __PROXY__ 为上面的 proxyString, 然后直接返回
        const pac_url = "https://raw.githubusercontent.com/DrayChou/gfw-pac/master/gfw.template.pac";

        const response = await fetch(pac_url, {
            headers: { "content-type": "text/html;charset=UTF-8" },
        });
        const pac_text = await response.text();
        return new Response(pac_text.replace("__PROXY__", proxyString), {
            headers: { "content-type": "application/x-ns-proxy-autoconfig" },
        });
    },
};
