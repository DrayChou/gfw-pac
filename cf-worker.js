export default {
  async fetch(request, env, ctx) {
    // 当前 URL: https://pac.newfuture.cc/SOCKS5%3A%2F%2Flocalhost%3A1080%7CHTTP%3A%2F%2Flocalhost%3A1111.pac
    // 需要从 location.pathname 中提取出 pac 文件名
    const url = request.url;

    // 解析 URL
    const location = new URL(url);
    const pacName = location.pathname.substr(1).replace(/\.pac$/, "");

    // decodeURIComponent 解码
    const hosts = decodeURIComponent(pacName);

    // 以 | 分割
    const hostList = hosts.split("|");

    // 拼成 SOCKS5 localhost:7893; SOCKS5 localhost:1080;
    const proxyString = hostList.map((host) => `${host}`).join("; ");

    // 读取本地的 ./gfw.template.pac 文件，替换 __PROXY__ 为上面的 proxyString, 然后直接返回
    const pac = await ctx.assets.get("gfw.template.pac");
    return new Response(pac.replace("__PROXY__", proxyString), {
      headers: { "content-type": "application/x-ns-proxy-autoconfig" },
    });
  },
};
