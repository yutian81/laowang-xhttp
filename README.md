![image](https://github.com/user-attachments/assets/fb20a984-3427-4180-ba1a-5843fa5a327c)

## 部署到deno

- 主入口文件：`deno.ts`
- 设置环境变量：根据 `deno.ts` 里的变量说明在 deno 控制面板设置

## 项目反代

- 部署 `deno-proxy.js` 到 CF WORKER 并绑定自定义域名来反代 deno 项目
- 修改节点 host 和 sni 为 worker 自定义域名
- 修改节点入口地址为优选域名或优选IP
