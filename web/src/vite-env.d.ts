/// <reference types="vite/client" />

/**
 * 构建期注入的版本号（来源：web/package.json 的 version，见 vite.config.ts 的 define）。
 *
 * 为什么要有它：控制台「关于」页以前手写死 `v1.4.2`，发版时只改服务端与 README
 * 就会漏掉前端（v1.4.3 实测漏了）。现在只有 package.json 一处是真源。
 */
declare const __APP_VERSION__: string
