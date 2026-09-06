# 传输/断点续传实测笔记

2026-09-06/07 在局域网真实链路(500MB/Chromium APK 等样本)上的观察记录。
浏览器下载栈的行为以当时版本为准,后续版本可能变化,不作为恒定规律。

## 服务器侧能力(/dl 与 /view 共用 serve())

- 文件响应携带 `ETag`(= catalog id,id 与文件一一对应且不可变,可当强
  validator),并校验 `If-Range`:失配回落完整 200,防止拼脏字节。
- `Range: bytes=N-` → 206 Partial Content(含 Content-Range);畸形/多段
  Range 头也回落完整 200。
- 逐字节正确性已抽样验证:206 切片与源文件同偏移 SHA256 一致。
- /view = inline + 长 immutable 缓存;/dl = attachment + no-store。
- 传输账本:每个 /dl 是独立的 per-request 计数器(并发多流互不影响);
  30s 静默的在途计数器由监视器剪除(带日志),流还活着时下一 chunk 自动
  重建计数器,done 日志与 Delivered 推送不受影响。

## 各客户端实测行为(下载路径)

- **Android Chrome / 系统 AndroidDownloadManager**:大文件先按
  Content-Length 三等分并行拉取;断 WiFi 重连后各段自动按断点重新发
  Range(实测设备换 IP 也能接上)。系统下载器接管后 UA 变为
  `AndroidDownloadManager/N`。
- **小米浏览器(MiuiBrowser)**:常态即分段下载,约 4-15MB 一段、双线程
  并行、每段独立 Range;断网重连后按段续上。分段间有少量安全重叠,由
  客户端自行去重拼装。
- **iOS(Safari/CrOS/Chrome iOS)**:下载路径实测从不发 Range,"重试"
  语义为完整重拉;视频预览 seek 是另一条路径(/view),照常使用 Range。
  中断后重试时进度条可能冻结在旧百分比,传输实际在重新进行——客户端
  UI 行为。
- **Windows 桌面 Edge/Chrome**:初始请求收到 200 后会三段分拆一次
  (Range);暂停/继续走同一 TCP 连接的背压,不重发请求;传输中真断
  (接口重置)后任务进入中断态,实测未见自动重拨,手动"继续"也
  未必出网——恢复主要靠重新发起下载。秒级网络抖动可被 TCP 重传桥接,
  会话存活则下载无感继续。
- 短抖动的 TCP 桥接说明:断网时长只影响"TCP 会话是否存活",不发新
  请求的"继续下载"与 Range 续传是两回事,前者服务器日志零痕迹。

## 复测方法

- 日志:tinbox.log(exe 同目录),关注 `download start` /
  `prune stalled pull` / `download counter rebuilt` / `done` /
  `closed by receiver` / `serve ... range=...` 行。
- 桌面浏览器:地址栏直接打开 `/dl?id=...&r=<新值>` 与页面 iframe 触发
  路径等价;断点位置串起后应出现 `Range: bytes=N-` 且 `download done`
  总字节数 = 断点 + 续传段。
- curl 抽样验证:`curl -r 100000000-109999999
  -H 'If-Range: "<id>"' http://<ip>:<port>/dl?id=<id>`,核对 206 与切片
  哈希。
