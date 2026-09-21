# 传输/断点续传实测笔记

2026-09-06/07 在局域网真实链路(500MB/Chromium APK 等样本)上的观察记录。
浏览器下载栈的行为以当时版本为准,后续版本可能变化,不作为恒定规律。

## 服务器侧能力(/dl 与 /view 共用 serve())

- 文件响应携带 `ETag`(= catalog id + 构建标签;id 与文件一一对应且不可
  变,构建标签在重新编译后变化,使旧构建缓存的响应头不会被 304 沿用,
  可当强 validator),并校验 `If-Range`:失配回落完整 200,防止拼脏字节。
- `Range: bytes=N-` → 206 Partial Content(含 Content-Range);畸形/多段
  Range 头也回落完整 200。
- 逐字节正确性已抽样验证:206 切片与源文件同偏移 SHA256 一致。
- /view = inline + 长 immutable 缓存;/dl = attachment + no-store。
- 传输落盘:上传半途文件以 `pending__{id}__{名}` 哨兵名落盘,成功即同卷
  原子 rename 剥掉前缀;启动 reconcile 见 `pending__` 一律删除。半截文件
  因此自证身份、不依赖索引存活——崩溃+索引丢失也不会被收养成完整文件,
  删除失败(AV 锁)则每次启动重试直到成功。命名空间为服务端纳秒 id,
  用户文件名无法碰撞。
- 传输账本:每个 /dl 是独立的 per-request 计数器(并发多流互不影响);
  5s 静默的在途计数器由监视器剪除(带日志;暂停与真死同判,误报被接受,
  活流下一 chunk 自动重建计数器),done 日志与 Delivered 推送不受影响。
  已完成计数器保留 15s 后剪除。窗口 2026-09-08 由 30s 调至 5s,
  与上传静默超时(同为 5s)对称:30s 的唯一辩护理由"容忍暂停"在实测中
  不成立——暂停误报在 30s 下同样发生,窗口只决定何时报、不决定报几次。

## 各客户端实测行为(下载路径)

- **Android Chrome / 系统 AndroidDownloadManager**:大文件先按
  Content-Length 三等分并行拉取;断 WiFi 重连后各段自动按断点重新发
  Range(实测设备换 IP 也能接上)。系统下载器接管后 UA 变为
  `AndroidDownloadManager/N`。
- **小米浏览器(MiuiBrowser)**:常态即分段下载,约 4-15MB 一段、双线程
  并行、每段独立 Range;断网重连后按段续上。分段间有少量安全重叠,由
  客户端自行去重拼装。
- **iOS(Safari/CrOS/Chrome iOS)**:按中断方式分叉(2026-09-08 补测)。
  断 WiFi / 异常中断 → "重试"语义为完整重拉,**不发 Range**;进度条可能
  冻结在旧百分比,传输实际在重新进行——客户端 UI 行为。下载管理器里
  **主动暂停→继续** → 关闭旧连接,数秒后从已提交偏移(实测回退 ~5MB,
  即最后提交块边界)发 `Range: bytes=N-` + `If-Range` 续传:日志表现为
  `closed by receiver` → 新 `download start` 带 Range。视频预览 seek 是
  另一条路径(/view),照常使用 Range。
- **Android 模拟器(Chrome 149,Android 10; K,2026-09-08)**:下载初始
  200 后三段分拆(1/3、2/3 点并行 Range),与桌面同款。**暂停 = 三段连接
  保持打开、停止读取**(背压,无 close 行)→ 随后被 prune 划账(观测时
  窗口为 30s);继续 =
  弃旧连接,三条新 Range 请求按段续传(每段回退 ~9MB 至已提交块边界)。
  **断网 = no-FIN 无声死(日志零痕迹)** → prune 收尸(观测时窗口 30s);重连后同样按段
  Range 续传(回退 ~5MB)——与 iOS"断网=完整重拉"形成对照。模拟器上
  系统下载器未接管(UA 始终 Chrome Mobile),与真机行为不同。附带:被
  暂停的旧连接其 serve 写任务会长期阻塞(无 FIN 永不报错),账已清、无
  UI 影响,等客户端侧弃 socket 才补 close 行。
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
