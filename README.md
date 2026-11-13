# Certimate UniFi OS 部署插件

`unifi-os` 将 Certimate 工作流中的 PEM 证书链和私钥上传到 UniFi OS，激活证书，再通过新的 TLS 连接核对管理端提供的证书。插件适用于管理界面提供 **Settings → Control Plane → Console → Certificates** 的 UniFi OS Server 和硬件控制台。部署使用管理界面的会话和证书 API，参考 [acme.sh 的 UniFi OS 部署脚本](https://github.com/acmesh-official/acme.sh/blob/master/deploy/unifios.sh)和 [Ubiquiti 的 UniFi OS Server 文档](https://help.ui.com/hc/en-us/articles/34210126298775-Self-Hosting-UniFi)。

## 安装

使用支持外部插件协议 3 的 Certimate。插件依赖锁定到 Certimate 提交 `b0fca4697cbe`。构建命令如下。

```sh
go test ./...
mkdir -p dist/unifi-os
go build -trimpath -o dist/unifi-os/unifi-os.exe ./unifi-os
cp unifi-os/manifest.json dist/unifi-os/
```

将整个 `dist/unifi-os/` 复制到 Certimate 的插件根目录下。目录结构为 `$CERTIMATE_PLUGIN_DIR/unifi-os/manifest.json` 和 `$CERTIMATE_PLUGIN_DIR/unifi-os/unifi-os.exe`。保留可执行权限，确保其他用户无权写入插件目录或二进制，然后重启 Certimate。

## 配置工作流

1. 在**授权凭据**中选择 **UniFi OS**，填写有权管理控制台证书的本地管理员用户名和密码。
2. 在**部署证书**节点选择 **UniFi OS**，选中凭据和上游证书节点，填写控制台的 HTTPS 管理地址。自托管 UniFi OS Server 通常用 `https://主机名:11443`，硬件控制台通常用 `https://主机名`。
3. 管理 API 默认验证 TLS。首次部署到使用自签名证书的控制台时，可在受信任网络中开启**跳过管理 API 的 TLS 验证**。证书启用后仍会核对管理端提供的叶证书指纹。
4. **清理旧证书**默认关闭。开启后，仅在验证新证书已生效时删除由此插件创建、同一主题、SAN 和密钥类型、且生效日期更早的未启用证书。UniFi OS 激活证书会替换当前控制台使用的证书。

## 发布

合并到 GitHub 的 `main` 后，`Release plugin` 会发布首个版本。后续发布需更新 `unifi-os/manifest.json` 的 `version`。工作流先上传 GitHub Release 的平台 ZIP，再更新插件市场索引。手动重试可在 **Actions → Release plugin → Run workflow** 选择 `main`，插件目录填 `unifi-os`。
