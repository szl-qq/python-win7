# Third-party notices / 第三方组件与许可

本项目**不是** CPython 的分支，也不重新实现 Python。它是把 Python 官方发布的
32 位 Windows embeddable 包做**二进制补丁**后重新打包分发。各组成部分的权利归属如下。

## 1. CPython (Python 3.13.16 / 3.15.2, 32-bit Windows)

- 来源：https://www.python.org/ftp/python/&lt;ver&gt;/python-&lt;ver&gt;-embed-win32.zip
- 许可：PSF License Agreement（Python Software Foundation License）
- 交付包内保留官方 `LICENSE.txt`，未做删改。
- 我们修改了 `python313.dll` 的导入表（改导入名、追加 `.w7imp` 节），
  并重新计算了 PE 校验和。修改后的 DLL 数字签名失效，这是预期结果。
- PSF 许可允许再分发修改后的二进制，前提是保留版权与许可声明；
  本项目在交付包的 `LICENSE.txt` 中满足了这一点。

## 2. Mozilla CA Bundle (`certs/cacert.pem`)

- 来源：https://curl.se/ca/cacert.pem （由 Mozilla 的 CA 程序生成）
- 许可：Mozilla Public License 2.0（对证书数据本身，实践上等同于公开事实数据；
  仍在此注明来源与许可）
- 用途：追加到 Python 的默认 SSL 信任库，修补 Win7 系统根证书库过旧的问题。

## 3. Microsoft Visual C++ Redistributable (`vc_redist.x86.exe`)

- 来源：https://aka.ms/vs/17/release/vc_redist.x86.exe
- 许可：Microsoft 可再分发条款（Microsoft Software License Terms）
- 本仓库**不包含**该文件（见 `.gitignore`），`build.sh` 在构建时下载。
  发布 Release 时如需附带，请遵守微软的可再分发条款，不要修改该安装包。

## 4. 本仓库自有代码

`tools/`、`shim/`、`docs/`、`build.sh` 等：MIT，见 [LICENSE](LICENSE)。

其中 `shim/*.c` 由 mingw-w64 交叉编译；产物链接 mingw 运行时的静态库，
按 mingw-w64 的许可（多数为 public domain / ZPL）可自由分发。

## 5. 商标

"Python" 是 Python Software Foundation 的注册商标。本项目名称中提及 Python
仅为说明兼容对象，不代表 PSF 的认可或背书。
