# -*- coding: utf-8 -*-
"""为默认 SSL 上下文追加内置根证书 cacert.pem（Windows 7 兼容用）

Windows 7 SP1 的系统 ROOT 证书库常停留在多年前，缺少 ISRG Root X1 等新的
公共根，访问 HTTPS 会报：

    [SSL: CERTIFICATE_VERIFY_FAILED] unable to get local issuer certificate

本模块在解释器启动时（由 site 自动导入）把随包的 cacert.pem 追加进默认 SSL
上下文。只追加、不替换系统证书，也不关闭校验；系统已有的根证书照旧生效。

cacert.pem 需与 python.exe 位于同一目录（本项目的交付包就是这样摆放的）。
"""
import os
import sys

try:
    import ssl
except Exception:  # 无 ssl 的构建，忽略
    ssl = None


def _find_ca():
    names = ("cacert.pem", "cacert.crt")
    roots = []
    for getter in (
        lambda: os.path.dirname(os.path.abspath(sys.executable)),
        lambda: os.path.abspath(sys.prefix),
    ):
        try:
            p = getter()
            if p and p not in roots:
                roots.append(p)
        except Exception:
            pass
    for root in roots:
        for n in names:
            p = os.path.join(root, n)
            if os.path.isfile(p):
                return p
    return None


_CA_FILE = _find_ca()

if _CA_FILE and ssl is not None:
    for _var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        os.environ.setdefault(_var, _CA_FILE)

    def _with_bundle(fn):
        def wrapper(*args, **kwargs):
            ctx = fn(*args, **kwargs)
            try:
                ctx.load_verify_locations(_CA_FILE)
            except Exception:
                pass
            return ctx

        wrapper.__name__ = getattr(fn, "__name__", "create_default_context")
        wrapper.__doc__ = "ssl.create_default_context + bundled CA (Win7 compat)"
        return wrapper

    ssl.create_default_context = _with_bundle(ssl.create_default_context)
    if hasattr(ssl, "_create_default_https_context"):
        ssl._create_default_https_context = ssl.create_default_context
