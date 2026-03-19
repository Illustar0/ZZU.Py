---
hide:
- navigation
---
# 逆向笔记

一些在实现 `zzupy` 过程中记录下来的上游接口行为。这里只保留对源码实现有直接帮助的信息。

## 一卡通电费充值

一卡通电费充值的请求体经过加密，涉及 SM2 和 SM4。

`server/utilities/pay` 中 `params` 的原始结构如下：

```json
{
    "utilityType": "electric",
    "payCode": "06",
    "password": "{支付密码}",
    "amt": "{充值金额}",
    "timestamp": {timestamp},
    "bigArea": "",
    "area": "{area}",
    "building": "{building}",
    "unit": "",
    "level": "{level}",
    "room": "{area}-{building}--{level}-{room}",
    "subArea": "",
    "customfield": {
    }
}
```

处理方式：

- 先向 `server/auth/getEncrypt` 请求加密信息
- 使用固定 SM4 密钥解密返回的 `publicKey`
- 用解密后的公钥以 `SM2` 的 `C1C3C2` 模式加密压缩后的请求体
- 最终请求参数里需要去掉密文十六进制前缀中的 `04`

固定 SM4 密钥：`773638372d392b33435f48266a655f35`（Hex）

## 教务 `sign`

本科教务不少请求头里带有 `sign`，其计算逻辑如下：

```python
def get_sign(dynamic_secret: str, params: str) -> str:
    """计算请求的 sign 值

    Args:
        dynamic_secret (str): login 后自动获取，来自 login-token 请求
        params (str): URL 请求参数

    Returns:
        str: sign 值
    """
    parsed_params: Dict[str, str] = {k: v[0] for k, v in parse_qs(params).items()}

    timestamp = parsed_params.pop("timestamp", "")
    random = parsed_params.pop("random", "")

    sorted_values = [v for k, v in sorted(parsed_params.items())]

    parts_to_sign = [dynamic_secret] + sorted_values + [timestamp, random]
    original_string = "|".join(parts_to_sign)

    sign = hashlib.md5(original_string.encode("utf-8")).hexdigest().upper()
    return sign
```

当前观察到服务端对该值并不严格校验，因此 `zzupy` 的新本科教务实现没有依赖这套逻辑。


## 自助服务系统

自助服务系统登录页存在一个隐藏的 `checkcode` 字段。它不是通过前端算法实时计算出来的，而是直接写在 HTML 页面里，因此客户端登录前需要先抓取登录页并提取该字段。

## 统一认证与 App 下线

豫见郑大 App 端的统一认证本身是 JWT 流程，但账密登录后手机端会被挤下线。结合抓包观察，关键点在：

- App 启动后会调用 `https://cas.s.zzu.edu.cn/token/login/userOnlineDetect`
- 请求中会携带学号、`deviceId` 和 `userToken`
- 服务端响应会影响 App 是否要求重新登录

这也是为什么脚本侧重新执行账密登录后，移动端在线状态可能受到影响。
