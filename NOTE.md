# Note
<font color=gray size=3> 一些逆向过程的笔记</font>

### 充值电费
ZZU 的电费充值过程中对请求体进行了加密，这本没有问题，抽象的是他居然选择的是国密算法，SM2 和 SM4。  
甚至他使用的 `sm-crypto` 对于 SM2 算法的实现根本就不够规范，完全不带处理 `04` 头的，整的我懵了半天  

以下为`server/utilities/pay`中`params`的原文结构（格式化后）
```json
{
    "utilityType": "electric",
    "payCode": "06",
    "password": "XXXXX",
    "amt": "10",
    "timestamp": 233,
    "bigArea": "",
    "area": "XX",
    "building": "XX",
    "unit": "",
    "level": "XX",
    "room": "XX-XX--XX-XXX",
    "subArea": "",
    "customfield": {
    }
}
```
使用 SM2 算法 (CipherMode: C1C3C2) 对其进行加密（加密时需将其压缩），需自行删去 `04` 头，公钥由`server/auth/getEncrypt`中的`publicKey`进行 SM4 解密后得到，SM4 密钥为`773638372d392b33435f48266a655f35 (Hex)`

### Sign
树维教务的很多请求里都有个 `sign` 值，很好理解，拿来校验的嘛。然而树维教务根本不对 `sign` 值进行校验，甚至没有都没关系  
Man, what can I say?  
具体逻辑忘了，直接放 Python 实现吧
```Python
def get_sign(dynamic_secret: str, params: str) -> str:
    """
    获取sign值

    :param str dynamic_secret: login 后自动获取，来自 login-token 请求
    :param str params: URL 请求参数
    :return: sign 值
    :rtype: str
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

### 自助服务系统
先不提自助服务系统那隐藏了的、神奇的、为空的验证码，他还有个 `checkcode`。  
我一开始还以为它是哪里算出来的，最后发现其实它的值直接写在网页里了....


### 统一认证
众所周知豫见郑大 APP 端的统一认证使用的是标准的 JWT 方案。那么问题就来了，为什么使用 ZZU.Py 进行账密登录，手机上就会被踢下线呢？  
关键在于 `https://cas.s.zzu.edu.cn/token/login/userOnlineDetect` 。豫见郑大 APP 端启动时会通过这个接口上报学号 、`deviceId` 和 `userToken`，并根据响应决定要不要让你重新登录。  
也就是说，只要 Block 掉这个请求，手机上的豫见郑大 APP 就不会因为 ZZU.Py 进行账密登录而被踢下线了。  
本来还想反编译 apk 看看能不能改下...结果发现加了爱加密企业版，诗人？  
写个 Xposed 模块，然后用 LSPatch 打包应该是个办法，可惜我不会 Java ，就留给有缘人实现吧