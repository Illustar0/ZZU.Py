# ZZU.Py
<font color=gray size=3>郑州大学移动校园的 Python API 封装</font>

## 安装

```shell
pip install zzupy --upgrade
```

## Done & To Do
- [x] API
  - [x] 登录
    - [x] 帐密登录
    - [x] Cookie 登录
- [x] Supwisdom
  - [x] 获取课表
    - [x] 获取当日课表
    - [x] 获取当周课表
    - [x] 获取自定义周数课表
  - [x] 获取空教室
- [x] Network
  - [x] 校园网认证 
    - [x] 校园网
    - [x] 移动宽带
  - [x] 获取在线设备数据
  - [x] 获取消耗流量
  - [x] 获取使用时长
  - [x] 注销设备
- [x] eCard
  - [x] 充值电费 
  - [x] 获取校园卡余额
  - [x] 获取剩余电费

前往 [ZZU.Py Completion Plan](https://github.com/users/Illustar0/projects/1) 查看 To Do

## 文档

[文档](https://illustar0.github.io/ZZU.Py/)

## Note
[Note](https://github.com/Illustar0/ZZU.Py/blob/main/NOTE.md)

## Example

```Py
from zzupy import ZZUPy
from http.cookies import SimpleCookie
cookie = SimpleCookie()
cookie["userToken"] = "Your userToken"
cookie["userToken"]["domain"] = ".zzu.edu.cn"
cookie["userToken"]["path"] = "/"
me = ZZUPy("usercode","password", cookie)
info = me.login()
print(f"{info["usercode"]} {info["name"]} 登录成功")
print("校园卡余额：", str(me.eCard.get_balance()))
print("剩余电费：", str(me.eCard.get_remaining_energy()))
print("课表JSON：", me.Supwisdom.get_current_week_courses("172").dump_json())
me.Network.login()
print(me.Network.get_online_devices().dump_json())
```

## 致谢

- [ZZU-API](https://github.com/TorCroft/ZZU-API) 提供了部分接口的参考 ~~(其实是我懒得抓包)~~
- [Share ZZU WLAN](https://github.com/zidou-kiyn/share_zzu_wlan) 提供了新的校园网 Portal 认证相关代码

## 许可

MIT license