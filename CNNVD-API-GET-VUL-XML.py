# CNNVD API Python 示例代码
# CNNVD 实名注册单位通过 API 快捷获取漏洞信息
# 需要自行替换 APP_ID 和 APP_SECRET 为实际申请的值

import hashlib
import json
import random
import string
import time
import requests

# 1. 基础配置
HOST = "https://www.cnnvd.org.cn"  # 接口基地址
URI = "/cnnvdweb/2.0/openapi/vul/xml"  # 获取 XML 漏洞信息的请求路径
URL = HOST + URI

APP_ID = "YOUR_APP_ID"  # 请替换为实际申请的 AppID
APP_SECRET = "YOUR_APP_SECRET"  # 请替换为实际申请的 API 密钥

# 2. 构造认证参数
method = "POST"
timestamp = str(int(time.time() * 1000))  # Unix 时间戳，毫秒级
nonce = "".join(
    random.choices(string.ascii_letters + string.digits, k=16)
)  # 16位随机字符串

# 3. 计算 POST 请求签名 (规则: method + uri + timestamp + nonce + appSecret)
sign_str = f"{method}{URI}{timestamp}{nonce}{APP_SECRET}"
x_sign = hashlib.sha256(sign_str.encode("utf-8")).hexdigest()

# 4. 组装请求头 (Header)
headers = {
    "Content-Type": "application/json",  # 请求体格式为 JSON
    "X-Appid": APP_ID,                   # 系统分配的应用ID
    "X-Timestamp": timestamp,            # 毫秒级时间戳
    "X-Nonce": nonce,                    # 16位随机字符串
    "X-Sign": x_sign,                    # SHA256 签名值
}

# 5. 组装请求体 (Body) - 获取 XML 漏洞信息的请求参数
payload = {
    "pageNum": 1,                      # 页码, 默认是1
    "pageSize": 10,                    # 每页数量, 默认是20, 最大值为 2000
    "publishStartDate": "2026-10-21",  # 发布开始时间, 格式: YYYY-MM-DD
    "publishEndDate": "2026-10-23",    # 发布结束时间, 格式: YYYY-MM-DD
    # "updateStartDate": "2026-05-10",   # 更新开始时间, 格式: YYYY-MM-DD
    # "updateEndDate": "2026-05-15"      # 更新结束时间, 格式: YYYY-MM-DD
}

# 打印调试信息
# print("--- 调试信息 ---")
# print("签名原串:", sign_str)
# print("计算签名:", x_sign)

# 6. 发送 POST 请求
try:
  response = requests.post(URL, json=payload, headers=headers, timeout=10)
  # print("\n--- 响应结果 ---")
  # print("状态码:", response.status_code)

  # 使用 json.dumps 美化输出响应数据
  pretty_data = json.dumps(
      response.json(), indent=4, ensure_ascii=False
  )
  print("响应数据:\n", pretty_data)
except Exception as e:
  print("请求发生错误:", e)
