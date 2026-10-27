# 该 Python 脚本用于对接 CNNVD 厂商漏洞 OpenAPI（获取 XML 格式漏洞信息接口），实现自动化、分页式的数据抓取与本地安全归档。
# 核心功能亮点：
# 1. 自动翻页抓取：无需手动指定页码，脚本会自动根据总记录数进行分页请求，直到获取完所有数据。
# 2. 动态签名计算：每次请求前都会重新生成时间戳、随机数，并计算 SHA256 签名，确保请求合法有效。
# 3. 数据本地归档：抓取完成后，脚本会将所有漏洞数据保存为 JSON 文件，文件名包含当前日期，便于归档和后续分析。

# 需要自行替换 APP_ID 和 APP_SECRET 为实际申请的值

from datetime import datetime
import hashlib
import json
import os
import random
import string
import time
import requests

# 1. 基础配置
HOST = "https://www.cnnvd.org.cn"      # 接口基地址
URI = "/cnnvdweb/2.0/openapi/vul/xml"  # 获取 XML 漏洞信息的请求路径
URL = HOST + URI

APP_ID = "YOUR_APP_ID"  # 替换为你的实际 AppID
APP_SECRET = "YOUR_APP_SECRET"  # 请替换为实际申请的 API 密钥

method = "POST" # 请求方法固定为 POST
page_num = 1    # 当前页码，初始为 1
page_size = 20  # 每页数量, 默认是20, 建议将每页数量调大, 文档最大支持 2000, 减少请求次数
all_records = []  # 用于存放所有获取到的漏洞数据

print("开始自动翻页获取数据...")

while True:
  # 【关键】每次请求前必须重新生成时间戳、随机数并重新计算签名
  timestamp = str(int(time.time() * 1000))
  nonce = "".join(
      random.choices(string.ascii_letters + string.digits, k=16)
  ) # 16位随机字符串

  # 计算 POST 请求签名 (规则: method + uri + timestamp + nonce + appSecret)
  sign_str = f"{method}{URI}{timestamp}{nonce}{APP_SECRET}"
  x_sign = hashlib.sha256(sign_str.encode("utf-8")).hexdigest()

  # 组装请求头
  headers = {
      "Content-Type": "application/json",   # 请求体格式为 JSON
      "X-Appid": APP_ID,                    # 系统分配的应用ID
      "X-Timestamp": timestamp,             # 毫秒级时间戳
      "X-Nonce": nonce,                     # 16位随机字符串
      "X-Sign": x_sign,                     # SHA256 签名值
  }

  # 组装请求体（动态改变 pageNum）
  payload = {
      "pageNum": page_num,
      "pageSize": page_size,
      "publishStartDate": "2026-08-02",      # 发布开始时间, 格式: YYYY-MM-DD
      "publishEndDate": "2026-08-02",        # 发布结束时间, 格式: YYYY-MM-DD
      #"updateStartDate": "2026-03-01",      # 更新开始时间, 格式: YYYY-MM-DD
      #"updateEndDate": "2026-05-15",        # 更新结束时间, 格式: YYYY-MM-DD
  }

  try:
    response = requests.post(URL, json=payload, headers=headers, timeout=10)
    res_json = response.json()

    # 检查响应状态
    if res_json.get("code") == 200:
      data = res_json.get("data", {})
      records = data.get("records", [])
      total = data.get("total", 0)

      # 如果当前页没有数据了，跳出循环
      if not records:
        print("没有更多数据了。")
        break

      all_records.extend(records)
      print(
          f"成功获取第 {page_num} 页，本页 {len(records)} 条，累计已获取"
          f" {len(all_records)} / {total} 条"
      )

      # 如果已经获取的数据达到了总数，退出循环
      if len(all_records) >= total:
        print("所有数据已抓取完毕！")
        break

      # 准备获取下一页
      page_num += 1

      # 礼貌性延时 1 秒，防止请求过快触发接口的 429 频率限制
      time.sleep(1)

    else:
      print(f"请求异常，状态码: {res_json.get('code')}, 原因: {res_json.get('message')}")
      break

  except Exception as e:
    print(f"请求发生错误: {e}")
    break

# 打印最终汇总结果
print(f"\n--- 抓取完成 ---")
print(f"共收集到漏洞数据: {len(all_records)} 条")

# 2. 动态生成保存路径和文件名（脚本所在目录 + 日期后缀）
script_dir = os.path.dirname(os.path.abspath(__file__))  # 获取当前脚本所在目录
current_date = datetime.now().strftime("%Y-%m-%d")  # 获取当前日期，格式：2026-10-27
file_name = f"cnnvd_vulns-{current_date}.json"
file_path = os.path.join(script_dir, file_name)  # 拼接完整路径

# 3. 写入文件
with open(file_path, "w", encoding="utf-8") as f:
  json.dump(all_records, f, ensure_ascii=False, indent=4)

print(f"数据已成功保存至: {file_path}")
