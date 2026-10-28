import asyncio
import json
import os
import re
import time
import traceback
import aiohttp

# ==================== 配置区域 ====================
# 1. 之前脚本生成的本地 json 文件路径
JSON_FILE_PATH = r"xxx.json"

# 2. 准备将 XML 文件保存到的目标文件夹
OUTPUT_DIR = r"c:\Users\xxx\Desktop"

# 3. 最大并发限制（建议控制在 10-20 之间，避免触发官方 WAF 封禁 IP）
MAX_CONCURRENT_REQUESTS = 15
# ==================================================


def sanitize_filename(filename):
    """清理文件名中的非法字符，防止写入本地时报错"""
    return re.sub(r'[\\/*?:"<>|]', "_", filename)


async def download_xml(session, semaphore, vul_name, url):
    """单个 XML 文件的异步下载任务"""
    # 从长 URL 中用正则精准提取出 CNNVD 编号（例如 CNNVD-2026-49113541）
    match = re.search(r"(CNNVD-\d+-\d+)", url)
    if match:
        filename = f"{match.group(1)}.xml"
    else:
        filename = f"{sanitize_filename(vul_name)}.xml"

    file_path = os.path.join(OUTPUT_DIR, filename)

    # 【断点续传】检查本地是否已经下载过，避免重复请求
    if os.path.exists(file_path):
        return "exists"

    # 使用信号量控制并发，防止瞬间并发过高被官方防火墙拦截
    async with semaphore:
        try:
            # 设置超时：连接 10 秒，总耗时超过 30 秒则强行断开重试
            timeout = aiohttp.ClientTimeout(connect=10, total=30)
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    content = await response.read()
                    # 异步安全写入本地二进制文件
                    with open(file_path, "wb") as f:
                        f.write(content)
                    return "success"
                elif response.status == 403:
                    return "expired"  # 明确告知该链接已经超过了 10 分钟有效期
                else:
                    return f"error_status_{response.status}"
        except Exception as e:
            print(f"❌ 下载失败: {url} - 错误信息: {e}")
            return f"failed"


async def main():
    # 自动创建本地存放 XML 的目录
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    # 1. 读取 JSON 任务列表
    try:
        with open(JSON_FILE_PATH, "r", encoding="utf-8") as f:
            vul_list = json.load(f)
    except Exception as e:
        print(f"❌ 读取 JSON 文件失败，请检查路径是否正确。错误信息: {e}")
        return

    # 过滤出含有有效 xmlContent 链接的数据
    tasks_data = [item for item in vul_list if item.get("xmlContent")]
    total_tasks = len(tasks_data)
    
    print("=" * 50)
    print(f"📂 成功加载本地数据，共检测到 {len(vul_list)} 条漏洞记录。")
    print(f"📡 其中含有有效下载链接的任务共 {total_tasks} 条。")
    print(f"⚡ 开始异步下载，最大并发数限制为: {MAX_CONCURRENT_REQUESTS} ...")
    print("=" * 50 + "\n")

    if total_tasks == 0:
        print("⚠️ 没有找到可下载的链接，任务结束。")
        return

    start_time = time.time()

    # 2. 初始化并发控制器（信号量）
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    # 3. 创建全局异步 HTTP 客户端 Session
    async with aiohttp.ClientSession() as session:
        # 批量构建异步任务推入队列
        tasks = [
            asyncio.create_task(
                download_xml(
                    session,
                    semaphore,
                    item.get("vulName", "unknown"),
                    item.get("xmlContent")
                )
            )
            for item in tasks_data
        ]

        # 并发执行所有下载任务，并等待全部返回结果
        results = await asyncio.gather(*tasks)

    # 4. 结果数据统计与可视化输出
    success_count = results.count("success")
    exists_count = results.count("exists")
    expired_count = results.count("expired")
    failed_count = len(results) - success_count - exists_count - expired_count

    elapsed_time = time.time() - start_time

    print("\n" + "=" * 50)
    print("      🎉 国家信息安全漏洞库 XML 异步下载任务完成！")
    print("=" * 50)
    print(f"⏱️  总共耗时     : {elapsed_time:.2f} 秒")
    print(f"✅ 成功下载     : {success_count} 个文件")
    print(f"🔄 跳过（已存在）: {exists_count} 个文件")
    print(f"⏳ 链接过期失效  : {expired_count} 个 (已超过官方10分钟限制)")
    print(f"❌ 下载失败/报错  : {failed_count} 个")
    print(f"📂 本地保存目录  : {OUTPUT_DIR}")
    print("=" * 50)


if __name__ == "__main__":
    try:
        # 直接启动异步主程序
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 用户手动终止了下载任务。")

