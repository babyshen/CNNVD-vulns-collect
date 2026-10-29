# **核心特性**
# - 异步高并发：基于 asyncio + aiohttp 异步生态，下载速度相比传统单线程提升数十倍。
# - 智能并发控制：内置 Semaphore 信号量机制，严格限制并发数，防止因请求过猛触发官方防火墙（WAF）封禁 IP。
# - 断点续传/防重复：自动检测本地已下载文件，存在则直接跳过，节省企业带宽与接口调用额度。
# - 现代兼容性：代码已针对最新 Python 异步标准进行优化，无任何 Deprecated（弃用）警告。
# - 去重：在构建下载任务前，使用 seen_ids 过滤掉同一漏洞推送多次造成的重复条目。
#
# 修改 JSON_FILE_PATH 和 OUTPUT_DIR 两个变量为对应值	

import asyncio
import json
import os
import re
import time
import aiohttp

# ==================== 配置区域 ====================
# 1. 之前脚本生成的本地 json 文件路径
JSON_FILE_PATH = r"xxx.json"

# 2. 准备将 XML 文件保存到的目标文件夹
OUTPUT_DIR = r"D:\xml_files"

# 3. 最大并发限制（建议控制在 10-20 之间，避免触发官方 WAF 封禁 IP）
MAX_CONCURRENT_REQUESTS = 15
# ==================================================


def sanitize_filename(filename):
    """清理文件名中的非法字符，防止写入本地时报错"""
    return re.sub(r'[\\/*?:"<>|]', "_", filename)


def extract_cnnvd_id(url):
    """
    从动态签名的 AWS S3 Presigned URL 中精准剥离提取出 CNNVD 唯一编号。
    例如从 '.../CNNVD-2026-69563521.xml?X-Amz-Signature=...' 提取出 'CNNVD-2026-69563521'
    """
    match = re.search(r"(CNNVD-\d+-\d+)", url)
    if match:
        return match.group(1)
    return None


async def download_xml(session, semaphore, cnnvd_id, vul_name, url):
    """单个 XML 文件的异步下载任务"""
    if cnnvd_id:
        filename = f"{cnnvd_id}.xml"
    else:
        filename = f"{sanitize_filename(vul_name)}.xml"

    file_path = os.path.join(OUTPUT_DIR, filename)

    # 【断点续传/本地去重】检查本地磁盘是否已经存在对应 XML 文件
    if os.path.exists(file_path):
        return "exists"

    # 使用信号量控制并发，防止并发过高触发防火墙或封禁
    async with semaphore:
        try:
            # 设置超时：连接 10 秒，总耗时超过 30 秒则强行断开
            timeout = aiohttp.ClientTimeout(connect=10, total=30)
            async with session.get(url, timeout=timeout) as response:
                if response.status == 200:
                    content = await response.read()
                    # 异步安全写入本地文件
                    with open(file_path, "wb") as f:
                        f.write(content)
                    return "success"
                elif response.status == 403:
                    return "expired"  # 链接已失效（超过 10 分钟 AWS S3 鉴权有效期）
                else:
                    return f"error_status_{response.status}"
        except Exception as e:
            print(f"❌ 下载失败: {cnnvd_id or vul_name} - 错误信息: {e}")
            return "failed"


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

    # 2. JSON 内去重逻辑：基于 CNNVD ID 进行内存去重
    seen_ids = set()
    deduplicated_tasks = []
    json_duplicate_count = 0

    for item in vul_list:
        url = item.get("xmlContent")
        if not url:
            continue

        cnnvd_id = extract_cnnvd_id(url)

        # 如果提取到了 CNNVD ID 且该 ID 之前处理过，说明是参数变动引起的重复记录，直接过滤
        if cnnvd_id:
            if cnnvd_id in seen_ids:
                json_duplicate_count += 1
                continue
            seen_ids.add(cnnvd_id)

        deduplicated_tasks.append({
            "cnnvd_id": cnnvd_id,
            "vulName": item.get("vulName", "unknown"),
            "url": url
        })

    total_tasks = len(deduplicated_tasks)

    print("=" * 50)
    print(f"📂 成功加载本地数据，原始记录共 {len(vul_list)} 条。")
    print(f"🔁 过滤 JSON 内重复编号记录: {json_duplicate_count} 条。")
    print(f"📡 最终有效需下载的任务共 : {total_tasks} 条。")
    print(f"⚡ 开始异步下载，最大并发数限制为: {MAX_CONCURRENT_REQUESTS} ...")
    print("=" * 50 + "\n")

    if total_tasks == 0:
        print("⚠️ 没有符合要求的下载任务，程序结束。")
        return

    start_time = time.time()

    # 3. 初始化并发控制器（信号量）
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    # 4. 创建全局异步 HTTP 客户端 Session 并并发下载
    async with aiohttp.ClientSession() as session:
        tasks = [
            asyncio.create_task(
                download_xml(
                    session,
                    semaphore,
                    task["cnnvd_id"],
                    task["vulName"],
                    task["url"]
                )
            )
            for task in deduplicated_tasks
        ]

        # 并发执行所有下载任务
        results = await asyncio.gather(*tasks)

    # 5. 统计与可视化结果
    success_count = results.count("success")
    exists_count = results.count("exists")
    expired_count = results.count("expired")
    failed_count = len(results) - success_count - exists_count - expired_count

    elapsed_time = time.time() - start_time

    print("\n" + "=" * 50)
    print("      🎉 国家信息安全漏洞库 XML 异步下载任务完成！")
    print("=" * 50)
    print(f"⏱️  总共耗时         : {elapsed_time:.2f} 秒")
    print(f"✅ 成功下载         : {success_count} 个文件")
    print(f"🔄 跳过（本地已存在）: {exists_count} 个文件")
    print(f"🔁 跳过（JSON内重复） : {json_duplicate_count} 个记录")
    print(f"⏳ 链接过期失效      : {expired_count} 个 (已超过官方10分钟限制)")
    print(f"❌ 下载失败/报错      : {failed_count} 个")
    print(f"📂 本地保存目录      : {OUTPUT_DIR}")
    print("=" * 50)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 用户手动终止了下载任务。")
