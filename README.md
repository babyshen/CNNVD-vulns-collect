通过官方API接口进行漏洞信息批量获取

官方文档：
[《国家信息安全漏洞库（CNNVD）漏洞XML信息获取接口文档》](https://www.cnnvd.org.cn/frontend/specDocDownload)

如何申请 AppID？

登录 CNNVD 官网[www.cnnvd.org.cn](https://www.cnnvd.org.cn)→ 完成企业实名认证 → 进入“单位中心” →“账号安全” → “OpenAPI 密钥管理” → 申请生成 API 密钥。

> 可通过修改脚本中 `publishStartDate` `publishEndDate` `updateStartDate` `updateEndDate` 四个值来获取指定日期的漏洞信息

### 一、CNNVD-API-GET-VUL-XML.py 脚本说明

>  此脚本没有自动翻页获取，需要手动指定

返回结果如下：

```python
{
    "code": 200,
    "success": true,
    "message": "操作成功",
    "data": {
        "total": 775,
        "records": [
            {
                "vulId": null,
                "vulName": "Drupal SAML SSO - Service Provider 跨站脚本漏洞",
                "published": null,
                "lastModified": "2026-10-23 16:25:48",
                "xmlContent": "https://www.cnnvd.org.cn/cnnvd-vul-xml/u2/year-2026/CNNVD-2026-49113541.xml?response-content-disposition=attachment%3B%20filename%3D%22CNNVD-2026-49113541.xml%22&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=vul%2F20261026%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261026T005826Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=aec82c673517a2f4c65b560010940dd3307666a686c5ff6714450cbc1d4e73f6",
                "status": "ready"
            }
        ],
        "pageIndex": 1,
        "pageSize": 1
    },
    "time": "2026-10-26 08:58:26"
}
```


### 二、CNNVD-API-GET-ALL-VUL-XML.py 脚本说明

> 此脚本加入了自动翻页功能，可一次全量获取数据，同时可把数据以 JSON 格式存入本地文件

输出结果如下：

```
开始自动翻页获取数据...
成功获取第 1 页，本页 20 条，累计已获取 20 / 52 条
成功获取第 2 页，本页 20 条，累计已获取 40 / 52 条
成功获取第 3 页，本页 12 条，累计已获取 52 / 52 条
所有数据已抓取完毕！

--- 抓取完成 ---
共收集到漏洞数据: 52 条
数据已成功保存至: c:\Users\xxx\Desktop\cnnvd_vulns-2026-10-27.json
```

本地 json 部分内容如下：

```
[
    {
        "vulId": null,
        "vulName": "meta box 授权问题漏洞",
        "published": null,
        "lastModified": "2026-08-03 17:01:55",
        "xmlContent": "https://www.cnnvd.org.cn/cnnvd-vul-xml/u2/year-2026/CNNVD-2026-99304038.xml?response-content-disposition=attachment%3B%20filename%3D%22CNNVD-2026-99304038.xml%22&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=vul%2F20261027%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20261027T062506Z&X-Amz-Expires=600&X-Amz-SignedHeaders=host&X-Amz-Signature=50460598155639c1c77aa87f1939397d75121c2ef2ec4602ec5ace90925d4324",
        "status": "ready"
    },
    ......
]   
```

**其中 xmlContent 为 XML 文件下载链接，有效期 10 分钟，在有效期内通过该链接下载 XML 文件。**

XML 文件内容如下：

```
<cnnvd publisher="中国国家漏洞库" date="2026-10-23" date_range="2026年" format="增强版">
<cnnvd_items>
<cnnvd_id>CNNVD-2026-49113541</cnnvd_id>
<cve_id>CVE-2026-87949</cve_id>
<name>Drupal SAML SSO - Service Provider 跨站脚本漏洞</name>
<vendor>Drupal</vendor>
<product>SAML SSO - Service Provider</product>
<vuln_descript>Drupal SAML SSO - Service Provider是Drupal组织的一款为内容管理站点提供SAML单点登录服务提供方能力的身份认证扩展模块。Drupal SAML SSO - Service Provider 0.0.0版本至3.2.0版本存在跨站脚本漏洞，该漏洞源于网页生成期间输入中和不当，可能导致跨站脚本攻击。</vuln_descript>
<vuln_type>跨站脚本</vuln_type>
<severity>
<technicalseverity>低危</technicalseverity>
<overallseverity>低危</overallseverity>
</severity>
<published>2026-10-23</published>
<modified>2026-10-23</modified>
<references>
<reference>
<url>https://www.drupal.org/sa-contrib-2026-147</url>
</reference>
</references>
<patch_url>https://www.drupal.org/sa-contrib-2026-147</patch_url>
</cnnvd_items>
</cnnvd>
```
> XML 文件包含CNNVD编号、CVE 编号、名称、厂商、产品、描述、类型、危害等级（技术分级和综合分级）、发布时间、参考链接、补丁地址等信息，部分漏洞还包含PAV信息。

XML 文件详细解释 可参考 [《国家信息安全漏洞库(CNNVD) 网络安全漏洞信息XML描述规范》](https://www.cnnvd.org.cn/frontend/specDocDownload)

PAV 详细解释 可参考  [《国家信息安全漏洞库(CNNVD) 网络安全受漏洞影响产品描述规范》](https://www.cnnvd.org.cn/frontend/specDocDownload)

> 个人和企业用户也可通过注册实名认证之后，进行漏洞数据下载。

### 三、CNNVD-async-download.py 脚本说明
由于 CNNVD 官方 OpenAPI 返回的 XML 详情下载链接仅有 10 分钟有效期，本项目采用 Python Asyncio 异步高并发架构，实现海量 XML 漏洞详情文件的秒级高速下载，确保链接过期前数据完整落盘。针对上游脚本 `CNNVD-API-GET-ALL-VUL-XML.py` 生成的本地 JSON 文件进行批量下载。
 
**核心特性**
- 异步高并发：基于 asyncio + aiohttp 异步生态，下载速度相比传统单线程提升数十倍。
- 智能并发控制：内置 Semaphore 信号量机制，严格限制并发数，防止因请求过猛触发官方防火墙（WAF）封禁 IP。
- 断点续传/防重复：自动检测本地已下载文件，存在则直接跳过，节省企业带宽与接口调用额度。
- 现代兼容性：代码已针对最新 Python 异步标准进行优化，无任何 Deprecated（弃用）警告。

修改顶部的 配置区域 参数：
```
# ==================== 配置区域 ====================
# 1. 核心上游脚本 CNNVD-API-GET-ALL-VUL-XML.py 生成的本地 JSON 文件绝对路径
JSON_FILE_PATH = r"xxx.json"

# 2. 准备将 XML 文件保存到的本地目标文件夹
OUTPUT_DIR = r"./xml_files"

# 3. 最大并发限制（建议控制在 10-20 之间，避免触发官方风控）
MAX_CONCURRENT_REQUESTS = 15
# ==================================================
```
输出结果如下：
```
📂 成功加载本地数据，共检测到 52 条漏洞记录。
📡 其中含有有效下载链接的任务共 52 条。
⚡ 开始异步下载，最大并发数限制为: 15 ...
==================================================

==================================================
      🎉 国家信息安全漏洞库 XML 异步下载任务完成！
==================================================
⏱️  总共耗时     : 0.84 秒
✅ 成功下载     : 52 个文件
🔄 跳过（已存在）: 0 个文件
⏳ 链接过期失效  : 0 个 (已超过官方10分钟限制)
❌ 下载失败/报错  : 0 个
📂 本地保存目录  : D:\xml_files
==================================================
```
