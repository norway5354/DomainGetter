import requests
import json
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import time
from bs4 import BeautifulSoup
import tldextract
import subprocess
import datetime


class DomainGetter:
    result_domain_list = []

    def __init__(self):
        with open('input.json', 'r') as f:
            input_data = json.load(f)
            self.organize = input_data['organize']
            self.primary_domain = input_data['primary_domain']
            print("组织名：{}".format(self.organize))
            print("主域名：{}".format(self.primary_domain))
        pass

    def run_subfinder(self):
        """
        运行subfinder搜集域名
        :return:
        """
        command = 'subfinder -d {} -all -silent -duc'.format(self.primary_domain)
        try:
            # 使用subprocess.run来运行命令
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)

            # 打印命令输出
            domain_list = result.stdout
            # print(domain_list)
            self.result_domain_list.extend(domain_list.splitlines())

        except subprocess.CalledProcessError as e:
            # 如果命令执行失败，捕获异常并打印错误信息
            print(f"Error executing command: {e}")
            print(f"Command output: {e.output}")


    def check_reverse_whois(self):
        """
        检查反向whois
        :return:
        """
        url = "https://reverse-whois.whoisxmlapi.com/api/v2"
        payload = {
            "apiKey": "at_5Rao2Fn4hARnSfN1vOoVtftvMNXN7",
            "searchType": "current",
            "mode": "purchase",
            "punycode": True,
            "basicSearchTerms": {
                "include": [
                    self.organize
                ],
                "exclude": [
                ]
            }
        }
        json_payload = json.dumps(payload)
        try:
            response = requests.post(url=url, data=json_payload)
            # 检查请求是否成功
            if response.status_code == 200:
                # print("请求成功:")
                # print(response.json())  # 输出API的响应内容
                domains_list = response.json().get("domainsList", [])
                self.result_domain_list.extend(domains_list)
                # contents = "\n".join(domains_list)
                # with open(output_file, "w") as file:
                #     file.write(contents)
            else:
                print(f"请求失败: {response.status_code}")
                print(response.text)  # 输出错误信息
        except requests.exceptions.RequestException as e:
            print(f"请求异常: {e}")

    def check_crt(self):
        """
        crt.sh查域名
        :return:
        """
        # 定义URL和参数
        url = "https://crt.sh/"
        params = {
            "q": "AT&T Services, Inc.",
            "output": "json"
        }
        max_retries = 5
        timeout = 90
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,  # 每次重试之间的等待时间增加
            status_forcelist=[500, 502, 503, 504],  # 重试的状态码
        )
        headers = {
            'Sec-Ch-Ua': '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"Windows"',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-User': '?1',
            'Sec-Fetch-Dest': 'document',
            'Referer': 'https://crt.sh/',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'zh-CN,zh-TW;q=0.9,zh;q=0.8',
            'Priority': 'u=0, i'
        }

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount('https://', adapter)
        session.mount('http://', adapter)

        for attempt in range(max_retries + 1):
            try:
                response = session.get(url, params=params, timeout=timeout,headers=headers)
                if response.status_code == 200:
                    return response.json()  # 返回JSON响应内容
                else:
                    print(f"第 {attempt + 1} 次请求失败，状态码: {response.status_code}")
                    if attempt < max_retries:
                        print("等待并重试...")
                        time.sleep(2 ** attempt)  # 指数退避等待
                    else:
                        print("达到最大重试次数，放弃请求。")
            except requests.exceptions.RequestException as e:
                print(f"请求异常: {e}")
                if attempt < max_retries:
                    print("等待并重试...")
                    time.sleep(2 ** attempt)  # 指数退避等待
                else:
                    print("达到最大重试次数，放弃请求。")

    def check_buildwith(self):
        """
        buildwith获取根域名
        :return:
        """
        url = "https://builtwith.com/redirects/{}".format(self.primary_domain)
        try:
            response = requests.get(url)
            response.raise_for_status()  # 检查请求是否成功

            # 打印响应内容
            soup = BeautifulSoup(response.text, 'html.parser')
            for a_tag in soup.find_all('a', href=lambda href: href and 'redirects' in href):
                link_text = a_tag.get_text(strip=True)
                # 使用tldextract提取域名部分
                domain = tldextract.extract(link_text)

                # 检查是否有有效的域名部分
                if domain.domain and domain.suffix:
                    # 组合成完整的域名
                    full_domain = f"{domain.domain}.{domain.suffix}"
                    self.result_domain_list.append(full_domain)
                    # print(full_domain)
        except requests.exceptions.RequestException as e:
            print(f"请求发生错误: {e}")

    def check_httpx(self):
        """
        httpx测活
        :return:
        """
        # 准备要传递给httpx的数据，这里使用一个示例文本
        data = "\n".join(self.result_domain_list)

        # 启动httpx进程并通过标准输入传递数据
        try:
            # 使用subprocess.Popen启动httpx进程
            # 设置stdin=subprocess.PIPE使得我们可以通过标准输入传递数据
            # 设置stdout=subprocess.PIPE使得我们可以捕获httpx的输出
            # text=False表示处理二进制数据
            process = subprocess.Popen(["httpx", "-nf", "-silent"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

            # 将数据写入httpx的标准输入
            process.stdin.write(data)
            process.stdin.close()  # 关闭标准输入，通知httpx输入结束

            # 读取httpx的输出
            output = process.stdout.read()

            # 打印httpx的输出
            print(output.strip())
            self.result_domain_list = output.strip().splitlines()

            # 等待httpx进程结束
            process.wait()

        except Exception as e:
            print("Error:", e)


if __name__ == "__main__":
    # 获取当前日期
    current_date = datetime.datetime.now().strftime("%Y%m%d")
    obj = DomainGetter()
    print("正在进行反向Whois查询.")
    obj.check_reverse_whois()
    print("正在进行Buildwith查询..")
    obj.check_buildwith()
    print("正在进行Subfinder查询...")
    obj.run_subfinder()
    obj.result_domain_list = list(set(obj.result_domain_list))  # 去重

    print("正在进行httpx测活....")
    obj.check_httpx()  # 测活
    output_file = "{}-{}.txt".format(current_date, obj.primary_domain)
    with open(output_file, 'w') as f:
        f.write('\n'.join(obj.result_domain_list))
    print("结果输出到【{}】".format(output_file))

    pass
