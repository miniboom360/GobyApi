# GobyApi
<p align="center">
    <img width="350" src="img/goby.jpg"/>
<p>
<p align="center">
        <img src="https://img.shields.io/badge/license-MIT-blue" />
    <img src="https://img.shields.io/badge/build-passing-brightgreen">
        <img src="https://img.shields.io/badge/golang-100%25-brightgreen" />
</p>

这个库致力于将Goby API梳理和整合，以更简便的方式供gopher开发者使用，将Goby的资产梳理和漏洞扫描赋能给go开发者。



## Goby是什么

Goby是一款基于网络空间测绘技术的新一代网络安全工具，它通过给目标网络建立完整的资产知识库，进行网络安全事件应急与漏洞应急。

Goby可提供最全面的资产识别，目前预置了超过10万种规则识别引擎，能够针对硬件设备和软件业务系统进行自动化识别和分类，全面的分析出网络中存在的业务系统。Goby可提供最快速对目标影响最小的扫描体验，通过非常轻量级地发包能够快速的分析出端口对应的协议信息。Goby也为安全带来了高效，Goby预置了最具攻击效果的漏洞引擎，覆盖Weblogic，Tomcat等最严重漏洞。并且每日更新会被用于真实攻击的漏洞。

除了Goby预置的漏洞，Goby还提供了可以自定义的漏洞检查框架，发动互联网的大量安全从业者贡献POC，保证持续的应急响应能力。



## 为什么用go开发gobyApi库

因为目前大部分渗透工具使用的python而不是go，随着go语言在工程化能力和性能的优势越来越明显，越来越多的组织和武器替代python采用了go开发。

而目前市面上没有很好的支持Goby的开发库，用于赋能安全系统和自动化攻防，所以基于这个目的我开发了go语言版本的gobyApi库。



## 适用人群

+ 红蓝队，将goby集成自动化攻防系统

+ 甲方安全建设，用goby赋能漏扫和资产搜集
+ go语言爱好者

## 如何使用

### 开启goby内置server

+ linux/macos

  cd到goby/golib开启goby server

  ```
  ./goby-cmd  -mode api -bind 0.0.0.0:8361
  ```

  

+ windows

  找到goby/golib，cmd或者powershell执行

  ```bash
  .\goby-cmd.exe -mode api -bind 0.0.0.0:8361
  ```

出现以下日志，即启动成功

```
2021/04/06 15:39:30 Grab version:  grab_version_1.7.1.1
2021/04/06 15:39:33 Support 276  protocols, 695  ports
2021/04/06 15:39:33 <nil>
2021/04/06 15:39:33 Version: v1.24.262+beta
2021/04/06 15:39:33 API Server listen at  0.0.0.0:8361
```



### 使用gobyApi

获取库

```bash
go get gihub.com/miniboom360/GobyApi
```

使用示例

```go
package main

import (
	"fmt"
	"context"
	gobyApi "github.com/miniboom360/GobyApi"
	"time"
)

func main() {
    //扫描超时设置
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute * 30)
	defer cancel()
	ips := make([]string, 0)
	ips = append(ips,"172.31.10.10")
    
    // NewGobyApi(ips, remoteGobyServer, portScope, ctx)
    // ips：需要扫描的IP，支持整段扫描，比如 172.31.13.199/24、172.31.13.199-255
    // remoteGobyServer：远程goby server地址，注意不用URL最后不用加"/"，本地填""
    // portScope：1-65535，可自定义
    // ctx：设置的超时时间
	g := gobyApi.NewGobyApi(ips,"http://172.31.13.199:8361","1000-6000",ctx)

	//localhost
	//g := gobyApi.NewGobyApi(ips,"","1000-5000",ctx)

	g.StartScan()
	//fmt.Printf("g is %#v", g)
	if g.ScanStatus {
		fmt.Println("StartScan is scuess, over!")
	}

	m, err := g.GetAsserts()
	if err !=nil{
		fmt.Println(err)
		return
	}
	fmt.Printf("details = %#v\n", m)

	vuln, err := g.GetVulns()
	if err != nil{
		panic(err)
	}
	fmt.Println(vuln)
}
```

## 小tips
gobyApi内置调度器，确保goby的扫描效率前提情况下，分块进行请求，每次5个IP，一轮成功后再进行下一轮。但是调用方不感知，直接使用gobyApi返回的taskId即可获取所有扫描任务结果。


## TODO

欢迎小伙伴们反馈。







