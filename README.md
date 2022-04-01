# My_Net_Sniffer
此仓库用于软件系统与安全课程网络嗅探器实验

# **网络嗅探器设计与实现**

作者：程哥哥  学号：xxxx

引言：

此程序是由自己编写的个人网络嗅探器，相当于著名的包捕获软件[Wireshark](https://so.csdn.net/so/search?q=Wireshark&spm=1001.2101.3001.7020)的简化版，界面参考至别人的博客，由JFrame编写，主要业务逻辑基于JnetPcap开发，程序框架为MVC。主要功能如下：

\1. 实现了运行主机网卡选择进行抓包 

\2. 实现了IOS五层模型下所有数据包的捕获及显示 

\3. 实现了抓取的数据包从链路层到应用层的逐层包头的信息展示及分析 

\4. 实现了Ethernet、IP、ARP、ICMP、UDP、TCP、HTTP七种数据包的过滤及分析 

\5. 实现了源ip、目的ip、及包携带内容的关键字过滤功能 

\6. 实现了基于IP+Port的TCP流追踪功能

\7. 实现了所分析的包内容的数据保存。

Github地址：https://github.com/2017403603/My_Net_Sniffer

### 一、**开发环境**

Win10+IDEA+Jdk1.8+Wincap+Jnetpcap  

UI界面参考：https://blog.csdn.net/qq_34838643/article/details/78891127

Jnetpcap教程参考：https://blog.csdn.net/m0_37892044/article/details/120085261

### 二、**Jnetpcap**

Jnetpcap是一个Java网络抓包工具，Java平台本身不支持底层网络操作，需要第三方包利用JNI封装不同系统的C库来提供Java的上层接口，常用的类库包括 JPcap，JNetPcap等，他们都是基于[TcpDump](https://so.csdn.net/so/search?q=TcpDump&spm=1001.2101.3001.7020)/LibPcap的Java封装。

jNetPcap是 [libpcap](http://jnetpcap.com/)的一个Java完整封装。jNetPcap使用与libpcap相同风格的API。libpcap是unix/linux平台下的网络数据包捕获函数库，大多数网络监控软件都以它为基础。 Libpcap可以在绝大多数类unix平台下工作。Libpcap提供了系统独立的用户级别网络数据包捕获接口，并充分考虑到应用程序的可移植性。

### 三、**主要类及函数**

个人认为直接放代码没有意义，这里把主要类和函数功能说清楚，代码可以自行在github上下载运行。

View层:

Main.class：程序入口类

AppFrame.class：UI界面类

dataInjection()：数据填充

Control层：

AnalyzePackage.class：数据包分析类

Analyzed()：返回一个hashmap里面存储数据包的基本分析内容

parseSrcMac()、parseDestMac()：分析数据包的源MAC、目的MAC

parseProtocol()：分析数据包的协议类型

handleSrcIp()、handleDestIp()：分析数据包的源IP和目的IP地址

parseSrcPort()、parseDesPort()：分析数据包的源主机端口和目的主机端口

parseData()：获取到数据包携带的内容

handleHttp()：分析http数据包获得请求头参数及值，获取http中请求的传输报文

CapturePackage.class：线程类，run()方法负责数据包的抓取

MyPcapHandler.class：数据包处理类，每个被抓取到的数据包都会在这里被处理

NetworkCard.class：网卡类，负责返回本机的所有网卡参数

HandlerInfo.class：负责界面view与control之间的消息传递

ShowAfterFilter()：负责每次数据包过滤后界面数据包的重新显示

showTable()：负责数据包在界面表格的回显及显示信息处理

FilterUtils.class：过滤工具类，提供数据包条件筛选服务

IsFilter()：根据传入参数条件判断数据包是否被过滤

Istrace()：根据传入参数的IP和Port判断数据包是否被跟踪

Model层：无

### 四、**运行截图**

具体运行情况可以查看演示视频，以下为软件运行简要展示。

\1. **主界面**

主页面可以显示抓取到的数据包的时间、源IP或者源MAC地址、目的IP或者目的MAC地址、数据包协议、数据包原始长度，如下图所示：

<img src=".\图片存储\1.jpg" alt="img" style="zoom: 67%;" /> 

\2. **过滤条件**

<img src=".\图片存储\2.jpg" alt="img" style="zoom:67%;" />  <img src="file:///C:\Users\程哥哥\AppData\Local\Temp\ksohtml\wps2231.tmp.jpg" alt="img" style="zoom:67%;" />

​                （图1）                                                                            （图2）

<img src=".\图片存储\4.jpg" alt="img" style="zoom: 67%;" /> <img src=".\图片存储\5.jpg" alt="img" style="zoom:67%;" /> <img src=".\图片存储\6.jpg" alt="img" style="zoom:67%;" />

​                  （图3）                                             （图4）                                              （图5）

<img src=".\图片存储\7.jpg" alt="img" style="zoom:67%;" /> 

​																（图6）

其中图1为点击主界面“网卡”菜单项的展示情况，所显示为运行程序主机的网卡列表，可选择具体网卡进行抓包展示；

图2为点击主界面“协议”菜单项的展示情况，可选择想要过滤的数据包类型对抓取的数据包进行过滤；

图3为点击主界面“源IP”菜单项的展示情况，输入想要过滤的源IP地址，点击确认可以过滤不是所输入的源IP地址的数据包；

图4为点击主界面“目的IP”菜单项的展示情况，输入想要过滤的目的IP地址，点击确认可以过滤不是所输入的目的IP地址的数据包；

图5为点击主界面“查找”菜单项的展示情况，输入想要过滤的关键字内容，点击确认可以对捕获的数据包所携带的的具体包内容进行过滤；

图6为点击主界面“IP+Port流追踪”菜单项的展示情况，输入想要追踪的IP地址和Port端口(输入格式为 IP地址:Port端口)，点击确认可以追踪具体IP主机下具体Port端口的所有进出TCP数据包

\3. **数据包内容展示**

<img src=".\图片存储\8.jpg" alt="img" style="zoom:67%;" /> <img src=".\图片存储\9.jpg" alt="img" style="zoom:67%;" />

​    							   （图7）                                										    （图8）

<img src=".\图片存储\10.jpg" alt="img" style="zoom:67%;" /> <img src=".\图片存储\11.jpg" alt="img" style="zoom:67%;" />

​        （图9）                     （图10）

<img src=".\图片存储\12.jpg" alt="img" style="zoom:67%;" />   <img src=".\图片存储\13.jpg" alt="img" style="zoom:67%;" />

​      										 （图11）                                                       （图12） 

图7为在cmd窗口ping网址www.baidu.com的截图；图8为ping成功后选择只筛选ARP数据包的数据包列表；图9为ping成功后选择只筛选ICMP数据包的数据包列表；图10为只筛选HTTP数据包的数据包列表；

图11为点击一个ARP数据包的具体内容展示，数据展示从链路层Ethernet数据包头逐层开始；图12为点击一个ICMP数据包的具体内容展示，数据展示从链路层Ethernet数据包头逐层开始，之后展示IP头信息，最后是ICMP数据包具体内容；

图13、图14为点击一个HTTP数据包的具体内容展示，分析内容从链路层到应用层的逐层包头的信息展示

 <img src=".\图片存储\14.jpg" alt="14" style="zoom:67%;" /><img src=".\图片存储\15.jpg" alt="img" style="zoom:67%;" />

​    								（图13） 												                  （图14）

 <img src=".\图片存储\16.jpg" alt="img" style="zoom:67%;" /> <img src=".\图片存储\17.jpg" alt="17" style="zoom: 67%;" />

​            						 （图15）              													    （图16）

图15为追踪IP地址为192.138.1.106，Port端口为57598的TCP流演示，在输入框里输入192.138.1.106:57598；图16为TCP流追踪结果数据包列表。

### 五、**总结**

本程序从编写到结束一共历时五天左右，在此过程中由于不熟悉Jnetpcap包的使用，在阅读Jnetpcap包文档上花费了大量时间，项目框架采用经典mvc，写到后面的时候，代码有点乱，因此整个程序耦合度有些高，代码可读性应该还算说得过去。后期又花费了一些时间增强代码的健壮性，程序现有功能方面个人觉得完整度还行。由于时间原因，成程序只实现了Ethernet、IP、ARP、ICMP、UDP、TCP、HTTP七种数据包的过滤及分析，本程序还存在两个比较明显的问题，至今没想到解决办法：

\1. 程序选择网卡启动抓包线程有一定几率失败（盲猜应该是防火墙的原因）

\2. 程序抓包时，在遇到流量较大情况，会出现漏包现象。（应该是以太网网速太快，抓包速率跟不上的原因）
