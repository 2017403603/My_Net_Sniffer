package com.company.study;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

// 以下简单的介绍一下我们药要使用的类，具体的用法请查看api文档
import org.jnetpcap.Pcap;
/**
 * Pcap这个类是一个和 libpcap和winpcap 中 pcap_t 结构等同的主要类。它用于提供一个各种
 * 库方法到java 的直接映射
 * Pcap提供几个静态方法，用来 发现网络接口，随后打开 openlive，openDead，或者
 * openOffline pcap捕获会话。以上都是返回一个 Pcap 对象。这个对象是C语言的pcap_t结构
 * java vm 地址空间的支持。任何在Pcap对象上 的 非静态操作，都会转换为使用 JNI api 匹配
 * Libpcap 中 pcap_t C 的方法来完成调用。
 * 用了以上提及的3个静态方法，一定要调用 close（） 方法来释放 Libpcap 的资源
 * 如果 Pcap已经关闭了，但是非静态方法还是调用了，那就会抛出一个 IllegalStateException
 */

import org.jnetpcap.PcapIf;
/**
 * 这个类关联的是本地的 pcap_if_t 结构，把地址模拟为链式的地址结构。只读。
 */

import org.jnetpcap.packet.PcapPacket;

/**
 * 一个pcap 的数据包，但是不能用于创建一个新的数据包，具体的结构解释于代码使用中
 */

import org.jnetpcap.packet.PcapPacketHandler;

/**
 * 一个处理，监听，回调的接口，用于在一个新的packet捕获的时候，获得通知
 */

/**
 * 以下是这个样例的输出 :
 * Ps：在ubuntu下的时候，可能会出现一些运行时刻的权限问题，不能获取设备的权限
 *
 *  Network devices found:
 *  #0: \Device\NPF_{BC81C4FC-242F-4F1C-9DAD-EA9523CC992D} [Intel(R) PRO/100 VE]
 *  #1: \Device\NPF_{E048DA7F-D007-4EEF-909D-4238F6344971} [VMware Virtual Ethernet Adapter]
 *  #2: \Device\NPF_{5B62B373-3EC1-460D-8C71-54AA0BF761C7} [VMware Virtual Ethernet Adapter]
 *  #3: \Device\NPF_GenericDialupAdapter [Adapter for generic dialup and VPN capture]
 *
 *  Choosing 'Intel(R) PRO/100 VE) ' on your behalf:
 *  Received packet at Tue Nov 03 18:52:42 EST 2009 caplen=1362 len=1362 jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=82   len=82   jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=145  len=145  jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=62   len=62   jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=164  len=164  jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=62   len=62   jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=54   len=54   jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=1073 len=1073 jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=1514 len=1514 jNetPcap rocks!
 *  Received packet at Tue Nov 03 18:52:45 EST 2009 caplen=279  len=279  jNetPcap rocks!
 */
public class ClassicPcapExample {

    /**
     * Main startup method
     *
     * @param args
     *          ignored
     */
    public static void main(String[] args) {
        List<PcapIf> alldevs = new ArrayList<PcapIf>(); // alldevs用来装载所有的network interface card，
        StringBuilder errbuf = new StringBuilder(); // 获取错误信息

        /***************************************************************************
         * 首先我们要来获取系统中的设备列表
         **************************************************************************/
        int r = Pcap.findAllDevs(alldevs, errbuf);
        /** 这个方法构造了可以用pcap_open_live()打开的所有网络设备
         * 这个列表中的元素都是 pcap_if_t，
         * name 一个指向设备名字的指针；
         * adderess 是一个接口的地址列表的第一个元素的指针；
         * flag 一个PCAP_IF_LOOPBACK标记接口是否是loopback的
         * 失败返回-1，成功返回0
         */

        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            // 如果获取失败，或者获取到列表为空，则输出错误信息，退出
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }

        System.out.println("Network devices found:");

        int i = 0;  // 遍历所有的设备
        for (PcapIf device : alldevs) {
            String description =
                    (device.getDescription() != null) ? device.getDescription()
                            : "No description available";  // 如果该设备介绍，则输出介绍
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

        PcapIf device = alldevs.get(5); // 这里在测试的时候可以根据你的可用网卡号自主判断，不一定要第一个，我用了6
        System.out
                .printf("\nChoosing '%s' on your behalf:\n",
                        (device.getDescription() != null) ? device.getDescription()
                                : device.getName());

        /***************************************************************************
         * 打开我们选中的设备
         **************************************************************************/
        int snaplen = 64 * 1024;
        // Capture all packets, no trucation 不截断的捕获所有包
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
        int timeout = 10 * 1000;           // 10 seconds in millis
        Pcap pcap =
                Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        // openlive方法：这个方法打开一个和指定网络设备有关的，活跃的捕获器

        // 参数：snaplen指定的是可以捕获的最大的byte数，
        // 如果 snaplen的值 比 我们捕获的包的大小要小的话，
        // 那么只有snaplen大小的数据会被捕获并以packet data的形式提供。
        // IP协议用16位来表示IP的数据包长度，所有最大长度是65535的长度
        // 这个长度对于大多数的网络是足够捕获全部的数据包的

        // 参数：flags promisc指定了接口是promisc模式的，也就是混杂模式，
        // 混杂模式是网卡几种工作模式之一，比较于直接模式：
        // 直接模式只接收mac地址是自己的帧，
        // 但是混杂模式是让网卡接收所有的，流过网卡的帧，达到了网络信息监视捕捉的目的

        // 参数：timeout 这个参数使得捕获报后等待一定的时间，来捕获更多的数据包，
        // 然后一次操作读多个包，不过不是所有的平台都支持，不支持的会自动忽略这个参数

        // 参数：errbuf pcap_open_live()失败返回NULL的错误信息，或者成功时候的警告信息


        if (pcap == null) {  // 如果获取的pcap是null，则返回相关的错误信息
            System.err.printf("Error while opening device for capture: "
                    + errbuf.toString());
            return;
        }

        /***************************************************************************

         * 第三步我们创建一个packet handler 处理器来从libpcap loop中接收数据包
         **************************************************************************/
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {

            public void nextPacket(PcapPacket packet, String user) {

                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                        new Date(packet.getCaptureHeader().timestampInMillis()),
                        packet.getCaptureHeader().caplen(),  // 实际捕获的长度
                        packet.getCaptureHeader().wirelen(), // 原来长度
                        user                                 // 用户信息
                );
            }
        };

        /***************************************************************************
         * Fourth we enter the loop and tell it to capture 10 packets. The loop
         * method does a mapping of pcap.datalink() DLT value to JProtocol ID, which
         * is needed by JScanner. The scanner scans the packet buffer and decodes
         * the headers. The mapping is done automatically, although a variation on
         * the loop method exists that allows the programmer to sepecify exactly
         * which protocol ID to use as the data link type for this pcap interface.
         * 第四步，将handler进入loop中并告诉它抓取10个包，其它的等以后熟悉了api使用在看看是什么意思
         **************************************************************************/
        pcap.loop(10, jpacketHandler, "jNetPcap rocks!");

        /***************************************************************************
         * 最后一定要关闭pcap，否则抛出异常
         **************************************************************************/
        pcap.close();
    }
}