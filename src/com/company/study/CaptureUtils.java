package com.company.study;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

/**
 * @Description:抓包工具类
 * @author:hutao
 * @mail:hutao_2017@aliyun.com
 * @date:2021年9月2日
 */
public class CaptureUtils {

    /**
     * @Description:获取网络适配器,当返回List<PcapIf>为空时，说明未获取到网卡
     * @author:hutao
     * @mail:hutao_2017@aliyun.com
     * @date:2021年9月2日
     */
    public static List<PcapIf> getPcapIf() {
        StringBuilder errbuf = new StringBuilder();
        //定义网卡列表
        List<PcapIf> ifs = new ArrayList<PcapIf>();
        /* 返回值是一个整数结果代码，就像在 C 计数器部分一样。
         * ifs 列表中填充了从 C 函数调用 findAllDevs 返回的相应 C 结构 pcap_if 链表中找到的所有网络设备。
         */
        int statusCode = Pcap.findAllDevs(ifs, errbuf);
        if(statusCode != Pcap.OK){
            System.err.println("获取网卡失败：" + errbuf.toString());
        }
        return ifs;
    }

    /**
     * @Description:开始捕获数据包
     * @param
     * @author:hutao
     * @mail:hutao_2017@aliyun.com
     * @date:2021年9月2日
     */
    public static void capturePcap(PcapIf device) {
        //截断此大小的数据包
        int snaplen = Pcap.DEFAULT_JPACKET_BUFFER_SIZE;

        int promiscous = Pcap.MODE_PROMISCUOUS;

        //以毫秒为单位
        int timeout = 60 * 1000;
        //如果发生错误，它将保存一个错误字符串。 错误打开 Live 将返回 null
        StringBuilder errbuf = new StringBuilder();

        Pcap pcap = Pcap.openLive(device.getName(),snaplen,promiscous,timeout,errbuf);
        if(pcap == null) {
            System.err.println("获取数据包失败：" + errbuf.toString());
        }

        CustomPcapHandler<Object> handler = new CustomPcapHandler<Object>();
        // 捕获数据包计数
        int cnt = 1;
        //我们要发送到处理程序的自定义对象
        PrintStream out = System.out;
        while(true) {
            //每个数据包将被分派到抓包处理器Handler
            pcap.loop(cnt, handler, out);
        }
        //pcap.close();
    }
}
