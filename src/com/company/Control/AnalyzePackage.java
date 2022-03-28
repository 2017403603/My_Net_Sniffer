package com.company.Control;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.JProtocol;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @ClassName AnalyzePackage  //类名称
 * @Description: 类描述
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/27 14:02	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/27 14:02	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
 */

public class AnalyzePackage {
    //协议类型
    private static Ethernet eth = new Ethernet();
    private static Ip4 ip4 = new Ip4();
    private static Ip6 ip6 = new Ip6();
    private static Icmp icmp = new Icmp();
    private static Arp arp = new Arp();
    private static Udp udp = new Udp();
    private static Tcp tcp = new Tcp();
    private static Http http = new Http();
    //要分析的包
    static PcapPacket packet;
    //分析结果
    static HashMap<String, String> analyzeResult;

    //分析包赋值
    public AnalyzePackage(PcapPacket packet) {
        this.packet = packet;
    }

    //一层一层分析并且获得信息
    public static HashMap<String, String> Analyzed() {
        //初始化
        analyzeResult = new HashMap<String, String>();
        analyzeResult.put("协议", parseProtocol());
        analyzeResult.put("发送时间", new Date(packet.getCaptureHeader().timestampInMillis()).toString());
        analyzeResult.put("源MAC", parseSrcMAC());
        analyzeResult.put("目的MAC", parseDestMac());
        String srcLG = Long.toString(eth.source_LG());//0为出厂MAC，1为分配的MAC
        String srcIG = Long.toString(eth.source_IG());//0为单播，1为广播
        String destLG = Long.toString(eth.destination_LG());//0为出厂MAC，1为分配的MAC
        String destIG = Long.toString(eth.destination_IG());//0为单播，1为广播
        analyzeResult.put("源MAC地址类型", srcLG=="0"?"出厂MAC":"分配的MAC");
        analyzeResult.put("目的MAC地址类型", destLG=="0"?"出厂MAC":"分配的MAC");
        analyzeResult.put("源主机传播方式", srcIG=="0"?"单播":"广播");
        analyzeResult.put("目的主机传播方式", destIG=="0"?"单播":"广播");
        handleSrcIp();
        handleDestIp();
        analyzeResult.put("源端口", parseSrcPort());
        analyzeResult.put("目的端口", parseDestMac());
        String ack,seq;
        if (packet.hasHeader(tcp)) {
            ack = Long.toString(tcp.ack());
            seq = Long.toString(tcp.seq());
        } else {
            ack = seq = null;
        }
        analyzeResult.put("Ack序号", ack==null?"无":ack);
        analyzeResult.put("Seq序号", seq==null?"无":seq);
        boolean ifUseHttp = packet.hasHeader(http);
        analyzeResult.put("是否使用http协议", String.valueOf(ifUseHttp));
        analyzeResult.put("包内容", parseData());
        return analyzeResult;
    }
    //解析出源Mac地址
    private static String parseSrcMAC() {
        if (packet.hasHeader(eth)) { // 如果packet有eth头部
            return FormatUtils.mac(eth.source());
        }else{
            return "未知";
        }
    }
    //解析出目的Mac地址
    private static String parseDestMac() {
        if (packet.hasHeader(eth)) { // 如果packet有eth头部
            return FormatUtils.mac(eth.destination());
        }else{
            return "未知";
        }
    }
    //解析出协议类型
    public static String parseProtocol() {
        //逆向遍历协议表找到最精确（最高层）的协议名
        JProtocol[] protocols = JProtocol.values();
        for (int i = protocols.length - 1; i >= 0; i--) {
            if (packet.hasHeader(protocols[i].getId())) {
                return protocols[i].name();
            }
        }
        return null;
    }
    //ip有ip4，ip6
    //解析出源ip
    private static void handleSrcIp() {
        analyzeResult.put("源IP4","未知");
        analyzeResult.put("源IP6","未知");
        if (packet.hasHeader(ip4)) { // 如果packet有ip头部
            analyzeResult.put("源IP4",FormatUtils.ip(ip4.source()));
        }
        if (packet.hasHeader(ip6)) {
            analyzeResult.put("源IP6",FormatUtils.ip(ip6.source()));
        }
        return ;
    }

    //解析出目的ip
    private static void handleDestIp() {
        analyzeResult.put("目的IP4","未知");
        analyzeResult.put("目的IP6","未知");
        if (packet.hasHeader(ip4)) { // 如果packet有ip头部
            analyzeResult.put("目的IP4",FormatUtils.ip(ip4.destination()));
        }
        if (packet.hasHeader(ip6)) {
            analyzeResult.put("目的IP6",FormatUtils.ip(ip6.destination()));
        }
        return ;
    }
    //解析出源port
    private static String parseSrcPort() {
        if (packet.hasHeader(tcp)) {
            return String.valueOf(tcp.source());
        }else {
            return "未知";
        }
    }
    //解析出目的port
    private static String parseDesPort() {
        if (packet.hasHeader(tcp)) {
            return String.valueOf(tcp.destination());
        }else {
            return "未知";
        }
    }
    //解析包内容
    private static String parseData() {
        byte[] buff = new byte[packet.getTotalSize()];
        packet.transferStateAndDataTo(buff);
        JBuffer jb = new JBuffer(buff);
        String content = jb.toHexdump();
        return content;
    }

}
