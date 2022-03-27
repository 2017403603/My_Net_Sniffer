package com.company.Control;

import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

import java.net.InetAddress;
import java.net.UnknownHostException;
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
    private static Ip4 ip = new Ip4();
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
        analyzeResult.put("源IP", "未知");
        analyzeResult.put("目的IP", "未知");
        analyzeResult.put("包内容", " ");
        //抓取的包有协议头Ethernet
        if (packet.hasHeader(Ethernet.ID)) {
            handleEthernet();
        }
        //抓取的包有协议头IP
        if (packet.hasHeader(ip)) {
            handleIp();
        }
        //抓取的包有协议头ICMP
        if (packet.hasHeader(icmp)) {
            handleIcmp();
        }
        //抓取的包有协议头ARP
        if (packet.hasHeader(arp)) {
            handleArp();
        }
        //抓取的包有协议头UDP
        if (packet.hasHeader(udp)) {
            handleUdp();
        }
        //抓取的包有协议头TCP
        if (packet.hasHeader(tcp)) {
            handleTcp();
        }
        //抓取的包有协议头HTTP
        if (packet.hasHeader(http)) {
            handleHttp();
        }
        return analyzeResult;
    }

    //获得String类型的mac地址
    public static String asString(byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0) {
                buf.append(':');
            }
            if (b >= 0 && b < 16) {
                buf.append('0');
            }
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }

    public static void handleEthernet() {
        eth = packet.getHeader(eth);
        byte[] dstMac = eth.destination();
        byte[] srcMac = eth.source();
        int type = eth.type();
        analyzeResult.put("协议", "Ethernet II");
        analyzeResult.put("源MAC", asString(srcMac));
        analyzeResult.put("目的MAC", asString(dstMac));
    }

    public static void handleIp() {
        ip = packet.getHeader(ip);
        byte[] sIP = new byte[4], dIP = new byte[4];
        sIP = ip.source();
        dIP = ip.destination();
        String srcIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
        String dstIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
        analyzeResult.put("协议", "IP");
        analyzeResult.put("源IP", srcIP);
        analyzeResult.put("目的IP", dstIP);
    }

    public static void handleIcmp() {
        icmp = packet.getHeader(icmp);
        byte[] buff = new byte[packet.getTotalSize()];
        packet.transferStateAndDataTo(buff);
        JBuffer jb = new JBuffer(buff);
        String content = jb.toHexdump();
        analyzeResult.put("包内容", content);
        analyzeResult.put("协议", "ICMP");
    }

    public static void handleArp() {
        arp = packet.getHeader(arp);
        byte[] buff = new byte[packet.getTotalSize()];
        packet.transferStateAndDataTo(buff);
        JBuffer jb = new JBuffer(buff);
        String content = jb.toHexdump();
        analyzeResult.put("包内容", content);
        analyzeResult.put("协议", "ARP");
    }

    public static void handleTcp() {
        tcp = packet.getHeader(tcp);
        String srcPort = String.valueOf(tcp.source());
        String dstPort = String.valueOf(tcp.destination());
        analyzeResult.put("源端口", srcPort);
        analyzeResult.put("目的端口", dstPort);
        byte[] buff = new byte[packet.getTotalSize()];
        packet.transferStateAndDataTo(buff);
        JBuffer jb = new JBuffer(buff);
        String content = jb.toHexdump();
        analyzeResult.put("包内容", content);
        analyzeResult.put("协议", "TCP");
    }

    public static void handleUdp() {
        udp = packet.getHeader(udp);
        String srcPort = String.valueOf(udp.source());
        String dstPort = String.valueOf(udp.destination());
        analyzeResult.put("源端口", srcPort);
        analyzeResult.put("目的端口", dstPort);

        byte[] buff = new byte[packet.getTotalSize()];
        packet.transferStateAndDataTo(buff);
        JBuffer jb = new JBuffer(buff);
        String content = jb.toHexdump();
        analyzeResult.put("包内容", content);
        analyzeResult.put("协议", "UDP");
    }

    public static void handleHttp() {
        if (!packet.hasHeader(Http.ID)) {
            return;
        }
        http = packet.getHeader(http);
        //获取当前http请求中存在的请求头参数
        String[] fieldArray = http.fieldArray();
        Map<String, String> fieldMap = new HashMap<>();
        for (String temp : fieldArray) {
            fieldMap.put(temp.toUpperCase(), temp);
        }
//        //http请求头参数
//        Map<String,String> httpParams = new ConcurrentHashMap<>();
//        //获取http定义的请求头参数
//        Request[] valuesKeys = Request.values();
//        for (Request value : valuesKeys) {
//            //使用hash进行匹配，将双重for变成一重for
//            if(fieldMap.containsKey(value.name().toUpperCase().replace("_","-"))) {
//                httpParams.put(value.toString(),http.fieldValue(value));
//            }
//        }
        //获取http中请求的传输报文
        if (http.hasPayload()) {
            try {
                byte[] payload = http.getPayload();
                String result = new String(payload, "UTF-8");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        analyzeResult.put("协议", "HTTP");
    }

    public static HashMap<String,String> IPanalyze() throws UnknownHostException {
        HashMap<String,String> att = new HashMap<String,String>();
        if(!packet.hasHeader(Ip4.ID)) {
            return null;
        }
        Ip4 ip4 = packet.getHeader(new Ip4());
        //这里获取的IP地址同样是byte[]，而不是我们熟悉的十进制
        byte[] sources = ip4.source();
        byte[] destinations = ip4.destination();
        InetAddress sourceAddress = InetAddress.getByAddress(sources);
        String srcip= sourceAddress.getHostAddress();
        InetAddress desAddress = InetAddress.getByAddress(destinations);
        String desip= desAddress.getHostAddress();

        att.put("协议", new String("IP"));
        att.put("源IP", srcip);
        att.put("目的IP", desip);
        att.put("TTL", String.valueOf(ip4.ttl()));
        att.put("头长度", String.valueOf(ip4.getHeader().length));
        att.put("是否有其他切片", String.valueOf(ip4.isFragment()));
        return att;
    }

}
