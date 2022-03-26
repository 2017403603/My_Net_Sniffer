package com.company.Control;

import com.company.study.CustomPcapHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import javax.swing.table.DefaultTableModel;
import java.io.PrintStream;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

/**
 * @ClassName CapturePackage  //类名称
 * @Description: 类描述  启动线程抓包
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/26 15:57	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/26 15:57	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
 */

public class CapturePackage implements Runnable{
    //要抓包的设备
    private PcapIf device;
    //UI表模型
    private static DefaultTableModel tablemodel;
    //过滤信息
    private String FilterMess = "";
    //抓到的包存储
    static ArrayList<PcapPacket> packetlist = new ArrayList<PcapPacket>();
    //这个类是与 libpcap 和 winpcap 库实现中的原生 pcap_t 结构对等的Java类。 它提供了Java 与libpcap 库方法的直接映射。
    static Pcap pcap;
    //定义handler的处理方法
    static PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
        @Override
        public void nextPacket(PcapPacket packet, String user) {
//            System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
//                    new Date(packet.getCaptureHeader().timestampInMillis()),
//                    packet.getCaptureHeader().caplen(),  // 实际捕获的长度
//                    packet.getCaptureHeader().wirelen(), // 原来长度
//                    user                                 // 用户信息
//            );
//            // 设置过滤器
//            if(packet!=null&&TestFilter(packet)){
//                //System.out.println(packet);
//                packetlist.add(packet);
//                showTable(packet);
//            }
            packetlist.add(packet);
            showTable(packet);
            System.out.println("user:"+user);
        }
    };
    public CapturePackage() {
    }

    public CapturePackage(PcapIf device, DefaultTableModel tablemodel) {
        this.device = device;
        this.tablemodel = tablemodel;
    }

    public PcapIf getDevice() {
        return device;
    }

    public void setDevice(PcapIf device) {
        this.device = device;
    }

    public DefaultTableModel getTablemodel() {
        return tablemodel;
    }

    public void setTablemodel(DefaultTableModel tablemodel) {
        this.tablemodel = tablemodel;
    }

    public String getFilterMess() {
        return FilterMess;
    }

    public void setFilterMess(String filterMess) {
        FilterMess = filterMess;
    }

    @Override
    public void run() {
        //截断此大小的数据包
        int snaplen = Pcap.DEFAULT_JPACKET_BUFFER_SIZE;

        int promiscous = Pcap.MODE_PROMISCUOUS;

        //以毫秒为单位
        int timeout = 60 * 1000;
        //如果发生错误，它将保存一个错误字符串。 错误打开 Live 将返回 null
        StringBuilder errbuf = new StringBuilder();

        pcap = Pcap.openLive(device.getName(),snaplen,promiscous,timeout,errbuf);
        if(pcap == null) {
            System.err.println("获取数据包失败：" + errbuf.toString());
            return ;
        }

        //CustomPcapHandler<String> handler = new CustomPcapHandler<String>();
        // 捕获数据包计数
        int cnt = 1;
        //我们要发送到处理程序的自定义对象
        String user = "程哥哥";
        while(true) {
            //设置抓包速率与间隔
            long startTime = System.currentTimeMillis();
            //每个数据包将被分派到抓包处理器Handler
            pcap.loop(cnt, jpacketHandler, user);
            try {
                //线程休眠2秒
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            System.out.println("list的大小为："+packetlist.size());
        }
//        pcap.close();
    }
    //将抓到包的信息添加到列表
    public static void showTable(PcapPacket packet){
        String[] rowData = getObj(packet);
        tablemodel.addRow(rowData);
    }
    //将抓的包的基本信息显示在列表上，返回信息的String[]形式
    public static String[] getObj(PcapPacket packet){
        String[] data = new String[6];
        if (packet != null/*&&new PacketAnalyze(packet).packetClass().size()>=3*/) {
            //捕获时间
            Date date = new Date(packet.getCaptureHeader().timestampInMillis());
            DateFormat df = new SimpleDateFormat("HH:mm:ss");
            data[0]=df.format(date);
            data[1]=/*new PacketAnalyze(packet).packetClass().get("源IP")*/"1.1.1.1";
            data[2]=/*new PacketAnalyze(packet).packetClass().get("目的IP")*/"1.1.1.1";
            data[3]=/*new PacketAnalyze(packet).packetClass().get("协议")*/"CGG";
            data[4]=String.valueOf(packet.getCaptureHeader().caplen());
        }
        return data;
    }
}
