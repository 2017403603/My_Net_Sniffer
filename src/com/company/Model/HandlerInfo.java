package com.company.Model;

import com.company.Control.AnalyzePackage;
import com.company.Utils.FilterUtils;
import org.jnetpcap.packet.PcapPacket;

import javax.swing.table.DefaultTableModel;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

/**
 * @ClassName Filter  //类名称
 * @Description: 类描述  用于图形界面与数据包存储之间信息传递
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/27 12:04	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/29 20:24	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.3    //版本号
 */

public class HandlerInfo {
    //过滤协议
    public static String FilterProtocol = "";
    //过滤源IP
    public static String FilterSrcip = "";
    //过滤目的IP
    public static String FilterDesip = "";
    //过滤关键字
    public static String FilterKey = "";
    //跟踪IP
    public static String TraceIP = "";
    //跟踪端口
    public static String TracePort = "";
    //抓到的包存储
    public static ArrayList<PcapPacket> packetlist = new ArrayList<PcapPacket>();
    //抓到的包分析
    public static ArrayList<PcapPacket> analyzePacketlist = new ArrayList<PcapPacket>();
    //UI表模型
    public static DefaultTableModel tablemodel;

    public static void setFilterProtocol(String filterProtocol) {
        FilterProtocol = filterProtocol;
    }

    public static void setFilterSrcip(String filterSrcip) {
        FilterSrcip = filterSrcip;
    }

    public static void setFilterDesip(String filterDesip) {
        FilterDesip = filterDesip;
    }

    public static void setFilterKey(String filterKey) {
        FilterKey = filterKey;
    }

    public static void setTraceIP(String traceIP) {
        TraceIP = traceIP;
    }

    public static void setTracePort(String tracePort) {
        TracePort = tracePort;
    }

    public static void setTablemodel(DefaultTableModel tablemodel) {
        HandlerInfo.tablemodel = tablemodel;
    }

    //将list集合清除
    public void clearAllpackets() {
        packetlist.clear();
        analyzePacketlist.clear();
    }

    //过滤后数据包重新显示
    public static void ShowAfterFilter() {
        FilterUtils filterUtils = new FilterUtils();
        while (tablemodel.getRowCount() > 0) {
            tablemodel.removeRow(tablemodel.getRowCount() - 1);
        }
        analyzePacketlist.clear();
        for (int i = 0; i < packetlist.size(); i++) {
            if (filterUtils.IsFilter(packetlist.get(i), FilterProtocol, FilterSrcip, FilterDesip, FilterKey)
                    && filterUtils.Istrace(packetlist.get(i), TraceIP, TracePort)) {
                analyzePacketlist.add(packetlist.get(i));
                showTable(packetlist.get(i));
            }
        }
    }

    //将抓到包的信息添加到列表
    public static void showTable(PcapPacket packet) {
        String[] rowData = getObj(packet);
        tablemodel.addRow(rowData);
    }

    //将抓的包的基本信息显示在列表上，返回信息的String[]形式
    public static String[] getObj(PcapPacket packet) {
        String[] data = new String[6];
        if (packet != null) {
            //捕获时间
            Date date = new Date(packet.getCaptureHeader().timestampInMillis());
            DateFormat df = new SimpleDateFormat("HH:mm:ss");
            data[0] = df.format(date);
            HashMap<String, String> hm = new AnalyzePackage(packet).Analyzed();
            data[1] = hm.get("源IP4").equals("未知") ? hm.get("源IP6") : hm.get("源IP4");
            data[2] = hm.get("目的IP4").equals("未知") ? hm.get("目的IP6") : hm.get("目的IP4");
            if (hm.get("源IP4").equals("未知") && hm.get("源IP6").equals("未知")) {
                data[1] = hm.get("源MAC");
            }
            if (hm.get("目的IP4").equals("未知") && hm.get("目的IP6").equals("未知")) {
                data[2] = hm.get("目的MAC");
            }
            data[3] = hm.get("协议");
            data[4] = String.valueOf(packet.getCaptureHeader().wirelen());
        }
        return data;
    }
}
