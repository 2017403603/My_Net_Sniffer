package com.company.Model;

import com.company.Control.AnalyzePackage;
import org.jnetpcap.packet.PcapPacket;

import javax.swing.table.DefaultTableModel;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

/**
 * @ClassName Filter  //类名称
 * @Description: 类描述
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/27 12:04	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/27 12:04	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
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
    //抓到的包存储
    public static ArrayList<PcapPacket> packetlist = new ArrayList<PcapPacket>();
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

    public static void setTablemodel(DefaultTableModel tablemodel) {
        HandlerInfo.tablemodel = tablemodel;
    }

    //将list集合清除
    public void clearpackets() {
        packetlist.clear();
    }

    //将抓到包的信息添加到列表
    public static void showTable(PcapPacket packet) {
        String[] rowData = getObj(packet);
        tablemodel.addRow(rowData);
    }

    //将抓的包的基本信息显示在列表上，返回信息的String[]形式
    public static String[] getObj(PcapPacket packet) {
        String[] data = new String[6];
        if (packet != null && new AnalyzePackage(packet).Analyzed().size() >= 3) {
            //捕获时间
            Date date = new Date(packet.getCaptureHeader().timestampInMillis());
            DateFormat df = new SimpleDateFormat("HH:mm:ss");
            data[0] = df.format(date);
            data[1] = new AnalyzePackage(packet).Analyzed().get("源IP").equals("未知") ?
                    new AnalyzePackage(packet).Analyzed().get("源MAC") : new AnalyzePackage(packet).Analyzed().get("源IP");
            data[2] = new AnalyzePackage(packet).Analyzed().get("目的IP").equals("未知") ?
                    new AnalyzePackage(packet).Analyzed().get("目的MAC") : new AnalyzePackage(packet).Analyzed().get("目的IP");
            data[3] = new AnalyzePackage(packet).Analyzed().get("协议");
            data[4] = String.valueOf(packet.getCaptureHeader().wirelen());
        }
        return data;
    }
}
