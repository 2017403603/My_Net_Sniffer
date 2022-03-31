package com.company.Utils;

import com.company.Control.AnalyzePackage;
import org.jnetpcap.packet.PcapPacket;

import java.util.HashMap;

/**
 * @ClassName FilterUtils  //类名称
 * @Description: 类描述  用于过滤数据包
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/27 13:23	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/29 20:20	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.3    //版本号
 */

public class FilterUtils {
    //设置过滤规则
    public static boolean IsFilter(PcapPacket packet, String FilterProtocol, String FilterSrcip, String FilterDesip, String FilterKey) {
        HashMap<String,String> hm = new AnalyzePackage(packet).Analyzed();
        //协议过滤
        if (FilterProtocol.equals("Ethernet II")) {
            if (!hm.get("协议").equals("ETHERNET")) {
                return false;
            }
        } else if (FilterProtocol.equals("IP")) {
            if (!(hm.get("协议").equals("IP4")||hm.get("协议").equals("IP6"))) {
                return false;
            }
        } else if (FilterProtocol.equals("ICMP")) {
            if (!hm.get("协议").equals("ICMP")) {
                return false;
            }
        } else if (FilterProtocol.equals("ARP")) {
            if (!hm.get("协议").equals("ARP")) {
                return false;
            }
        } else if (FilterProtocol.equals("UDP")) {
            if (!hm.get("协议").equals("UDP")) {
                return false;
            }
        } else if (FilterProtocol.equals("TCP")) {
            if (!hm.get("协议").equals("TCP")) {
                return false;
            }
        } else if (FilterProtocol.equals("HTTP")) {
            if (!hm.get("协议").equals("HTTP")) {
                return false;
            }
        } else if (FilterProtocol.equals("")) {

        }
        //源ip地址过滤
        if (!FilterSrcip.equals("")) {
            if (!(hm.get("源IP4").equals(FilterSrcip)||hm.get("源IP6").equals(FilterSrcip))) {
                return false;
            }
        }
        //目的ip地址过滤
        if (!FilterDesip.equals("")) {
            if (!(hm.get("目的IP4").equals(FilterDesip)||hm.get("目的IP6").equals(FilterDesip))) {
                return false;
            }
        }
        //关键字过滤
        if (!FilterKey.equals("")) {
            if (!hm.get("包内容").contains(FilterKey)) {
                return false;
            }
        }
        return true;
    }
    //设置追踪规则
    public static boolean Istrace(PcapPacket packet,String IP,String Port){
        //如果是默认值，默认跟踪
        if (IP.equals("")||Port.equals("")){
            return true;
        }
        HashMap<String,String> hm = new AnalyzePackage(packet).Analyzed();
        if (hm.get("协议").equals("TCP")&&
                (hm.get("源IP4").equals(IP)|| hm.get("源IP6").equals(IP))&&
                hm.get("源端口").equals(Port)){
            return true;
        }
        if (hm.get("协议").equals("TCP")&&
                (hm.get("目的IP4").equals(IP)||hm.get("目的IP6").equals(IP))&&
                hm.get("目的端口").equals(Port)){
            return true;
        }
        return false;
    }
}
