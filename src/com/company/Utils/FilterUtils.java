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
        if (FilterProtocol.contains("Ethernet II")) {
            if (!hm.get("协议").equals("ETHERNET")) {
                return false;
            }
        } else if (FilterProtocol.contains("IP")) {
            if (!(hm.get("协议").equals("IP4")||hm.get("协议").equals("IP6"))) {
                return false;
            }
        } else if (FilterProtocol.contains("ICMP")) {
            if (!hm.get("协议").equals("ICMP")) {
                return false;
            }
        } else if (FilterProtocol.contains("ARP")) {
            if (!hm.get("协议").equals("ARP")) {
                return false;
            }
        } else if (FilterProtocol.contains("UDP")) {
            if (!hm.get("协议").equals("UDP")) {
                return false;
            }
        } else if (FilterProtocol.contains("TCP")) {
            if (!hm.get("协议").equals("TCP")) {
                return false;
            }
        } else if (FilterProtocol.contains("HTTP")) {
            if (!hm.get("协议").equals("HTTP")) {
                return false;
            }
        } else if (FilterProtocol.equals("")) {

        }
        //源ip地址过滤
        if (FilterSrcip.contains("src")) {
            String src = FilterSrcip.substring(4, FilterSrcip.length());
            if (!(hm.get("源IP4").equals(src)||hm.get("源IP6").equals(src))) {
                return false;
            }
        }
        //目的ip地址过滤
        if (FilterDesip.contains("des")) {
            String des = FilterDesip.substring(4, FilterDesip.length());
            if (!(hm.get("目的IP4").equals(des)||hm.get("目的IP6").equals(des))) {
                return false;
            }
        }
        //关键字过滤
        if (FilterKey.contains("keyword")) {
            String keyword = FilterKey.substring(8, FilterKey.length());
            if (!hm.get("包内容").contains(keyword)) {
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
