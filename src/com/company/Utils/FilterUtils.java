package com.company.Utils;

import com.company.Control.AnalyzePackage;
import org.jnetpcap.packet.PcapPacket;

/**
 * @ClassName FilterUtils  //类名称
 * @Description: 类描述
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/27 13:23	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/27 13:23	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
 */

public class FilterUtils {
    //设置过滤规则
    public static boolean IsFilter(PcapPacket packet, String FilterProtocol, String FilterSrcip, String FilterDesip, String FilterKey) {
        //协议过滤
        if (FilterProtocol.contains("Ethernet II")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("Ethernet II")) {
                return false;
            }
        } else if (FilterProtocol.contains("IP")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("IP")) {
                return false;
            }
        } else if (FilterProtocol.contains("ICMP")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("ICMP")) {
                return false;
            }
        } else if (FilterProtocol.contains("ARP")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("ARP")) {
                return false;
            }
        } else if (FilterProtocol.contains("UDP")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("UDP")) {
                return false;
            }
        } else if (FilterProtocol.contains("TCP")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("TCP")) {
                return false;
            }
        } else if (FilterProtocol.contains("HTTP")) {
            if (!new AnalyzePackage(packet).Analyzed().get("协议").equals("HTTP")) {
                return false;
            }
        } else if (FilterProtocol.equals("")) {

        }
        //源ip地址过滤
        if (FilterSrcip.contains("src")) {
            String src = FilterSrcip.substring(4, FilterSrcip.length());
            if (!new AnalyzePackage(packet).Analyzed().get("源IP").equals(src)) {
                return false;
            }
        }
        //目的ip地址过滤
        if (FilterDesip.contains("des")) {
            String des = FilterDesip.substring(4, FilterDesip.length());
            if (!new AnalyzePackage(packet).Analyzed().get("目的IP").equals(des)) {
                return false;
            }
        }
        //关键字过滤
        if (FilterKey.contains("keyword")) {
            String keyword = FilterKey.substring(8, FilterKey.length());
            if (!new AnalyzePackage(packet).Analyzed().get("包内容").contains(keyword)) {
                return false;
            }
        }
        return true;
    }
}
