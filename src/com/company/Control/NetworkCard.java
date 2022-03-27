package com.company.Control;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * @ClassName NetworkCard  //类名称
 * @Description: 类描述  用于返回网卡信息
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/26 14:01	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/26 14:01	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
 */

public class NetworkCard {
    //所有网卡列表
    List<PcapIf> alldevs = new ArrayList<PcapIf>();
    //报错信息
    StringBuilder errbuf = new StringBuilder();

    @Test
    public List<PcapIf> getAlldevs() {
        //读取网卡
        int r = Pcap.findAllDevs(alldevs, errbuf);
        //判断是否读取成功
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can’t read list of devices, error is %s", errbuf.toString());
            return alldevs;
        }
        System.out.println("Network devices found:");
        return alldevs;
    }
}
