package com.company.study;

import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class JnetApp {
    public static void main(String[] args) {
//        SpringApplication.run(JnetApp.class, args);
        List<PcapIf> devs = new ArrayList<PcapIf>();
        StringBuilder errsb = new StringBuilder();
        int r = Pcap.findAllDevs(devs, errsb);
        if (r == Pcap.NOT_OK || devs.isEmpty()) {
            System.err.println("未获取到网卡");
        } else {
            System.out.println("获取到网卡：");
            System.out.println(devs);
        }
    }
}
