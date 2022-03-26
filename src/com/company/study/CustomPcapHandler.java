package com.company.study;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * @ClassName CustomPcapHandler  //类名称
 * @Description: 类描述
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/26 16:52	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/26 16:52	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
 */

public class CustomPcapHandler<Object> implements PcapPacketHandler<Object> {
    @Override
    public void nextPacket(PcapPacket packet, Object user) {
        System.out.println(packet);
    }
}
