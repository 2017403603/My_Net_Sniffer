package com.company.Control;

import com.company.Model.HandlerInfo;
import com.company.Utils.FilterUtils;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

/**
 * @ClassName CustomPcapHandler  //类名称
 * @Description: 类描述  抓到的每一个数据包将会在这里进行处理
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/26 16:52	//创建时间
 * @UpdateUser: 更新人  程哥哥
 * @UpdateDate: 2022/3/29 20:28	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.3    //版本号
 */

public class MyPcapHandler<Object> implements PcapPacketHandler<Object> {
    FilterUtils filterUtils;
    @Override
    public void nextPacket(PcapPacket packet, Object handlerInfo) {
        HandlerInfo Info = (HandlerInfo) handlerInfo;
        if (packet != null) {
            //抓到的所有包都放入
            Info.packetlist.add(packet);
            //符合条件的包放入
            if(filterUtils.IsFilter(packet, Info.FilterProtocol, Info.FilterSrcip, Info.FilterDesip, Info.FilterKey)&&
            filterUtils.Istrace(packet, Info.TraceIP, Info.TracePort)){
                Info.analyzePacketlist.add(packet);
                Info.showTable(packet);
            }
            System.out.println(packet);
        }
    }
}
