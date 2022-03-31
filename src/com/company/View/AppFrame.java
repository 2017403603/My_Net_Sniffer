package com.company.View;

import com.company.Control.AnalyzePackage;
import com.company.Control.CapturePackage;
import com.company.Model.HandlerInfo;
import com.company.Control.NetworkCard;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.junit.Test;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.net.UnknownHostException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * @ClassName AppFrame  //类名称
 * @Description: 类描述  图形界面
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/25 23:12	//创建时间
 * @UpdateUser: 更新人 程哥哥
 * @UpdateDate: 2022/3/29 20:20	//更新时间
 * @UpdateRemark: 更新的信息版本更新
 * @Version: 1.3    //版本号
 */

public class AppFrame extends JFrame {
    //菜单条
    JMenuBar jMenuBar;
    //菜单
    JMenu jMenu1, jMenu2;
    //菜单项
    JMenuItem[] jMenuItems;
    //菜单条目
    JMenuItem item1, item2, item3, item4, item5, item6, item7;
    //原地址、目的地址、搜索地址按钮
    JButton srcButton, desButton, searchButton, trackButton;
    //容器
    JPanel jPanel;
    //滚动条
    JScrollPane jScrollPane;
    //表格
    JTable jTable;
    //表头内容
    final String[] head = new String[]{
            "时间", "源IP或源MAC", "目的IP或目的MAC", "协议", "长度"
    };
    //表模型
    DefaultTableModel tableModel;
    //表内容
    Object[][] DataList = {};
    //处理信息
    HandlerInfo handlerInfo;

    //UI部分
    public AppFrame() {
        //标题设置
        this.setTitle("网络嗅探器1.3");
        //起始坐标、长宽
        this.setBounds(250, 150, 900, 600);
        //菜单条
        jMenuBar = new JMenuBar();
        //根据网卡过滤
        jMenu1 = new JMenu("  网卡  ");
        //设置字体
        jMenu1.setFont(new Font("", Font.BOLD, 20));
        //根据协议过滤
        jMenu2 = new JMenu("  协议  ");
        //设置字体
        jMenu2.setFont(new Font("", Font.BOLD, 20));
        item1 = new JMenuItem(" Ethernet II ");
        //设置字体
        item1.setFont(new Font("", Font.BOLD, 20));
        item2 = new JMenuItem(" IP ");
        //设置字体
        item2.setFont(new Font("", Font.BOLD, 20));
        item3 = new JMenuItem(" ICMP ");
        //设置字体
        item3.setFont(new Font("", Font.BOLD, 20));
        item4 = new JMenuItem(" ARP ");
        //设置字体
        item4.setFont(new Font("", Font.BOLD, 20));
        item5 = new JMenuItem(" UDP ");
        //设置字体
        item5.setFont(new Font("", Font.BOLD, 20));
        item6 = new JMenuItem(" TCP ");
        //设置字体
        item6.setFont(new Font("", Font.BOLD, 20));
        item7 = new JMenuItem(" HTTP ");
        //设置字体
        item7.setFont(new Font("", Font.BOLD, 20));
        //加入菜单选项
        jMenu2.add(item1);
        jMenu2.add(item2);
        jMenu2.add(item3);
        jMenu2.add(item4);
        jMenu2.add(item5);
        jMenu2.add(item6);
        jMenu2.add(item7);
        //根据源ip地址过滤
        srcButton = new JButton(" 源IP ");
        //设置字体
        srcButton.setFont(new Font("", Font.BOLD, 20));
        //根据目的ip地址过滤
        desButton = new JButton(" 目的IP ");
        //设置字体
        desButton.setFont(new Font("", Font.BOLD, 20));
        //根据关键字进行过滤
        searchButton = new JButton(" 查找  ");
        //设置字体
        searchButton.setFont(new Font("", Font.BOLD, 20));
        //tcp+port流追踪
        trackButton = new JButton(" IP+Port流追踪  ");
        //设置字体
        trackButton.setFont(new Font("", Font.BOLD, 20));
        //将菜单添加到菜单条上
        jMenuBar.add(jMenu1);
        jMenuBar.add(jMenu2);
        jMenuBar.add(srcButton);
        jMenuBar.add(desButton);
        jMenuBar.add(searchButton);
        jMenuBar.add(trackButton);
        //菜单条设置
        setJMenuBar(jMenuBar);
        //表设置
        tableModel = new DefaultTableModel(DataList, head);
        //初始化表，设置所有行列无法编辑
        jTable = new JTable(tableModel) {
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        // 设置表格的大小
        jTable.setPreferredScrollableViewportSize(new Dimension(600, 30));
        // 创建表格标题对象
        JTableHeader head = jTable.getTableHeader();
        // 设置表头大小
        head.setPreferredSize(new Dimension(head.getWidth(), 30));
        // 设置表格字体
        head.setFont(new Font("楷体", Font.PLAIN, 16));
        //设置每行的高度为30
        jTable.setRowHeight(30);
        // 设置相邻两行单元格的距离
        jTable.setRowMargin(5);
        // 设置可否被选择.默认为false
        jTable.setRowSelectionAllowed(true);
        // 设置所选择行的背景色
        jTable.setSelectionBackground(Color.green);
        // 设置所选择行的前景色
        jTable.setSelectionForeground(Color.blue);
        // 是否显示网格线
        jTable.setShowGrid(true);
        //启动布局管理器
        jTable.doLayout();
        //新建滚动条
        jScrollPane = new JScrollPane(jTable);
        //网格布局
        jPanel = new JPanel(new GridLayout(0, 1));
        //容器尺寸
        jPanel.setPreferredSize(new Dimension(900, 600));
        //容器背景
        jPanel.setBackground(Color.black);
        //设置滚动条
        jPanel.add(jScrollPane);
        //加入内容
        setContentPane(jPanel);
        pack();
        //显示设置
        setResizable(false);
        setVisible(true);
        //点击进程结束
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                System.exit(0);
            }
        });
    }

    ///////////////////////////////////////////////////////////////////////////////////////
    //所有网卡列表
    List<PcapIf> alldevs;
    //抓包类
    CapturePackage capturePackage;

    ////////////////////////////////////////////////////////////////////////////////////
    //数据填充
    @Test
    public void dataInjection() {
        //获取所有显卡
        alldevs = new NetworkCard().getAlldevs();
        //动态初始化条目
        jMenuItems = new JMenuItem[alldevs.size()];
        int i = 0;
        //遍历网卡：显示网卡编号和描述信息
        for (PcapIf device : alldevs) {
            String description = (device.getDescription() != null) ? device.getDescription()
                    : "No description available";
            jMenuItems[i] = new JMenuItem("#" + i + ": " + device.getName() + "["
                    + description + "]");
            //字体设置
            jMenuItems[i].setFont(new Font("", Font.BOLD, 15));
            jMenu1.add(jMenuItems[i]);
            jMenuItems[i].addActionListener(new CardActionListener(device));
            i++;
        }
        //初始化抓包类
        capturePackage = new CapturePackage();
        //初始化处理器信息
        handlerInfo = new HandlerInfo();
        handlerInfo.setTablemodel(tableModel);
        //item1绑定事件
        item1.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("Ethernet II");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        item2.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("IP");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        item3.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("ICMP");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        item4.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("ARP");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        item5.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("UDP");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        item6.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("TCP");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        item7.addActionListener(
                new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e3) {
                        handlerInfo.setFilterProtocol("HTTP");
                        handlerInfo.ShowAfterFilter();
                    }
                });
        srcButton.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String fsip = JOptionPane.showInputDialog("请输入源IP，以筛选数据包：");
                        if (fsip == null) fsip = "";
                        handlerInfo.setFilterSrcip(fsip);
                        handlerInfo.ShowAfterFilter();
                    }
                });
        desButton.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String fdip = JOptionPane.showInputDialog("请输入目的IP，以筛选数据包：");
                        if (fdip == null) fdip = "";
                        handlerInfo.setFilterDesip(fdip);
                        handlerInfo.ShowAfterFilter();
                    }
                });
        searchButton.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String fkeyword = JOptionPane.showInputDialog("请输入数据关键字，以筛选数据包：");
                        if (fkeyword == null) fkeyword = "";
                        handlerInfo.setFilterKey(fkeyword);
                        handlerInfo.ShowAfterFilter();
                    }
                });
        trackButton.addActionListener(
                new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        String ip_port = JOptionPane.showInputDialog("请输入要追踪的IP地址和Port端口(输入数据格式为 IP地址:Port端口)，以追踪TCP流：");
                        if (ip_port == null || ip_port == "") ip_port = ":";
                        String[] str = ip_port.split(":");
                        handlerInfo.setTraceIP(str[0]);
                        handlerInfo.setTracePort(str[1]);
                        handlerInfo.ShowAfterFilter();
                    }
                });
        jTable.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent ev) {
                if (ev.getClickCount() == 2) {
                    //获得选取行
                    int row = jTable.getSelectedRow();
                    //标题
                    JFrame frame = new JFrame("详细信息");
                    //画布
                    JPanel panel = new JPanel();
                    //文本区域大小
                    final JTextArea info = new JTextArea(32, 42);
                    //是否可编辑
                    info.setEditable(false);
                    info.setLineWrap(true);
                    info.setWrapStyleWord(true);
                    frame.add(panel);
                    //加滚动条
                    panel.add(new JScrollPane(info));
                    JButton save = new JButton("保存到本地");
                    //保存事件绑定
                    save.addActionListener(
                            new ActionListener() {
                                public void actionPerformed(ActionEvent e3) {
                                    String text = info.getText();
                                    Date date = new Date(System.currentTimeMillis());
                                    DateFormat df = new SimpleDateFormat("HH点mm秒ss");
                                    String name = df.format(date);
                                    try {
                                        FileOutputStream fos = new FileOutputStream("C:\\Users\\程哥哥\\Desktop\\临时文件\\软件系统与安全\\My_Net_Sniffer\\" + name + ".txt");
                                        fos.write(text.getBytes());
                                        fos.close();
                                    } catch (Exception e) {
                                        e.printStackTrace();
                                    }
                                }
                            });
                    //加入保存按钮并且设置
                    panel.add(save);
                    frame.setBounds(150, 150, 500, 600);
                    frame.setVisible(true);
                    frame.setResizable(false);
                    //获取数据包
                    ArrayList<PcapPacket> packetlist = handlerInfo.analyzePacketlist;
                    //获得分析后的信息
                    Map<String, String> hm = new HashMap<String, String>();
                    PcapPacket packet = packetlist.get(row);
                    AnalyzePackage analyzePackage = new AnalyzePackage(packet);
                    hm = analyzePackage.Analyzed();
                    info.append("                               " + hm.get("协议") + "数据包" + "                               \n");
                    if (packet.hasHeader(Ethernet.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------Ethernet头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("源MAC" + " : " + hm.get("源MAC") + "\n");
                        info.append("源MAC地址类型" + " : " + hm.get("源MAC地址类型") + "\n");
                        info.append("源主机传播方式" + " : " + hm.get("源主机传播方式") + "\n");
                        info.append("目的MAC" + " : " + hm.get("目的MAC") + "\n");
                        info.append("目的MAC地址类型" + " : " + hm.get("目的MAC地址类型") + "\n");
                        info.append("目的主机传播方式" + " : " + hm.get("目的主机传播方式") + "\n");
                    }
                    if (packet.hasHeader(Ip4.ID) || packet.hasHeader(Ip6.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------IP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("IP协议版本" + " : " + hm.get("IP协议版本") + "\n");
                        info.append("头长度" + " : " + packet.getCaptureHeader().wirelen() + "\n");
                        info.append("源IP4地址" + " : " + hm.get("源IP4") + "\n");
                        info.append("源IP6地址" + " : " + hm.get("源IP6") + "\n");
                        info.append("目的IP4地址" + " : " + hm.get("目的IP4") + "\n");
                        info.append("目的IP6地址" + " : " + hm.get("目的IP6") + "\n");
                        info.append("是否有其他切片" + " : " + hm.get("是否有其他切片") + "\n");
                    } else if (packet.hasHeader(new Arp())) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------ARP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        Arp arp = packet.getHeader(new Arp());
                        info.append(arp + "\n");
                    }
                    if (packet.hasHeader(Tcp.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------TCP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("源主机端口" + " : " + hm.get("源端口") + "\n");
                        info.append("目的主机端口" + " : " + hm.get("目的端口") + "\n");
                        info.append("是否有SYN标志位" + " : " + hm.get("Syn") + "\n");
                        info.append("是否有FIN标志位" + " : " + hm.get("Fin") + "\n");
                        info.append("Ack序号" + " : " + hm.get("Ack序号") + "\n");
                        info.append("Seq序号" + " : " + hm.get("Seq序号") + "\n");
                        info.append("是否使用http协议" + " : " + hm.get("是否使用http协议") + "\n");
                    } else if (packet.hasHeader(Udp.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------UDP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("源主机端口" + " : " + hm.get("源端口") + "\n");
                        info.append("目的主机端口" + " : " + hm.get("目的端口") + "\n");
                    } else if (packet.hasHeader(new Icmp())) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------ICMP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        Icmp icmp = packet.getHeader(new Icmp());
                        info.append(icmp + "\n");
                    }
                    if (packet.hasHeader(Http.ID)) {
                        info.append("------------------------------------------------------------------------------\n");
                        info.append("-------------------------------HTTP头信息：-------------------------------\n");
                        info.append("------------------------------------------------------------------------------\n");
                        analyzePackage.handleHttp();
                        for (Map.Entry<String, String> me : analyzePackage.fieldMap.entrySet()) {
                            info.append(me.getKey() + " : " + me.getValue() + "\n");
                        }
                        for (Map.Entry<String, String> me : analyzePackage.httpParams.entrySet()) {
                            info.append(me.getKey() + " : " + me.getValue() + "\n");
                        }
                        info.append(analyzePackage.httpresult);
                    }

                    info.append("------------------------------------------------------------------------------\n");
                    info.append("原始数据包内容" + " : " + hm.get("包内容") + "\n");
                }
            }
        });

    }

    //表示整个抓包进程
    Thread capthread = null;

    //为每张网卡绑定响应事件
    private class CardActionListener implements ActionListener {
        PcapIf device;

        CardActionListener(PcapIf device) {
            this.device = device;
        }

        public void actionPerformed(ActionEvent e) {
            if (capthread == null) {
                capturePackage.setDevice(device);
                capturePackage.setHandlerInfo(handlerInfo);
                capthread = new Thread(capturePackage);
                capthread.start();   //开启抓包线程
            } else {
                capturePackage.setDevice(device);
                handlerInfo.clearAllpackets();
                while (tableModel.getRowCount() > 0) {
                    tableModel.removeRow(tableModel.getRowCount() - 1);
                }
            }
        }
    }
}
