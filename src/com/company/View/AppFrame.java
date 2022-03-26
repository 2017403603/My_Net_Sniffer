package com.company.View;

import com.company.Control.CapturePackage;
import com.company.Control.NetworkCard;
import org.jnetpcap.PcapIf;
import org.junit.Test;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * @ClassName AppFrame  //类名称
 * @Description: 类描述
 * @Author: 程哥哥    //作者
 * @CreateDate: 2022/3/24 23:12	//创建时间
 * @UpdateUser: 更新人
 * @UpdateDate: 2022/3/24 23:12	//更新时间
 * @UpdateRemark: 更新的信息
 * @Version: 1.0    //版本号
 */

public class AppFrame extends JFrame {
    //菜单条
    JMenuBar jMenuBar;
    //菜单
    JMenu jMenu1, jMenu2;
    //菜单项
    JMenuItem[] jMenuItems;
    //菜单条目
    JMenuItem item1, item2, item3;
    //原地址、目的地址、搜索地址按钮
    JButton srcButton, desButton, searchButton;
    //容器
    JPanel jPanel;
    //滚动条
    JScrollPane jScrollPane;
    //表格
    JTable jTable;
    //表头内容
    final String[] head = new String[]{
            "时间", "源IP", "目的IP", "协议", "长度"
    };
    //表模型
    DefaultTableModel tableModel;
    //表内容
    Object[][] DataList = {/*{1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1},
            {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1},
            {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1},
            {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1},
            {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1}, {1, 1, 1, 1, 1},
            {1, 1, 1, 1, 1}*/};
    //UI部分
    public AppFrame() {
        //标题设置
        this.setTitle("网络嗅探器1.0");
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
        item1 = new JMenuItem(" ICMP ");
        //设置字体
        item1.setFont(new Font("", Font.BOLD, 20));
        item2 = new JMenuItem(" TCP ");
        //设置字体
        item2.setFont(new Font("", Font.BOLD, 20));
        item3 = new JMenuItem(" UDP ");
        //设置字体
        item3.setFont(new Font("", Font.BOLD, 20));
        //加入菜单选项
        jMenu2.add(item1);
        jMenu2.add(item2);
        jMenu2.add(item3);
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
        //将菜单添加到菜单条上
        jMenuBar.add(jMenu1);
        jMenuBar.add(jMenu2);
        jMenuBar.add(srcButton);
        jMenuBar.add(desButton);
        jMenuBar.add(searchButton);
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
            jMenuItems[i] = new JMenuItem("#"+i + ": " + device.getName() + "["
                    + description  + "]");
            //字体设置
            jMenuItems[i].setFont(new Font("", Font.BOLD, 15));
            jMenu1.add(jMenuItems[i]);
            jMenuItems[i].addActionListener(
                    new CardActionListener(device));
            i++;
        }
        //初始化抓包类
        capturePackage = new CapturePackage();
        //初始化表模型
        capturePackage.setTablemodel(tableModel);
    }
    //为每张网卡绑定响应事件
    private class CardActionListener implements ActionListener {

        PcapIf device;
        CardActionListener(PcapIf device){
            this.device = device;
        }
        public void actionPerformed(ActionEvent e) {
            capturePackage.setDevice(device);
            capturePackage.setFilterMess("");
            new Thread(capturePackage).start();   //开启抓包线程
        }
    }
}
