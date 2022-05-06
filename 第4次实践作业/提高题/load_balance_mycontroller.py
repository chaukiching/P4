#!/usr/bin/env python3
import argparse
import os
import sys
from time import sleep

import grpc

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
import p4runtime_lib.helper
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections

def writeecmp_group(p4info_helper, ingress_sw,
                     dst_ip_addr, base, count):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ecmp_group", # 定义表名
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr
            # 若包头对应的 hdr.ipv4.dstAddr 字段与参数中的 dst_ip_addr 匹配，则执行这一条表项的对应动作
        }, # 设置匹配域
        action_name="MyIngress.set_ecmp_select", # 定义动作名
        action_params={
            "ecmp_base": base,
            "ecmp_count": count
        })
    # 需要使用 p4info_helper 解析器来将规则转化为 P4Runtime 能够识别的形式
    ingress_sw.WriteTableEntry(table_entry) # 调用 WriteTableEntry ，将生成的匹配动作表项加入交换机
    print("Installed rule on %s" % ingress_sw.name)

def writeecmp_nhop(p4info_helper, ingress_sw,
                     result, dmac, ipv4, switch_port):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ecmp_nhop", # 定义表名
        match_fields={
            "meta.ecmp_select": result
            # 若包头对应的 meta.ecmp_select 字段与参数中的 result 匹配，则执行这一条表项的对应动作
        }, # 设置匹配域
        action_name="MyIngress.set_nhop", # 定义动作名
        action_params={
            "nhop_dmac": dmac,
            "nhop_ipv4": ipv4,
            "port": switch_port
        })
    # 需要使用 p4info_helper 解析器来将规则转化为 P4Runtime 能够识别的形式
    ingress_sw.WriteTableEntry(table_entry) # 调用 WriteTableEntry ，将生成的匹配动作表项加入交换机
    print("Installed rule on %s" % ingress_sw.name)

def writesend_frame(p4info_helper, egress_sw,
                        egress_port, mac):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.send_frame", # 定义表名
        match_fields={
            "standard_metadata.egress_port": egress_port
            # 若包头对应的 standard_metadata.egress_port 字段与参数中的 egress_port 匹配，则执行这一条表项的对应动作
        }, # 设置匹配域
        action_name="MyEgress.rewrite_mac", # 定义动作名
        action_params={
            "smac": mac
        })
    # 需要使用 p4info_helper 解析器来将规则转化为 P4Runtime 能够识别的形式
    egress_sw.WriteTableEntry(table_entry) # 调用 WriteTableEntry ，将生成的匹配动作表项加入交换机
    print("Installed rule on %s" % egress_sw.name)

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path) # 初始化 p4info_helper

    try:
        # 为s1、s2、s3创建交换机连接对象
        # 这是由一个运行时gRPC连接支持的
        # 此外，将发送给交换机的所有 P4Runtime 消息转存到给定的 txt 文件
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        # 在交换机上安装 P4 程序
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        writeecmp_group(p4info_helper, ingress_sw=s1,
                         dst_ip_addr=("10.0.0.1", 32), base=0, count=2)
        writeecmp_nhop(p4info_helper, ingress_sw=s1,
                         result=0, dmac="00:00:00:00:01:02", ipv4="10.0.2.2", switch_port=2)
        writeecmp_nhop(p4info_helper, ingress_sw=s1,
                         result=1, dmac="00:00:00:00:01:03", ipv4="10.0.3.3", switch_port=3)
        writesend_frame(p4info_helper, egress_sw=s1,
                         egress_port=2, mac="00:00:00:01:02:00")
        writesend_frame(p4info_helper, egress_sw=s1,
                         egress_port=3, mac="00:00:00:01:03:00")

        writeecmp_group(p4info_helper, ingress_sw=s2,
                         dst_ip_addr=("10.0.2.2", 32), base=0, count=1)
        writeecmp_nhop(p4info_helper, ingress_sw=s2,
                         result=0, dmac="08:00:00:00:02:02", ipv4="10.0.2.2", switch_port=1)
        writesend_frame(p4info_helper, egress_sw=s2,
                         egress_port=1, mac="00:00:00:02:01:00")

        writeecmp_group(p4info_helper, ingress_sw=s3,
                         dst_ip_addr=("10.0.3.3", 32), base=0, count=1)
        writeecmp_nhop(p4info_helper, ingress_sw=s3,
                         result=0, dmac="08:00:00:00:03:03", ipv4="10.0.3.3", switch_port=1)
        writesend_frame(p4info_helper, egress_sw=s3,
                         egress_port=1, mac="00:00:00:03:01:00")

        while True:
            sleep(2)

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/load_balance.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/load_balance.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
