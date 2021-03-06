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

def writecheck_ports(p4info_helper, ingress_sw,
                     ingress_port, egress_spec, dire):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.check_ports", # 定义表名
        match_fields={
            "standard_metadata.ingress_port": ingress_port,
            "standard_metadata.egress_spec": egress_spec
            # 若包头对应的字段与参数匹配，则执行这一条表项的对应动作
        }, # 设置匹配域
        action_name="MyIngress.set_direction", # 定义动作名
        action_params={
            "dir": dire
        })
    # 需要使用 p4info_helper 解析器来将规则转化为 P4Runtime 能够识别的形式
    ingress_sw.WriteTableEntry(table_entry) # 调用 WriteTableEntry ，将生成的匹配动作表项加入交换机
    print("Installed rule on %s" % ingress_sw.name)

def writeipv4_lpm(p4info_helper, ingress_sw,
                     dst_eth_addr, dst_ip_addr, switch_port):

    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm", # 定义表名
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr
            # 若包头对应的字段与参数匹配，则执行这一条表项的对应动作
        }, # 设置匹配域
        action_name="MyIngress.ipv4_forward", # 定义动作名
        action_params={
            "dstAddr": dst_eth_addr,
            "port": switch_port
        })
    # 需要使用 p4info_helper 解析器来将规则转化为 P4Runtime 能够识别的形式
    ingress_sw.WriteTableEntry(table_entry) # 调用 WriteTableEntry ，将生成的匹配动作表项加入交换机
    print("Installed rule on %s" % ingress_sw.name)

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
        s4 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s4',
            address='127.0.0.1:50054',
            device_id=3,
            proto_dump_file='logs/s4-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()
        s4.MasterArbitrationUpdate()

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
        s4.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s4")

        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=1, egress_spec=3, dire=0)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=1, egress_spec=4, dire=0)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=2, egress_spec=3, dire=0)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=2, egress_spec=4, dire=0)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=3, egress_spec=1, dire=1)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=3, egress_spec=2, dire=1)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=4, egress_spec=1, dire=1)
        writecheck_ports(p4info_helper, ingress_sw=s1, ingress_port=4, egress_spec=2, dire=1)
        writeipv4_lpm(p4info_helper, ingress_sw=s1,
                         dst_eth_addr="08:00:00:00:01:11", dst_ip_addr=["10.0.1.1", 32], switch_port=1)
        writeipv4_lpm(p4info_helper, ingress_sw=s1,
                         dst_eth_addr="08:00:00:00:02:22", dst_ip_addr=["10.0.2.2", 32], switch_port=2)
        writeipv4_lpm(p4info_helper, ingress_sw=s1,
                         dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=["10.0.3.3", 32], switch_port=3)
        writeipv4_lpm(p4info_helper, ingress_sw=s1,
                         dst_eth_addr="08:00:00:00:04:00", dst_ip_addr=["10.0.4.4", 32], switch_port=4)

        writeipv4_lpm(p4info_helper, ingress_sw=s2,
                         dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=["10.0.1.1", 32], switch_port=4)
        writeipv4_lpm(p4info_helper, ingress_sw=s2,
                         dst_eth_addr="08:00:00:00:04:00", dst_ip_addr=["10.0.2.2", 32], switch_port=3)
        writeipv4_lpm(p4info_helper, ingress_sw=s2,
                         dst_eth_addr="08:00:00:00:03:33", dst_ip_addr=["10.0.3.3", 32], switch_port=1)
        writeipv4_lpm(p4info_helper, ingress_sw=s2,
                         dst_eth_addr="08:00:00:00:04:44", dst_ip_addr=["10.0.4.4", 32], switch_port=2)

        writeipv4_lpm(p4info_helper, ingress_sw=s3,
                         dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=["10.0.1.1", 32], switch_port=1)
        writeipv4_lpm(p4info_helper, ingress_sw=s3,
                         dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=["10.0.2.2", 32], switch_port=1)
        writeipv4_lpm(p4info_helper, ingress_sw=s3,
                         dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=["10.0.3.3", 32], switch_port=2)
        writeipv4_lpm(p4info_helper, ingress_sw=s3,
                         dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=["10.0.4.4", 32], switch_port=2)

        writeipv4_lpm(p4info_helper, ingress_sw=s4,
                         dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=["10.0.1.1", 32], switch_port=2)
        writeipv4_lpm(p4info_helper, ingress_sw=s4,
                         dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=["10.0.2.2", 32], switch_port=2)
        writeipv4_lpm(p4info_helper, ingress_sw=s4,
                         dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=["10.0.3.3", 32], switch_port=1)
        writeipv4_lpm(p4info_helper, ingress_sw=s4,
                         dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=["10.0.4.4", 32], switch_port=1)

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
                        default='./build/firewall.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/firewall.json')
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
