/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> ETHERTYPE_ARP = 0x0806;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

const bit<16> ARP_HTYPE_ETHERNET = 0x0001;
const bit<16> ARP_PTYPE_IPV4     = 0x0800;
const bit<8>  ARP_HLEN_ETHERNET  = 6;
const bit<8>  ARP_PLEN_IPV4      = 4;
const bit<16> ARP_OPER_REQUEST   = 1;
const bit<16> ARP_OPER_REPLY     = 2;

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
}//arp的头部结构

header arp_ipv4_t {
    mac_addr_t  sha;//发送方硬件地址
    ipv4_addr_t spa;//发送方协议地址
    mac_addr_t  tha;//目标硬件地址
    ipv4_addr_t tpa;//目标协议地址
}

struct metadata {
    ipv4_addr_t dst_ipv4;
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    arp_ipv4_t   arp_ipv4;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);//从数据报文指针开始位置，抽取以太网包头
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;//若为0x0800，则转换到parse_ipv4状态
            ETHERTYPE_ARP: parse_arp;//若为0x0806，则转换到parse_arp状态
            default: accept;//若都不是则接受
        }//根据协议类型切换至不同状态，类似C语言中的switch...case
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);//抽取ipv4包头
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);//抽取arp包头
        transition select(hdr.arp.htype, hdr.arp.ptype,
                          hdr.arp.hlen,  hdr.arp.plen) {
            (ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4,
             ARP_HLEN_ETHERNET,  ARP_PLEN_IPV4) : parse_arp_ipv4;//arp头部的值都相同，则转换到下一状态
            default : accept;
        }
    }
    
    state parse_arp_ipv4 {
        packet.extract(hdr.arp_ipv4);
        meta.dst_ipv4 = hdr.arp_ipv4.tpa;
        transition accept;
    }  
    
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;//将端口参数赋值给输出端口
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;//数据包的源地址改为目的地址
        hdr.ethernet.dstAddr = dstAddr;//目的地址改为新地址
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;//ttl减1
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;//key值为数据包头部字段的ipv4头部的目的地址，lpm为最长前缀匹配模式
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }//表中可执行的动作
        size = 1024;
        default_action = drop();
    }

    action send_arp_reply(macAddr_t dstAddr) {
        hdr.ethernet.dstAddr = hdr.arp_ipv4.sha;
        hdr.ethernet.srcAddr = dstAddr;
        
        hdr.arp.oper         = ARP_OPER_REPLY;
        
        hdr.arp_ipv4.tha     = hdr.arp_ipv4.sha;//将目标硬件地址（tha）设置为到达arp数据包的发送方硬件地址（sha）
        hdr.arp_ipv4.tpa     = hdr.arp_ipv4.spa;//将目标协议地址（tpa）设置为到达arp数据包的发送方协议地址（spa）
        hdr.arp_ipv4.sha     = dstAddr;//发送方硬件地址（sha）更新为交换机的mac地址
        hdr.arp_ipv4.spa     = meta.dst_ipv4;发送方协议地址（spa）更新为交换机的ip地址

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    
    table arp_ternary {
        key = {
            har.arp.oper : ternary;
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            send_arp_reply;
            drop;
        }//表中可执行的动作
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }//当ipv4头部有效，应用ipv4_lpm表
        else (hdr.arp.isValid()) {
            arp_ternary.apply();
        }//当arp头部有效，应用arp_ternary表
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.arp_ipv4);
        packet.emit(hdr.ipv4);
    }//解析后的头部必须再次添加到数据包中
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),//解析数据包，提取包头
MyVerifyChecksum(),//检验和校验
MyIngress(),//输入处理
MyEgress(),//输出处理
MyComputeChecksum(),//计算新的校验和
MyDeparser()//逆解析器
) main;
