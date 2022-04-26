/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_SRCROUTING = 0x1234;

#define MAX_HOPS 9

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

header srcRoute_t {
    bit<1>    bos;  //表示是否为堆栈底部
    bit<15>   port;  //表示为出端口
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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t              ethernet;
    srcRoute_t[MAX_HOPS]    srcRoutes;
    ipv4_t                  ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {


    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        /*
         * TODO: Modify the next line to select on hdr.ethernet.etherType
         * If the value is TYPE_SRCROUTING transition to parse_srcRouting
         * otherwise transition to accept.
         */
        transition select(hdr.ethernet.etherType) {
            TYPE_SRCROUTING: parse_srcRouting;  //只有当etherType类型值是0x1234才解析源路由
            default: accept;
        }
    }

    state parse_srcRouting {
        /*
         * TODO: extract the next entry of hdr.srcRoutes
         * while hdr.srcRoutes.last.bos is 0 transition to this state
         * otherwise parse ipv4
         */
        packet.extract(hdr.srcRoutes.next);  //抽取包头，使用next移动指针
        transition select(hdr.srcRoutes.last.bos) {  //堆栈中上一层的元素
            1: parse_ipv4;  
            default: parse_srcRouting;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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

    action srcRoute_nhop() {
        /*
         * TODO: set standard_metadata.egress_spec
         * to the port in hdr.srcRoutes[0] and
         * pop an entry from hdr.srcRoutes
         */
        standard_metadata.egress_spec = (bit<9>)hdr.srcRoutes[0].port;  //配置下一跳的输出端口，和IP转发类似，通过设置标准元数据的输出端口egress_spec即可
        hdr.srcRoutes.pop_front(1);  //删除srcRoutes的第一个条目，运用堆栈的操作pop_front(1)实现将栈顶往下数的1个元素弹出
        //当数据包每到达一跳交换机时，交换机将一个项目（即输出端口）弹出堆栈顶部，并根据指定的输出端口号port转发数据包
    }

    action srcRoute_finish() {
        hdr.ethernet.etherType = TYPE_IPV4;  //修改etherType跳到IP解析
    }

    action update_ttl(){
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;  //使用源路由转发数据包，IPv4的TTL同步递减
    }

    apply {
        if (hdr.srcRoutes[0].isValid()){  //检查源路由（srcRoutes[0]）是否存在
            /*
             * TODO: add logic to:
             * - If final srcRoutes (top of stack has bos==1):
             *   - change etherType to IP
             * - choose next hop and remove top of srcRoutes stack
             */
            if (hdr.srcRoutes[0].bos == 1){  //特定值bos为1，表示到达堆栈底部，为最后一跳
                srcRoute_finish();
            }
            srcRoute_nhop();
            if (hdr.ipv4.isValid()){
                update_ttl();
            }
        }else{
            drop();  //如果源路由无效，则丢包
        }
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

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.srcRoutes);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
