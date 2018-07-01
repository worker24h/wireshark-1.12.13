
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <glib.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/packet.h>
#include "wsutil/pint.h"
#include "packet-tcp.h"

#define _DEBUG_ETCD_ 1
static FILE *logFile = NULL; 
static void 
etcd_open_logfile() 
{
    logFile = fopen("C:\\etcd.parse.log", "w");
}

static void 
etcd_write_logfile(char *data) 
{    
    fwrite(data, strlen(data), 1, logFile);   
}

static void 
etcd_close_logfile() 
{
    fclose(logFile);
}


#ifdef _MSC_VER
/* MSVC is stuck in the last century and doesn't have C99's stdint.h. */
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
#else
#include <stdint.h>
#endif

#define align8(s) ((s)+7)&(~7) //8字节对齐

void proto_register_etcd_protocol (void);
void proto_reg_handoff_etcd_protocol(void);

/*
 * 每个bit为1 代表对应的数据结构中该字段是有值 用于wireshark解析
 */
static int message_filed_bit = 0;
typedef enum _message_bitmap {
    mbm_type_bit1 = 0x1,
    mbm_to_bit2 = 0x01 << 1,
    mbm_from_bit3 = 0x01 << 2,
    mbm_term_bit4 = 0x01 << 3,
    mbm_logterm_bit5 = 0x01 << 4,
    mbm_index_bit6 = 0x01 << 5,
    mbm_entry_bit7 = 0x01 << 6,
    mbm_commit_bit8 = 0x01 << 7,
    mbm_snapshot_bit9 = 0x01 << 8,
    mbm_reject_bit10 = 0x01 << 9,
    mbm_rejecthint_bit11 = 0x01 << 10,
    mbm_context_bit12 = 0x01 << 11,
}message_bitmap;

static int snapshot_filed_bit = 0;
typedef enum _snapshot_bitmap {
    sbm_data_bit1 = 1,
    sbm_metadata_bit2 = 0x01 << 1,
}snapshot_bitmap;
static int snapshot_len = 0;

static int entry_filed_bit =0 ;

static gboolean etcd_protocol_buffer_desegment = TRUE;

static int proto_etcd_grpc = -1;
static int hf_etcd_pb_header = -1;
static int hf_etcd_pb_length = -1;
static int hr_etcd_pb_end = -1;

static int hf_etcd_pb_filed_flag = -1;
static int hf_etcd_pb_filed_num = -1;
static int hf_etcd_pb_wire_type = -1;

static int hf_etcd_pb_message_type = -1;
static int hf_etcd_pb_message_to = -1;
static int hf_etcd_pb_message_from = -1;
static int hf_etcd_pb_message_term = -1;
static int hf_etcd_pb_message_logterm = -1;

static int hf_etcd_pb_entry_type = -1;

static int hf_etcd_pb_message_index = -1;
static int hf_etcd_pb_message_entries = -1;
static int hf_etcd_pb_message_commit = -1;
static int hf_etcd_pb_message_snapshot_len = -1;
static int hf_etcd_pb_message_entry_len = -1;
static int hf_etcd_pb_message_metadata_len = -1;
static int hf_etcd_pb_message_conf_len = -1;
static int hf_etcd_pb_message_conf_nodes = -1;
static int hf_etcd_pb_message_reject = -1;
static int hf_etcd_pb_message_rejecthint = -1;
static int hf_etcd_pb_message_context = -1;
static int hf_etcd_pb_message_playload_len = -1;
static int hf_etcd_pb_message_private_data = -1;
static int hf_etcd_pb_message_context_len = -1;
static int hf_etcd_pb_message_context_data = -1;

static int hf_etcd_pb_message_msgappv2_msgtype = -1;
static int hf_etcd_pb_message_msgappv2_entries = -1;
static int hf_etcd_pb_message_msgappv2_data_len = -1;
static int hf_etcd_pb_message_msgappv2_commit = -1;

static int hf_etcd_pb_request_length = -1;
static int hf_etcd_pb_message_request_id = -1;
static int hf_etcd_pb_message_request_method = -1;
static int hf_etcd_pb_message_request_path = -1;
static int hf_etcd_pb_message_request_val = -1;
static int hf_etcd_pb_message_request_dir = -1;
static int hf_etcd_pb_message_request_prev_value = -1;
static int hf_etcd_pb_message_request_prev_index = -1;
static int hf_etcd_pb_message_request_prev_exist = -1;
static int hf_etcd_pb_message_request_expiration = -1;
static int hf_etcd_pb_message_request_wait = -1;
static int hf_etcd_pb_message_request_since = -1;
static int hf_etcd_pb_message_request_recursive = -1;
static int hf_etcd_pb_message_request_sorted = -1;
static int hf_etcd_pb_message_request_quorum = -1;
static int hf_etcd_pb_message_request_time = -1;
static int hf_etcd_pb_message_request_stream = -1;
static int hf_etcd_pb_message_request_refresh = -1;
static int hf_etcd_pb_message_request_pad = -1;


static gint ett_etcd_items = -1;
static gint ett_etcd_pb_snapshot = -1;
static gint ett_etcd_pb_snapshot_hdr = -1;
static gint ett_etcd_pb_snapshot_data = -1;
static gint ett_etcd_pb_entry = -1;
static gint ett_etcd_pb_entry_hdr = -1;
static gint ett_etcd_pb_entry_data = -1;
static gint ett_etcd_pb_entry_private_data = -1;

static gint ett_etcd_pb_snap_metadata = -1;
static gint ett_etcd_pb_snap_metadata_hdr = -1;
static gint ett_etcd_pb_snap_metadata_data = -1;

static gint ett_etcd = -1;
static gint ett_etcd_hdr = -1;
static gint ett_etcd_protocol_field = -1;
static gint ett_etcd_protocol_field_hdr = -1;

#define BITMAP_FIELD_INFO_LEN  1
#define TCP_ETCD_CLUSTER_PORT  2380
#define TCP_ETCD_SERVER_PORT   2379


#define MsgHup             0  //用于激发选举流程
#define MsgBeat            1  //内部消息 用于通知leader发送心跳消息MsgHeartbeat
#define MsgProp            2  //
#define MsgApp             3  //包含log entries消息 同步数据 由leader发出
#define MsgAppResp         4  //针对MsgApp的响应消息
#define MsgVote            5  // 投票消息
#define MsgVoteResp        6  // 投票响应消息
#define MsgSnap            7
#define MsgHeartbeat       8  //心跳消息
#define MsgHeartbeatResp   9  //心跳响应消息
#define MsgUnreachable     10
#define MsgSnapStatus      11
#define MsgCheckQuorum     12
#define MsgTransferLeader  13
#define MsgTimeoutNow      14
#define MsgReadIndex       15
#define MsgReadIndexResp   16
#define MsgPreVote         17
#define MsgPreVoteResp     18

/* etcd types */
static const value_string etcd_types[] = {
    {MsgHup              ,"MsgHup"},
    {MsgBeat             ,"MsgBeat"},
    {MsgProp             ,"MsgProp"},
    {MsgApp              ,"MsgApp"},
    {MsgAppResp          ,"MsgAppResp"},
    {MsgVote             ,"MsgVote"},
    {MsgVoteResp         ,"MsgVoteResp"},
    {MsgSnap             ,"MsgSnap"},
    {MsgHeartbeat        ,"MsgHeartbeat"},
    {MsgHeartbeatResp    ,"MsgHeartbeatResp"},
    {MsgUnreachable      ,"MsgUnreachable"},
    {MsgSnapStatus       ,"MsgSnapStatus"},
    {MsgCheckQuorum      ,"MsgCheckQuorum"},
    {MsgTransferLeader   ,"MsgTransferLeader"},
    {MsgTimeoutNow       ,"MsgTimeoutNow"},
    {MsgReadIndex        ,"MsgReadIndex"},
    {MsgReadIndexResp    ,"MsgReadIndexResp"},
    {MsgPreVote          ,"MsgPreVote"},
    {MsgPreVoteResp      ,"MsgPreVoteResp"},
    {0, NULL }
};


#define EntryNormal      0
#define EntryConfChange  1

/* etcd types */
static const value_string etcd_entry_types[] = {
    {EntryNormal          ,"EntryNormal"},
    {EntryConfChange      ,"EntryConfChange"},
    {0, NULL }
};

#define TYPE_LINK_HEARTBEAT 0
#define TYPE_APP_ENTRY      1
#define TYPE_MSG_APP        2
/* etcd types */
static const value_string etcd_msgapp_types[] = {
    {TYPE_LINK_HEARTBEAT   ,"LinkHeartbeat"},
    {TYPE_APP_ENTRY        ,"AppEntry"},
    {TYPE_MSG_APP          ,"MsgApp"},
    {0, NULL }
};



#define GRPC_DATA_END(b)      ((b) < 0x80)
#define GRPC_DATA(b)          ((b) & 0x7F)
#define GRPC_FIELD_NUM(b)     ((b) >> 3)
#define GRPC_FIELD_TYPE(b)    ((b) & 0x7)


static guint32
protocol_tvb_get_uint64(tvbuff_t *tvb, int offset,  uint64_t *d) 
{
    uint64_t b    = 0;
    uint64_t b64  = 0;
    guint32 pos   = 0;
    guint32 shift = 0;
    
    for (shift = 0; shift < 64; shift +=7) {
        b = tvb_get_guint8(tvb, offset++);
        pos++;
        (*d) |= GRPC_DATA(b) << shift;
        if (GRPC_DATA_END(b)) {
            break;
        }
    }
    return pos;
}


static guint32
protocol_get_uint64(guint8 *data, uint64_t *d) 
{
    guint8 b      = 0;
    guint32 pos   = 0;
    guint32 shift = 0;
    
    for (shift = 0; shift < 64; shift +=7) {
        b = data[pos++];
        (*d) |= GRPC_DATA(b) << shift;
        if (GRPC_DATA_END(b)) {
            break;
        }
    }
    return pos;
}


static guint32
protocol_get_uint32(guint8 *data, uint32_t *d) 
{
    guint8 b      = 0;
    guint32 pos   = 0;
    guint32 shift = 0;
    
    for (shift = 0; shift < 64; shift +=7) {
        b = data[pos++];
        (*d) |= GRPC_DATA(b) << shift;
        if (GRPC_DATA_END(b)) {
            break;
        }
    }
    return pos;
}

static uint64_t
dissect_etcd_header(tvbuff_t *raw_tvb, packet_info *pinfo _U_, proto_tree *tree, gint *offset)
{
    proto_item  *ti;
    gint item_len = 0, next_offset = 0;
    proto_tree *etcd_header_tree;
    uint64_t real_data_len = 0;

    item_len = tvb_find_line_end(raw_tvb, *offset, -1, &next_offset, FALSE);
    ti = proto_tree_add_text(tree, raw_tvb, *offset, item_len+2, "Etcd Header");//加2代表后面的\r\n
    etcd_header_tree = proto_item_add_subtree(ti, ett_etcd_hdr);
    proto_tree_add_item(etcd_header_tree, hf_etcd_pb_header, raw_tvb, *offset, item_len+2, ENC_NA);
    *offset = next_offset;
    return item_len + 2;
}

static void 
get_field_info(tvbuff_t *raw_tvb, gint offset, guint8 *field_num, guint8 *wire_type)
{
    guint8 field_info = 0;
    field_info = tvb_get_guint8(raw_tvb, offset);
    *field_num = field_info >> 3;
    *wire_type = field_info & 0x7F;
    return;
}

static proto_tree *
dissect_etcd_flags(tvbuff_t *raw_tvb, proto_tree *tree, gint offset, uint64_t total_len, const char *treename)
{
    proto_item  *ti;
    proto_tree *flags_tree, *filed_tree;

    ti = proto_tree_add_text(tree, raw_tvb, offset, (gint)total_len, treename);
    filed_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

    ti = proto_tree_add_text(filed_tree, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "FieldInfo");
    flags_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

    proto_tree_add_bits_item(flags_tree, hf_etcd_pb_filed_num, raw_tvb, (offset * 8), 5, ENC_NA);
    proto_tree_add_bits_item(flags_tree, hf_etcd_pb_wire_type, raw_tvb, (offset * 8) + 5, 3, ENC_NA);
    return filed_tree;
}

static proto_tree *
dissect_etcd_snapshot_header(tvbuff_t *raw_tvb, proto_tree *tree, gint offset, uint64_t total_len)
{
    proto_item  *ti;
    proto_tree *snapshot, *snapshot_hdr, *filed_tree, *data_tree = NULL;
    gint e_len = 0;
    uint64_t e = 0;
    ti = proto_tree_add_text(tree, raw_tvb, offset, (gint)total_len, "Snapshot");
    snapshot = proto_item_add_subtree(ti, ett_etcd_pb_snapshot);

    ti = proto_tree_add_text(snapshot, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "Snapshot Header");
    snapshot_hdr = proto_item_add_subtree(ti, ett_etcd_pb_snapshot_hdr);

    ti = proto_tree_add_text(snapshot_hdr, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "FieldInfo");
    filed_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

    // field info
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_filed_num, raw_tvb, (offset * 8), 5, ENC_NA);
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_wire_type, raw_tvb, (offset * 8) + 5, 3, ENC_NA);
    offset++;

    //消息长度    
    e_len = protocol_tvb_get_uint64(raw_tvb, offset, &e);
    proto_tree_add_bytes_format_value(snapshot_hdr, hf_etcd_pb_message_snapshot_len, 
                                raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
    offset+=e_len;

    if (e) {
        ti = proto_tree_add_text(snapshot, raw_tvb, offset, (gint)e, "Data");
        data_tree = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata_data);
    }
    return data_tree;
}

static proto_tree *
dissect_etcd_entry_header(tvbuff_t *raw_tvb, proto_tree *tree, gint offset, uint64_t total_len)
{
    proto_item  *ti;
    proto_tree *snapshot, *snapshot_hdr, *filed_tree, *data_tree = NULL;
    gint e_len = 0;
    uint64_t e = 0;
    ti = proto_tree_add_text(tree, raw_tvb, offset, (gint)total_len, "Entry");
    snapshot = proto_item_add_subtree(ti, ett_etcd_pb_entry);

    ti = proto_tree_add_text(snapshot, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "Enty Header");
    snapshot_hdr = proto_item_add_subtree(ti, ett_etcd_pb_entry_hdr);

    ti = proto_tree_add_text(snapshot_hdr, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "FieldInfo");
    filed_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

    // field info
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_filed_num, raw_tvb, (offset * 8), 5, ENC_NA);
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_wire_type, raw_tvb, (offset * 8) + 5, 3, ENC_NA);
    offset++;

    //消息长度    
    e_len = protocol_tvb_get_uint64(raw_tvb, offset, &e);
    proto_tree_add_bytes_format_value(snapshot_hdr, hf_etcd_pb_message_entry_len, 
                                raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
    offset+=e_len;

    if (e) {
        ti = proto_tree_add_text(snapshot, raw_tvb, offset, (gint)e, "Data");
        data_tree = proto_item_add_subtree(ti, ett_etcd_pb_entry_data);
    }
    return data_tree;
}

static proto_tree *
dissect_etcd_snapshot_metadata_header(tvbuff_t *raw_tvb, proto_tree *tree, gint offset, uint64_t total_len)
{
    proto_item  *ti;
    proto_tree *snapshot, *snapshot_hdr, *filed_tree, *data_tree = NULL;
    gint e_len = 0;
    uint64_t e = 0;
    ti = proto_tree_add_text(tree, raw_tvb, offset, (gint)total_len, "Metadata");
    snapshot = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata);

    ti = proto_tree_add_text(snapshot, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "Metadata Header");
    snapshot_hdr = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata_hdr);

    ti = proto_tree_add_text(snapshot_hdr, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "FieldInfo");
    filed_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

    // field info
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_filed_num, raw_tvb, (offset * 8), 5, ENC_NA);
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_wire_type, raw_tvb, (offset * 8) + 5, 3, ENC_NA);
    offset++;

    //消息长度    
    e_len = protocol_tvb_get_uint64(raw_tvb, offset, &e);
    proto_tree_add_bytes_format_value(snapshot_hdr, hf_etcd_pb_message_metadata_len, 
                                raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
    offset+=e_len;

    if (e) {
        ti = proto_tree_add_text(snapshot, raw_tvb, offset, (gint)e, "Data");
        data_tree = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata_data);
    }
    return data_tree;
}

static proto_tree *
dissect_etcd_snapshot_confstate_header(tvbuff_t *raw_tvb, proto_tree *tree, gint offset, uint64_t total_len)
{
    proto_item  *ti;
    proto_tree *snapshot, *snapshot_hdr, *filed_tree, *data_tree = NULL;
    gint e_len = 0;
    uint64_t e = 0;
    ti = proto_tree_add_text(tree, raw_tvb, offset, (gint)total_len, "ConfState");
    snapshot = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata);

    ti = proto_tree_add_text(snapshot, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "ConfState Header");
    snapshot_hdr = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata_hdr);

    ti = proto_tree_add_text(snapshot_hdr, raw_tvb, offset, BITMAP_FIELD_INFO_LEN, "FieldInfo");
    filed_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

    // field info
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_filed_num, raw_tvb, (offset * 8), 5, ENC_NA);
    proto_tree_add_bits_item(filed_tree, hf_etcd_pb_wire_type, raw_tvb, (offset * 8) + 5, 3, ENC_NA);
    offset++;

    //消息长度    
    e_len = protocol_tvb_get_uint64(raw_tvb, offset, &e);
    proto_tree_add_bytes_format_value(snapshot_hdr, hf_etcd_pb_message_metadata_len, 
                                raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
    offset+=e_len;
    if (e) {
        ti = proto_tree_add_text(snapshot, raw_tvb, offset, (gint)e, "Data");
        data_tree = proto_item_add_subtree(ti, ett_etcd_pb_snap_metadata_data);
    }
    return data_tree;
}


static void
dissect_etcd_pb_confstate_message(tvbuff_t *raw_tvb, gint offset, proto_tree *conf_tree, guint data_length)
{
    proto_tree  *flags_tree;
    guint32 e_len;
    uint64_t e;
    guint32 len = 0;
    guint8 field_num = 0, wire_type = 0;

    while (len < data_length) {
        get_field_info(raw_tvb, offset, &field_num, &wire_type);
        e = e_len = 0;
        switch(field_num) {            
            case 1:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, conf_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Nodes");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_index, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            default:
                break;                
        } 
    }
    return;
}


static void
dissect_etcd_pb_metadata_message(tvbuff_t *raw_tvb, gint offset, proto_tree *metadata_tree, guint data_length)
{
    proto_tree  *data_tree, *flags_tree;
    guint32 e_len;
    uint64_t e;
    guint32 len = 0;
    guint8 field_num = 0, wire_type = 0;        
        
    while (len < data_length) {
        get_field_info(raw_tvb, offset, &field_num, &wire_type);        
        e = e_len = 0;
        switch(field_num) {
            case 1:
                /* 先获取数据总长度 */
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_snapshot_confstate_header(raw_tvb, metadata_tree, offset, e_len+e+BITMAP_FIELD_INFO_LEN);
                offset += e_len + BITMAP_FIELD_INFO_LEN;
                len += e_len + BITMAP_FIELD_INFO_LEN;
                //解析confstate消息 变量e表示confstate长度
                if (e) {
                    dissect_etcd_pb_confstate_message(raw_tvb, offset, data_tree, (guint)e);
                    len += (gint)e;
                    offset += (gint)e;
                }

                break;
            case 2:
                /* 先获取数据总长度 */
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, metadata_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Index");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_index, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 3:
                /* 先获取数据总长度 */
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, metadata_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Term");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_term, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            default:
                break;                
        } 
    }
    return ;
}
static void
dissect_etcd_pb_request_message(tvbuff_t *raw_tvb, gint offset, proto_tree *entry_tree, uint64_t data_length)
{
    proto_tree  *data_tree;
    guint32 e_len;
    uint64_t e;
    guint32 len = 0;
    guint8 field_num = 0, wire_type = 0;        
        
    while (len < data_length) {
        get_field_info(raw_tvb, offset, &field_num, &wire_type);        
        e = e_len = 0;
        switch(field_num) {
            case 1:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "ID");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_id, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 2:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Method");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_request_length, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                
                proto_tree_add_item(data_tree, hf_etcd_pb_message_request_method, raw_tvb, offset, (guint)e, ENC_NA);                            
                len += (gint)e;
                offset += (gint)e;
                break;
            case 3:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "PATH");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_request_length, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                
                proto_tree_add_item(data_tree, hf_etcd_pb_message_request_path, raw_tvb, offset, (guint)e, ENC_NA);                            
                len += (gint)e;
                offset += (gint)e;
                break;
            case 4:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Body");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_request_length, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                
                proto_tree_add_item(data_tree, hf_etcd_pb_message_request_val, raw_tvb, offset, (guint)e, ENC_NA);                            
                len += (gint)e;
                offset += (gint)e;
                break;
             case 5:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "IsDir");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_dir, 
                            raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;
                break;
             case 6:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "PreValue");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_request_length, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                
                proto_tree_add_item(data_tree, hf_etcd_pb_message_request_prev_value, raw_tvb, offset, (guint)e, ENC_NA);                            
                len += (gint)e;
                offset += (gint)e;
                break;
             case 7:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "PrevIndex");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_prev_index, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
             case 8:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "PrevExist");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_prev_exist, 
                            raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;
                break;
             case 9:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Expiration");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_prev_index, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;                
                break;
            case 10:
               e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
               data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Wait");
               offset+=BITMAP_FIELD_INFO_LEN;
               len+=BITMAP_FIELD_INFO_LEN;
               proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_wait, 
                           raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
               offset += e_len;
               len += e_len;
               break;
            case 11:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Since");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_since, 
                         raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 12:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Recursive");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_recursive, 
                          raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;
                break;
            case 13:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Sort");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_sorted, 
                          raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;
                break;
            case 14:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Quorum");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_quorum,
                          raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;
                break;
            case 15:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Time");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_time, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 16:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Stream");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_stream,
                          raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;
                break;
            case 17:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Refresh");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_request_refresh,
                          raw_tvb, offset, e_len, NULL, "%s [*]", e?"TRUE":"FALSE");
                offset += e_len;
                len += e_len;                
                break;
            default:
                //补齐字段                                
                proto_tree_add_item(entry_tree, hf_etcd_pb_message_request_pad, raw_tvb, offset, (guint)(data_length - len), ENC_NA);
                len = (guint)data_length;//结束循环
                break;
        }
    }
}

static void
dissect_etcd_pb_entry_message(tvbuff_t *raw_tvb, gint offset, proto_tree *entry_tree, uint64_t data_length)
{
    proto_tree  *data_tree, *entry_data_tree;
    proto_item  *ti;
    guint32 e_len;
    uint64_t e;
    guint32 len = 0, msglen = 0;
    guint8 field_num = 0, wire_type = 0;        
        
    while (len < data_length) {
        get_field_info(raw_tvb, offset, &field_num, &wire_type);        
        e = e_len = 0;
        switch(field_num) {
            case 1:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "EntryType");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_entry_type, 
                            raw_tvb, offset, e_len, NULL, "%s (%d) [*]", 
                            etcd_entry_types[e].strptr, e);
                offset += e_len;
                len += e_len;
                break;
            case 2:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Term");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_term, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 3:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, entry_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Index");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_index, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 4:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                ti = proto_tree_add_text(entry_tree, raw_tvb, offset, (gint)(e_len+e+BITMAP_FIELD_INFO_LEN), "Data");
                data_tree = proto_item_add_subtree(ti, ett_etcd_protocol_field);

                entry_data_tree = dissect_etcd_flags(raw_tvb, data_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "EntryLen");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(entry_data_tree, hf_etcd_pb_message_entry_len, 
                                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                
                /* e表示私有数据长度 */                
                dissect_etcd_pb_request_message(raw_tvb, offset, data_tree, e);
                len += (gint)e;
                offset += (gint)e;
                break;
            default:
                break;                
        } 
    }
    return ;
}

static void
dissect_etcd_pb_snapshot_message(tvbuff_t *raw_tvb, gint offset, proto_tree *snapshot_tree, guint data_length)
{
    proto_tree  *data_tree;
    guint32 e_len;
    uint64_t e;
    guint32 len = 0, msglen = 0;
    guint8 field_num = 0, wire_type = 0;        
        
    while (len < data_length) {
        get_field_info(raw_tvb, offset, &field_num, &wire_type);        
        e = e_len = 0;
        switch(field_num) {
            case 1:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_flags(raw_tvb, snapshot_tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Data");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(data_tree, hf_etcd_pb_message_type, 
                            raw_tvb, offset, e_len, NULL, "%s (%d) [*]", 
                            etcd_types[e].strptr, e);
                offset += e_len;
                len += e_len;
                
                /* e表示私有数据长度 */
                proto_tree_add_item(data_tree, hf_etcd_pb_message_private_data, raw_tvb, offset, (guint)e, ENC_NA);
                len += (gint)e;
                offset += (gint)e;
                break;
            case 2:
                /* 先获取数据总长度 */
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_snapshot_metadata_header(raw_tvb, snapshot_tree, offset, e_len+e+BITMAP_FIELD_INFO_LEN);
                offset += e_len + BITMAP_FIELD_INFO_LEN;
                len += e_len + BITMAP_FIELD_INFO_LEN;
                //解析snapshot消息 变量e表示snapshot长度
                if (e) {
                    dissect_etcd_pb_metadata_message(raw_tvb, offset, data_tree, (guint)e);
                    len += (gint)e;
                    offset += (gint)e;
                }
                break;
            default:
                break;                
        } 
    }
    return ;
}

static void 
parse_protocol_buffer_message(tvbuff_t *raw_tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, guint64 length)
{
    uint64_t e = 0; /* etcd protocol data */
    guint32 e_len = 0;
    guint8 field_num = 0, wire_type = 0;
    proto_tree *flags_tree, *data_tree;
    guint32 len = 0;

    while (len < length) {
        //由于Etcd中定义的字段数量 用一个字节就可以表示，这里就简单处理读取一个字节
        get_field_info(raw_tvb, offset, &field_num, &wire_type);        
        
        e = e_len = 0;
        switch(field_num) {
            case 1:
                /* 先获取数据总长度 */
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Type");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_type, 
                            raw_tvb, offset, e_len, NULL, "%s (%d) [*]", 
                            etcd_types[e].strptr, e);                
                col_set_str(pinfo->cinfo, COL_INFO, etcd_types[e].strptr); //设置col列名称
                offset += e_len;
                len += e_len;
                break;
            case 2:
                /* 先获取数据总长度 */
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "To");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_to, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 3:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "From");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_from, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 4:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Term");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_term, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 5:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "LogTerm");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_logterm, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;                
                break;
            case 6:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Index");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_index, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 7:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_entry_header(raw_tvb, tree, offset, e_len+e+BITMAP_FIELD_INFO_LEN);
                offset += e_len + BITMAP_FIELD_INFO_LEN;
                len += e_len + BITMAP_FIELD_INFO_LEN;
                //解析snapshot消息 变量e表示snapshot长度
                if (e) {
                    dissect_etcd_pb_entry_message(raw_tvb, offset, data_tree, (guint)e);
                    len += (gint)e;
                    offset += (gint)e;
                }
                break;
            case 8:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Commit");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_commit, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 9:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                data_tree = dissect_etcd_snapshot_header(raw_tvb, tree, offset, e_len+e+BITMAP_FIELD_INFO_LEN);
                offset += e_len + BITMAP_FIELD_INFO_LEN;
                len += e_len + BITMAP_FIELD_INFO_LEN;
                //解析snapshot消息 变量e表示snapshot长度
                if (e) {
                    dissect_etcd_pb_snapshot_message(raw_tvb, offset, data_tree, (guint)e);
                    len += (gint)e;
                    offset += (gint)e;
                }
                break;
            case 10:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "Reject");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_reject, 
                            raw_tvb, offset, e_len, NULL, "%s [*]", e?"True":"False");
                offset += e_len;
                len += e_len;
                break;
            case 11:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+BITMAP_FIELD_INFO_LEN, "RejectHint");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_rejecthint, 
                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                break;
            case 12:
                e_len = protocol_tvb_get_uint64(raw_tvb, offset+BITMAP_FIELD_INFO_LEN, &e);
                flags_tree = dissect_etcd_flags(raw_tvb, tree, offset, e_len+e+BITMAP_FIELD_INFO_LEN, "Data");
                offset+=BITMAP_FIELD_INFO_LEN;
                len+=BITMAP_FIELD_INFO_LEN;
                proto_tree_add_bytes_format_value(flags_tree, hf_etcd_pb_message_context_len, 
                                            raw_tvb, offset, e_len, NULL, "0x%llx [*]", e);
                offset += e_len;
                len += e_len;
                
                /* e表示私有数据长度 */
                proto_tree_add_item(flags_tree, hf_etcd_pb_message_context_data, raw_tvb, offset, (guint)e, ENC_NA);
                len += (gint)e;
                offset += (gint)e;
                break;
        }
    }
    return;
}

static proto_tree * 
create_item_tree(tvbuff_t *raw_tvb, proto_tree *tree, int *offset, uint64_t *real_data_len, int item) {
    proto_item  *ti;
    gint item_len = 0, next_offset = 0;
    proto_tree *etcd_item_tree;
    
    *real_data_len = tvb_get_ntoh64(raw_tvb, *offset);
    ti = proto_tree_add_text(tree, raw_tvb, *offset, (gint)(*real_data_len+8), "Item.%d", item);//加8代表后面的length长度
    etcd_item_tree = proto_item_add_subtree(ti, ett_etcd_items);
    proto_tree_add_item(etcd_item_tree, hf_etcd_pb_length, raw_tvb, *offset, 8, ENC_BIG_ENDIAN);
    *offset += 8;
    return etcd_item_tree;
}

static gboolean
is_http_packet(tvbuff_t *tvb, packet_info *pinfo)
{
    gint offset = 0, next_offset, linelen;

    /* Check if we have a line terminated by CRLF
     * Return the length of the line (not counting the line terminator at
     * the end), or, if we don't find a line terminator:
     *
     *      if "deseg" is true, return -1;
     */
    linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, TRUE);
    if((linelen == -1)||(linelen == 8)){
        return FALSE;
    }

    /* Check if the line start or ends with the HTTP token */
    if((tvb_strncaseeql(tvb, linelen-8, "HTTP/1.1", 8) == 0)||(tvb_strncaseeql(tvb, 0, "HTTP/1.1", 8) == 0)) {        
        return TRUE;
    }

    return FALSE;
}

static gboolean
is_msgappv2_message(tvbuff_t *tvb, gint offset, guint32 length)
{
    guint8 type = tvb_get_guint8(tvb, offset);
    if ((type == TYPE_LINK_HEARTBEAT && length == 6)|| type == TYPE_APP_ENTRY || 
        type == TYPE_MSG_APP) {
        return TRUE;
    } else {
        return FALSE;
    }
}
static int
dissect_etcd_msgapp_v2_message(tvbuff_t *raw_tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    guint8 type;
    uint64_t entries;
    uint64_t entry_data_len;
    uint64_t ii = 0;
    proto_tree *entry_tree;
    proto_item *ti;

    type = tvb_get_guint8(raw_tvb, offset);
    proto_tree_add_item(tree, hf_etcd_pb_message_msgappv2_msgtype, raw_tvb, offset, 1, ENC_NA);
    offset++;
    col_set_str(pinfo->cinfo, COL_INFO, etcd_msgapp_types[type].strptr); //设置col列名称
    switch (type) {            
        case 0:            
            break;
        case 1:
            entries = tvb_get_ntoh64(raw_tvb, offset);
            proto_tree_add_item(tree, hf_etcd_pb_message_msgappv2_entries, raw_tvb, offset, 8, ENC_BIG_ENDIAN);
            offset+=8;
            for (ii = 0; ii < entries; ii++) {
                entry_data_len =  tvb_get_ntoh64(raw_tvb, offset);
                ti = proto_tree_add_text(tree, raw_tvb, offset, (gint)(entry_data_len+8), "Entry.%d", ii+1);//加8代表后面的length长度
                entry_tree = proto_item_add_subtree(ti, ett_etcd_items);

                proto_tree_add_item(entry_tree, hf_etcd_pb_message_msgappv2_data_len, raw_tvb, offset, 8, ENC_BIG_ENDIAN);
                offset+=8;
                //parse entry
                dissect_etcd_pb_entry_message(raw_tvb, offset, entry_tree, entry_data_len);
                offset += (guint)entry_data_len;
            }            
            proto_tree_add_item(tree, hf_etcd_pb_message_msgappv2_commit, raw_tvb, offset, 8, ENC_BIG_ENDIAN);
            offset+=8;
            break;
        case 2:        
            entry_data_len =  tvb_get_ntoh64(raw_tvb, offset);
            proto_tree_add_item(tree, hf_etcd_pb_message_msgappv2_data_len, raw_tvb, offset, 8, ENC_BIG_ENDIAN);
            offset+=8;           
            proto_tree_add_item(tree, hf_etcd_pb_message_private_data, raw_tvb, offset, (guint)entry_data_len, ENC_NA);
            offset += (guint)entry_data_len;
            break;
        default:
            break;
    }
    
    return offset;
}

static int
dissect_etcd_pb_message(tvbuff_t *raw_tvb, packet_info *pinfo, proto_tree *tree, gint offset, guint length)
{
    uint64_t     len  = 0;
    uint64_t    data_real_len = 0;
    proto_tree *data_tree;
    int item = 0;

    if (is_http_packet(raw_tvb, pinfo)) {//http 报文
        dissector_handle_t http_handle = find_dissector("http");
        call_dissector(http_handle, raw_tvb, pinfo, tree);
        return length;
    }
    
    //显示头部信息      
    data_real_len = dissect_etcd_header(raw_tvb, pinfo, tree, &offset);
    if (is_msgappv2_message(raw_tvb, offset, length)) {//特定报文
        offset = dissect_etcd_msgapp_v2_message(raw_tvb, pinfo, tree, offset);
    } else {
        while(data_real_len < (length-2)) {// length - 2 减去最后一个\r\n        
            data_tree = create_item_tree(raw_tvb, tree, &offset, &len, ++item);        
            parse_protocol_buffer_message(raw_tvb, pinfo, data_tree, offset, len);
            data_real_len += len + 8; //加8 表示playload长度字段所占字节数
            offset += (guint)len;     
        }
    }
    proto_tree_add_item(tree, hr_etcd_pb_end, raw_tvb, offset, 2, ENC_NA);
    return length;
}

static guint
get_etcd_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return tvb_captured_length(tvb);
}

static void
dissect_etcd_msg_tree(tvbuff_t *tvb, proto_tree *tree, guint tree_mode, packet_info *pinfo)
{
    proto_tree *etcd_tree;
    proto_item *ti;

    int         offset = 0;
    guint       len    = 0;

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", "Etcd Packet!!");
    len = get_etcd_pdu_length(pinfo, tvb, 0);
    ti = proto_tree_add_item(tree, proto_etcd_grpc, tvb, offset, len, ENC_NA);
    etcd_tree = proto_item_add_subtree(ti, tree_mode);

    dissect_etcd_pb_message(tvb, pinfo, etcd_tree, offset, len);
    return;
}

static int
dissect_etcd_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Etcd");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    dissect_etcd_msg_tree(tvb, tree, ett_etcd, pinfo);
    return tvb_length(tvb);
}

static int
dissect_etcd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    gint next_offset = 0;
    guint header_len = 0;

    /* header_len不包含\r\n next_offset跳过\r\n */
    header_len = tvb_find_line_end(tvb, 0, -1, &next_offset, FALSE);

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, header_len + 2,
                     get_etcd_pdu_length, dissect_etcd_pdu, data);
    return tvb_captured_length(tvb);
}


void proto_register_etcd_protocol (void) 
{
    static hf_register_info hf[] = {
        { &hf_etcd_pb_header,
            { "Header", "etcd.protocol.buferr.header",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_length,
            { "Length", "etcd.protocol.buferr.length",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hr_etcd_pb_end,
            { "Etcd End", "etcd.protocol.buferr.end",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_filed_num,
            { "FieldNum", "etcd.protocol.buferr.filed.num",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_wire_type,
            { "WireType", "etcd.protocol.buferr.wire.type",
               FT_UINT8, BASE_DEC, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_type,
            { "Value", "etcd.protocol.buferr.type",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_to,
            { "Value", "etcd.protocol.buferr.to",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_from,
            { "Value", "etcd.protocol.buferr.from",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_term,
            { "Value", "etcd.protocol.buferr.term",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_logterm,
            { "Value", "etcd.protocol.buferr.logterm",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_index,
            { "Value", "etcd.protocol.buferr.index",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_commit,
            { "Value", "etcd.protocol.buferr.commit",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_snapshot_len,
            { "SnapLen", "etcd.protocol.buferr.snap.len",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_entry_len,
            { "EntryLen", "etcd.protocol.buferr.entry.len",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_metadata_len,
            { "MetadataLen", "etcd.protocol.buferr.metadata.len",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_conf_len,
            { "ConfLen", "etcd.protocol.buferr.conf.len",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_conf_nodes,
            { "Nodes", "etcd.protocol.buferr.conf.nodes",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_private_data,
            { "Data", "etcd.protocol.buferr.data",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },        
        { &hf_etcd_pb_message_context_len,
            { "ContextLen", "etcd.protocol.buferr.context.len",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_context_data,
            { "Data", "etcd.protocol.buferr.context.data",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_entry_type,
            { "Value", "etcd.protocol.buferr.entry.type",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_playload_len,
            { "PlayLoadLen", "etcd.protocol.buferr.playload.len",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_reject,
            { "Value", "etcd.protocol.buferr.reject",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_rejecthint,
            { "Value", "etcd.protocol.buferr.rejecthint",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_msgappv2_msgtype,
            { "Type", "etcd.protocol.buferr.msgapp.msgtype",
               FT_UINT8, BASE_DEC, VALS(etcd_msgapp_types), 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_msgappv2_entries,
            { "Entries", "etcd.protocol.buferr.msgapp.entries",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_msgappv2_data_len,
            { "DataLen", "etcd.protocol.buferr.msgapp.entry.len",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_msgappv2_commit,
            { "Commit", "etcd.protocol.buferr.msgapp.commit",
               FT_UINT64, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
        },        
        { &hf_etcd_pb_request_length,
            { "Len", "etcd.protocol.buferr.request.legth",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_id,
            { "Value", "etcd.protocol.buferr.request.id",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_method,
            { "Value", "etcd.protocol.buferr.request.method",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_path,
            { "Value", "etcd.protocol.buferr.request.path",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_val,
            { "Value", "etcd.protocol.buferr.request.val",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_dir,
            { "Value", "etcd.protocol.buferr.request.dir",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_prev_value,
            { "Value", "etcd.protocol.buferr.request.prev.value",
               FT_STRING, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_prev_index,
            { "Value", "etcd.protocol.buferr.request.prev.index",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_prev_exist,
            { "Value", "etcd.protocol.buferr.request.prev.exist",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_expiration,
            { "Value", "etcd.protocol.buferr.request.expiration",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_wait,
            { "Value", "etcd.protocol.buferr.request.wait",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_since,
            { "Value", "etcd.protocol.buferr.request.since",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_recursive,
            { "Value", "etcd.protocol.buferr.request.recursive",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_sorted,
            { "Value", "etcd.protocol.buferr.request.sorted",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_quorum,
            { "Value", "etcd.protocol.buferr.request.quorum",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_time,
            { "Value", "etcd.protocol.buferr.request.time",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_stream,
            { "Value", "etcd.protocol.buferr.request.stream",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_refresh,
            { "Value", "etcd.protocol.buferr.request.refresh",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        },
        { &hf_etcd_pb_message_request_pad,
            { "Pad", "etcd.protocol.buferr.request.pad",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL }
        }
    };
    static gint *etcd_ett[] = {
        &ett_etcd,
        &ett_etcd_hdr,
        &ett_etcd_items,
        &ett_etcd_protocol_field,
        &ett_etcd_protocol_field_hdr,
        &ett_etcd_pb_entry,
        &ett_etcd_pb_entry_hdr,
        &ett_etcd_pb_entry_data,
        &ett_etcd_pb_entry_private_data,
        &ett_etcd_pb_snapshot,
        &ett_etcd_pb_snapshot_hdr,
        &ett_etcd_pb_snapshot_data,
        &ett_etcd_pb_snap_metadata,
        &ett_etcd_pb_snap_metadata_hdr,
        &ett_etcd_pb_snap_metadata_data
    };

    //static ei_register_info etcd_ei[] = {
    //};

    expert_module_t* expert_etcd;

    /*Register the protocol name and description*/
    proto_etcd_grpc = proto_register_protocol ("Etcd With GRPC Protocol", "Etcd", "etcd");
    new_register_dissector("etcd_grpc_protocol", dissect_etcd, proto_etcd_grpc);
    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_etcd_grpc, hf, array_length(hf));   
    proto_register_subtree_array(etcd_ett, array_length(etcd_ett));   
    expert_etcd = expert_register_protocol(proto_etcd_grpc);  

    //expert_register_field_array(expert_etcd, etcd_ei, array_length(etcd_ei));
}

void proto_reg_handoff_etcd_protocol (void) 
{
    dissector_handle_t etcd_handle;
    
    etcd_handle = new_create_dissector_handle(dissect_etcd, proto_etcd_grpc);
    dissector_add_uint("tcp.port", TCP_ETCD_CLUSTER_PORT, etcd_handle);

}

// line = tvb_get_ptr(tvb, offset, first_linelen);
//first_linelen = tvb_find_line_end(tvb, offset,
//    tvb_ensure_length_remaining(tvb, offset), &next_offset,
//    TRUE);

