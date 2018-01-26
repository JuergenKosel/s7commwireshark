/* packet-s7comm_plus.c
 *
 * Author:      Thomas Wiens, 2014 <th.wiens@gmx.de>
 * Description: Wireshark dissector for S7 Communication plus
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*  Credits
 * =========
 * Thanks to all here unnamed people, for supporting with capture files,
 * informations, inspirations, bug reports and code patches.
 * Special thanks go to:
 * - Contributions from Softing (www.softing.com)
 * - Contributions from Tani GmbH (www.tanindustrie.de)
 */

#include "config.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_ZLIB
#define ZLIB_CONST
#include <zlib.h>
#endif

void proto_reg_handoff_s7commp(void);
void proto_register_s7commp(void);

static guint32 s7commp_decode_id_value_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 offset, gboolean recursive);
static guint32 s7commp_decode_attrib_subscriptionreflist(tvbuff_t *tvb, proto_tree *tree, guint32 offset);

//#define USE_INTERNALS
/* #define DEBUG_REASSEMBLING */

 /*******************************************************
 * It's only possible to use this plugin for dissection of hexdumps (user-link-layer),
 * but only when the dissector isn't registered as heuristic dissector.
 * See how to use this:
 * http://wiki.wireshark.org/HowToDissectAnything
 * https://www.wireshark.org/docs/man-pages/text2pcap.html
 */
//#define DONT_ADD_AS_HEURISTIC_DISSECTOR

#define PROTO_TAG_S7COMM_PLUS                   "S7COMM-PLUS"

/* Min. telegram length for heuristic check */
#define S7COMMP_MIN_TELEGRAM_LENGTH             4

#define S7COMMP_HEADER_LEN                      4
#define S7COMMP_TRAILER_LEN                     4

/* Protocol identifier */
#define S7COMM_PLUS_PROT_ID                     0x72

/* Max number of array values displays on Item-Value tree. */
#define S7COMMP_ITEMVAL_ARR_MAX_DISPLAY         10

/* String length used for variant value decoding */
#define S7COMMP_ITEMVAL_STR_VAL_MAX             128         /* length for a single value */
#define S7COMMP_ITEMVAL_STR_ARRVAL_MAX          512         /* length for array values */

/* Wireshark ID of the S7COMM_PLUS protocol */
static int proto_s7commp = -1;

/* Forward declaration */
static gboolean dissect_s7commp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

/**************************************************************************
 * Protocol Version/type
 */
#define S7COMMP_PROTOCOLVERSION_1               0x01
#define S7COMMP_PROTOCOLVERSION_2               0x02
#define S7COMMP_PROTOCOLVERSION_3               0x03
#define S7COMMP_PROTOCOLVERSION_254             0xfe
#define S7COMMP_PROTOCOLVERSION_255             0xff

static const value_string protocolversion_names[] = {
    { S7COMMP_PROTOCOLVERSION_1,                "V1" },
    { S7COMMP_PROTOCOLVERSION_2,                "V2" },
    { S7COMMP_PROTOCOLVERSION_3,                "V3" },
    { S7COMMP_PROTOCOLVERSION_254,              "Ext. Keep Alive" },    /* Extended Keep Alive? */
    { S7COMMP_PROTOCOLVERSION_255,              "Keep Alive" },
    { 0,                                        NULL }
};

/**************************************************************************
 * Opcodes in data part
 */
#define S7COMMP_OPCODE_REQ                      0x31
#define S7COMMP_OPCODE_RES                      0x32
#define S7COMMP_OPCODE_NOTIFICATION             0x33
#define S7COMMP_OPCODE_RES2                     0x02    /* V13 HMI bei zyklischen Daten, dann ist in dem Request Typ2=0x74 anstatt 0x34 */

static const value_string opcode_names[] = {
    { S7COMMP_OPCODE_REQ,                       "Request" },
    { S7COMMP_OPCODE_RES,                       "Response" },
    { S7COMMP_OPCODE_NOTIFICATION,              "Notification" },
    { S7COMMP_OPCODE_RES2,                      "Response2" },
    { 0,                                        NULL }
};

static const value_string opcode_names_short[] = {
    { S7COMMP_OPCODE_REQ,                       "Req" },
    { S7COMMP_OPCODE_RES,                       "Res" },
    { S7COMMP_OPCODE_NOTIFICATION,              "Ntf" },
    { S7COMMP_OPCODE_RES2,                      "Rs2" },
    { 0,                                        NULL }
};
/**************************************************************************
 * Function codes in data part.
 */
#define S7COMMP_FUNCTIONCODE_ERROR              0x04b1
#define S7COMMP_FUNCTIONCODE_EXPLORE            0x04bb
#define S7COMMP_FUNCTIONCODE_CREATEOBJECT       0x04ca
#define S7COMMP_FUNCTIONCODE_DELETEOBJECT       0x04d4
#define S7COMMP_FUNCTIONCODE_SETVARIABLE        0x04f2
#define S7COMMP_FUNCTIONCODE_GETVARIABLE        0x04fc      /* only in old 1200 FW? */
#define S7COMMP_FUNCTIONCODE_ADDLINK            0x0506      /* not decoded yet */
#define S7COMMP_FUNCTIONCODE_REMOVELINK         0x051a      /* not decoded yet */
#define S7COMMP_FUNCTIONCODE_GETLINK            0x0524
#define S7COMMP_FUNCTIONCODE_SETMULTIVAR        0x0542
#define S7COMMP_FUNCTIONCODE_GETMULTIVAR        0x054c
#define S7COMMP_FUNCTIONCODE_BEGINSEQUENCE      0x0556
#define S7COMMP_FUNCTIONCODE_ENDSEQUENCE        0x0560
#define S7COMMP_FUNCTIONCODE_INVOKE             0x056b
#define S7COMMP_FUNCTIONCODE_SETVARSUBSTR       0x057c
#define S7COMMP_FUNCTIONCODE_GETVARSUBSTR       0x0586
#define S7COMMP_FUNCTIONCODE_GETVARIABLESADDR   0x0590      /* not decoded yet */
#define S7COMMP_FUNCTIONCODE_ABORT              0x059a      /* not decoded yet */

static const value_string data_functioncode_names[] = {
    { S7COMMP_FUNCTIONCODE_ERROR,               "Error" },
    { S7COMMP_FUNCTIONCODE_EXPLORE,             "Explore" },
    { S7COMMP_FUNCTIONCODE_CREATEOBJECT,        "CreateObject" },
    { S7COMMP_FUNCTIONCODE_DELETEOBJECT,        "DeleteObject" },
    { S7COMMP_FUNCTIONCODE_SETVARIABLE,         "SetVariable" },
    { S7COMMP_FUNCTIONCODE_GETVARIABLE,         "GetVariable" },
    { S7COMMP_FUNCTIONCODE_ADDLINK,             "AddLink" },
    { S7COMMP_FUNCTIONCODE_REMOVELINK,          "RemoveLink" },
    { S7COMMP_FUNCTIONCODE_GETLINK,             "GetLink" },
    { S7COMMP_FUNCTIONCODE_SETMULTIVAR,         "SetMultiVariables" },
    { S7COMMP_FUNCTIONCODE_GETMULTIVAR,         "GetMultiVariables" },
    { S7COMMP_FUNCTIONCODE_BEGINSEQUENCE,       "BeginSequence" },
    { S7COMMP_FUNCTIONCODE_ENDSEQUENCE,         "EndSequence" },
    { S7COMMP_FUNCTIONCODE_INVOKE,              "Invoke" },
    { S7COMMP_FUNCTIONCODE_SETVARSUBSTR,        "SetVarSubStreamed" },
    { S7COMMP_FUNCTIONCODE_GETVARSUBSTR,        "GetVarSubStreamed" },
    { S7COMMP_FUNCTIONCODE_GETVARIABLESADDR,    "GetVariablesAddress" },
    { S7COMMP_FUNCTIONCODE_ABORT,               "Abort" },
    { 0,                                        NULL }
};
/**************************************************************************
 * Data types
 */
#define S7COMMP_ITEM_DATATYPE_NULL              0x00
#define S7COMMP_ITEM_DATATYPE_BOOL              0x01        /* BOOL: fix 1 Byte */
#define S7COMMP_ITEM_DATATYPE_USINT             0x02        /* USINT, CHAR: fix 1 Byte */
#define S7COMMP_ITEM_DATATYPE_UINT              0x03        /* UINT, DATE: fix 2 Bytes */
#define S7COMMP_ITEM_DATATYPE_UDINT             0x04        /* UDint: varuint32 */
#define S7COMMP_ITEM_DATATYPE_ULINT             0x05        /* ULInt: varuint64 */
#define S7COMMP_ITEM_DATATYPE_SINT              0x06        /* SINT: fix 1 Bytes */
#define S7COMMP_ITEM_DATATYPE_INT               0x07        /* INT: fix 2 Bytes */
#define S7COMMP_ITEM_DATATYPE_DINT              0x08        /* DINT, TIME: varint32 */
#define S7COMMP_ITEM_DATATYPE_LINT              0x09        /* LInt: varint64 */
#define S7COMMP_ITEM_DATATYPE_BYTE              0x0a        /* BYTE: fix 1 Byte */
#define S7COMMP_ITEM_DATATYPE_WORD              0x0b        /* WORD: fix 2 Bytes */
#define S7COMMP_ITEM_DATATYPE_DWORD             0x0c        /* DWORD: fix 4 Bytes */
#define S7COMMP_ITEM_DATATYPE_LWORD             0x0d        /* LWORD: fix 8 Bytes */
#define S7COMMP_ITEM_DATATYPE_REAL              0x0e        /* REAL: fix 4 Bytes */
#define S7COMMP_ITEM_DATATYPE_LREAL             0x0f        /* LREAL: fix 8 Bytes */
#define S7COMMP_ITEM_DATATYPE_TIMESTAMP         0x10        /* TIMESTAMP: e.g reading CPU from TIA portal, fix 8 Bytes */
#define S7COMMP_ITEM_DATATYPE_TIMESPAN          0x11        /* TIMESPAN: e.g. reading cycle time from TIA portal, varint64 */
#define S7COMMP_ITEM_DATATYPE_RID               0x12        /* RID: fix 4 Bytes */
#define S7COMMP_ITEM_DATATYPE_AID               0x13        /* AID: varuint32*/
#define S7COMMP_ITEM_DATATYPE_BLOB              0x14
#define S7COMMP_ITEM_DATATYPE_WSTRING           0x15        /* Wide string with length header, UTF8 encoded */
#define S7COMMP_ITEM_DATATYPE_VARIANT           0x16
#define S7COMMP_ITEM_DATATYPE_STRUCT            0x17
/* 0x18 ?? */
#define S7COMMP_ITEM_DATATYPE_S7STRING          0x19        /* S7 String with maximum length of 254 characters, used only in tag-description */

static const value_string item_datatype_names[] = {
    { S7COMMP_ITEM_DATATYPE_NULL,               "Null" },
    { S7COMMP_ITEM_DATATYPE_BOOL,               "Bool" },
    { S7COMMP_ITEM_DATATYPE_USINT,              "USInt" },
    { S7COMMP_ITEM_DATATYPE_UINT,               "UInt" },
    { S7COMMP_ITEM_DATATYPE_UDINT,              "UDInt" },
    { S7COMMP_ITEM_DATATYPE_ULINT,              "ULInt" },
    { S7COMMP_ITEM_DATATYPE_SINT,               "SInt" },
    { S7COMMP_ITEM_DATATYPE_INT,                "Int" },
    { S7COMMP_ITEM_DATATYPE_DINT,               "DInt" },
    { S7COMMP_ITEM_DATATYPE_LINT,               "LInt" },
    { S7COMMP_ITEM_DATATYPE_BYTE,               "Byte" },
    { S7COMMP_ITEM_DATATYPE_WORD,               "Word" },
    { S7COMMP_ITEM_DATATYPE_DWORD,              "DWord" },
    { S7COMMP_ITEM_DATATYPE_LWORD,              "LWord" },
    { S7COMMP_ITEM_DATATYPE_REAL,               "Real" },
    { S7COMMP_ITEM_DATATYPE_LREAL,              "LReal" },
    { S7COMMP_ITEM_DATATYPE_TIMESTAMP,          "Timestamp" },
    { S7COMMP_ITEM_DATATYPE_TIMESPAN,           "Timespan" },
    { S7COMMP_ITEM_DATATYPE_RID,                "RID" },
    { S7COMMP_ITEM_DATATYPE_AID,                "AID" },
    { S7COMMP_ITEM_DATATYPE_BLOB,               "Blob" },
    { S7COMMP_ITEM_DATATYPE_WSTRING,            "WString" },
    { S7COMMP_ITEM_DATATYPE_VARIANT,            "Variant" },
    { S7COMMP_ITEM_DATATYPE_STRUCT,             "Struct" },
    { S7COMMP_ITEM_DATATYPE_S7STRING,           "S7String" },
    { 0,                                        NULL }
};

/* Datatype flags */
#define S7COMMP_DATATYPE_FLAG_ARRAY             0x10
#define S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY     0x20
#define S7COMMP_DATATYPE_FLAG_SPARSEARRAY       0x40

/**************************************************************************
 * Element-IDs
 */
#define S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT   0xa1
#define S7COMMP_ITEMVAL_ELEMENTID_TERMOBJECT    0xa2
#define S7COMMP_ITEMVAL_ELEMENTID_ATTRIBUTE     0xa3
#define S7COMMP_ITEMVAL_ELEMENTID_RELATION      0xa4
#define S7COMMP_ITEMVAL_ELEMENTID_STARTTAGDESC  0xa7
#define S7COMMP_ITEMVAL_ELEMENTID_TERMTAGDESC   0xa8
#define S7COMMP_ITEMVAL_ELEMENTID_VARTYPELIST   0xab
#define S7COMMP_ITEMVAL_ELEMENTID_VARNAMELIST   0xac

static const value_string itemval_elementid_names[] = {
    { S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT,    "Start of Object" },
    { S7COMMP_ITEMVAL_ELEMENTID_TERMOBJECT,     "Terminating Object" },
    { S7COMMP_ITEMVAL_ELEMENTID_ATTRIBUTE,      "Attribute" },
    { S7COMMP_ITEMVAL_ELEMENTID_RELATION,       "Relation" },
    { S7COMMP_ITEMVAL_ELEMENTID_STARTTAGDESC,   "Start of Tag-Description" },
    { S7COMMP_ITEMVAL_ELEMENTID_TERMTAGDESC,    "Terminating Tag-Description" },
    { S7COMMP_ITEMVAL_ELEMENTID_VARTYPELIST,    "VartypeList" },
    { S7COMMP_ITEMVAL_ELEMENTID_VARNAMELIST,    "VarnameList" },
    { 0,                                        NULL }
};

/**************************************************************************
 * There are IDs which values can be read or be written to.
 * This is some kind of operating system data/function for the plc.
 * The IDs seem to be unique for all telegrams in which they occur.
 * Add the datatype for this value in parentheses.
 */
 #ifdef USE_INTERNALS
    #include "internals/packet-s7comm_plus-aid-names.h"
#else
static const value_string id_number_names[] = {
    { 0,                                        "None" },
    { 233,                                      "Subscription name (String)" },
    { 537,                                      "Object OMS Type-Info-Container" },
    { 1048,                                     "Cyclic variables update set of addresses (UDInt, Addressarray)" },
    { 1049,                                     "Cyclic variables update rate (UDInt, in milliseconds)" },
    { 1051,                                     "Unsubscribe" },
    { 1053,                                     "Cyclic variables number of automatic sent telegrams, -1 means unlimited (Int)" },

    { 1256,                                     "Object Qualifier" },
    { 1257,                                     "Parent RID" },
    { 1258,                                     "Composition AID" },
    { 1259,                                     "Key Qualifier" },

    { 2421,                                     "Set CPU clock" },
    { 2449,                                     "Ident ES" },
    { 2450,                                     "Designators" },
    { 2451,                                     "Working Memory Size" },
    { 2453,                                     "Last modified" },
    { 2454,                                     "Load Memory Size" },

    { 2521,                                     "Block Number" },
    { 2522,                                     "Auto Numbering" },
    { 2523,                                     "Block Language" },
    { 2524,                                     "Knowhow Protected" },
    { 2527,                                     "Unlinked" },
    { 2529,                                     "Runtime Modified" },
    { 2532,                                     "CRC" },
    { 2533,                                     "Body Description" },
    { 2537,                                     "Optimize Info" },

    { 2543,                                     "Interface Modified" },
    { 2544,                                     "Interface Description" },
    { 2545,                                     "Compiler Swiches" },
    { 2546,                                     "Line Comments" },
    { 2580,                                     "Code block" },
    { 2581,                                     "Parameter modified" },
    { 2582,                                     "External Ref Data" },
    { 2583,                                     "Internal Ref Data" },
    { 2584,                                     "Network Comment" },
    { 2585,                                     "Network Title" },
    { 2586,                                     "Callee List" },
    { 2587,                                     "Interface Signature" },
    { 2588,                                     "Display Info" },
    { 2589,                                     "Debug Info" },
    { 2590,                                     "Local Error Handling" },
    { 2591,                                     "Long Constants" },
    { 2607,                                     "Start Info Type" },

    { 3151,                                     "Binding" },
    { 3448,                                     "Knowhow Protection Mode" },
    { 3449,                                     "Knowhow Protection Password" },
    { 3619,                                     "TO Block Set Number" },
    { 3634,                                     "Change Counter Copy" },

    { 4287,                                     "Title" },
    { 4288,                                     "Comment" },
    { 4294,                                     "Instance DB" },
    { 4560,                                     "PIP" },
    { 4578,                                     "Type Info" },
    { 4615,                                     "Latest Runtime" },
    { 4616,                                     "Min Runtime" },
    { 4617,                                     "Max Runtime" },
    { 4618,                                     "Call Frequency" },
    { 4619,                                     "Runtime Ratio" },

    { 0,                                        NULL }
};
#endif
static value_string_ext id_number_names_ext = VALUE_STRING_EXT_INIT(id_number_names);

/* Error codes */
#ifdef USE_INTERNALS
    #include "internals/packet-s7comm_plus-errorcodes.h"
#else
static const val64_string errorcode_names[] = {
    { 0,                                        "OK" },
    { 17,                                       "Message Session Pre-Legitimated" },
    { 19,                                       "Warning Service Executed With Partial Error" },
    { 22,                                       "Service Session Delegitimated" },
    { -12,                                      "Object not found" },
    { -17,                                      "Invalid CRC" },
    { -134,                                     "Service Multi-ES Not Supported" },
    { -255,                                     "Invalid LID" },
    { 0,                                        NULL }
};
#endif

static const val64_string genericerrorcode_names[] = {
    { 0,        "Ok" },
    { 1,        "General" },
    { 2,        "ApplicationError" },
    { 3,        "AccessDenied" },
    { 4,        "CantActivate" },
    { 5,        "CardinalityOverflow" },
    { 6,        "CardinalityUnderflow" },
    { 7,        "ClassNotAllowed" },
    { 8,        "InvalidAttributeIdentifier" },
    { 9,        "InvalidDatatype" },
    { 10,       "InvalidObjectIdentifier" },
    { 11,       "InvalidPlacement" },
    { 12,       "InvalidQualifier" },
    { 13,       "InvalidRange" },
    { 14,       "InvalidSession" },
    { 15,       "NotLinked" },
    { 16,       "ServiceTimeout" },
    { 17,       "Disconnected" },
    { 18,       "FailedToDisconnect" },
    { 19,       "InvalidAddress" },
    { 20,       "ServiceNotAllowed" },
    { 21,       "ServiceNotConnected" },
    { 22,       "NotOwner" },
    { 23,       "TooManyRequests" },
    { 24,       "TooManySessions" },
    { 25,       "SessionDelegitimated" },
    { 26,       "UnknownService" },
    { 27,       "InvalidStorageFormat" },
    { 28,       "InvalidComFormat" },
    { 29,       "NotChangableInRun" },
    { 30,       "WrongNrOfArgumentsOfInvoke" },
    { 31,       "WrongArgumentFormatOfInvoke" },
    { 32,       "InvokeFailed" },
    { 33,       "ObjectCannotBeStoredTwoTimesInParallel" },
    { 34,       "ObjectIsLocked" },
    { 35,       "StoreInactive" },
    { 36,       "HierarchyOverflow" },
    { 37,       "ObjectOrAttributeAlreadyExist" },
    { 38,       "NotEnoughMemoryAvailable" },
    { 39,       "NoMemoryOnStorage" },
    { 40,       "NoStorageDetected" },
    { 41,       "InvalidTimestampInTypesafeBlob" },
    { 42,       "InvalidFileName" },
    { 43,       "InvalidArgumentValue" },
    { 44,       "StoreDirectoryAlreadyUsed" },
    { 45,       "GeneralStoreError" },
    { 46,       "InvalidObjectReference" },
    { 47,       "GeneralCreate" },
    { 48,       "GeneralAddObject" },
    { 49,       "GeneralDeleteObject" },
    { 50,       "GeneralGetVariable" },
    { 51,       "GeneralSetVariable" },
    { 52,       "GeneralGetVariableSubrange" },
    { 53,       "GeneralSetVariableSubrange" },
    { 54,       "GeneralGetMultiVariables" },
    { 55,       "GeneralSetMultiVariables" },
    { 56,       "GeneralAddLink" },
    { 57,       "GeneralRemoveLink" },
    { 58,       "InvalidID" },
    { 59,       "GeneralComError" },
    { 60,       "NotChangableInErrorState" },
    { 61,       "MultiESNotSupported" },
    { 62,       "ServiceAborted" },
    { 63,       "SourceFileNotExisting" },
    { 64,       "InvalidVersion" },
    { 65,       "CommFormatDiffersFromStoreFormat" },
    { 66,       "GeneralTransaction" },
    { 67,       "Distribution" },
    { 68,       "GeneralPathNotFound" },
    { 69,       "GeneralEndOfFile" },
    { 70,       "GeneralFSWriteProtected" },
    { 71,       "GeneralFSDiskFull" },
    { 72,       "GeneralFSInvalidPathName" },
    { 73,       "WSTRING_not_supported" },
    { 74,       "TransactionAborted" },
    { 75,       "StoreForceStore" },
    { 76,       "GeneralIntegrity" },
    { 77,       "MultiESConflict" },
    { 78,       "TemporarilyOutOfResources" },
    { 79,       "MultiESLimitExceeded" },
    { 80,       "MultiESIncompatibleOtherESVersion" },
    { 81,       "ConcurrentTransactionRunning" },
    { 82,       "SslError" },
    { 0,        NULL }
};
/*static value_string_ext genericerrorcode_names_ext = VALUE_STRING_EXT_INIT(genericerrorcode_names);*/

/* Item access area */
/* Bei der aktuellen Struktur der Adresse ist nur noch ein Bereich bekannt */
#define S7COMMP_VAR_ITEM_AREA1_DB               0x8a0e              /* Reading DB, 2 Bytes DB-Number following */

static const value_string var_item_area1_names[] = {
    { S7COMMP_VAR_ITEM_AREA1_DB,                "DB" },
    { 0,                                        NULL }
};

/* Explore areas */
#define S7COMMP_EXPLORE_CLASS_ASALARMS          0x8a
#define S7COMMP_EXPLORE_CLASS_IQMCT             0x90
#define S7COMMP_EXPLORE_CLASS_UDT               0x91
#define S7COMMP_EXPLORE_CLASS_DB                0x92
#define S7COMMP_EXPLORE_CLASS_FB                0x93
#define S7COMMP_EXPLORE_CLASS_FC                0x94
#define S7COMMP_EXPLORE_CLASS_OB                0x95
#define S7COMMP_EXPLORE_CLASS_FBT               0x96
#define S7COMMP_EXPLORE_CLASS_LIB               0x02
#define S7COMMP_EXPLORE_CLASS_IQMCT_INPUT       0x01
#define S7COMMP_EXPLORE_CLASS_IQMCT_OUTPUT      0x02
#define S7COMMP_EXPLORE_CLASS_IQMCT_BITMEM      0x03
#define S7COMMP_EXPLORE_CLASS_IQMCT_04          0x04
#define S7COMMP_EXPLORE_CLASS_IQMCT_TIMER       0x05
#define S7COMMP_EXPLORE_CLASS_IQMCT_COUNTER     0x06
static const value_string explore_class_iqmct_names[] = {
    { S7COMMP_EXPLORE_CLASS_IQMCT_INPUT,        "IArea" },
    { S7COMMP_EXPLORE_CLASS_IQMCT_OUTPUT,       "QArea" },
    { S7COMMP_EXPLORE_CLASS_IQMCT_BITMEM,       "MArea" },
    { S7COMMP_EXPLORE_CLASS_IQMCT_04,           "UnknownArea04" },
    { S7COMMP_EXPLORE_CLASS_IQMCT_TIMER,        "S7Timers" },
    { S7COMMP_EXPLORE_CLASS_IQMCT_COUNTER,      "S7Counters" },
    { 0,                                        NULL }
};

#define S7COMMP_EXPLORE_CLASS_LIB_STYPE         0x00
#define S7COMMP_EXPLORE_CLASS_LIB_STYPEARR      0x01
#define S7COMMP_EXPLORE_CLASS_LIB_SFC           0x02
#define S7COMMP_EXPLORE_CLASS_LIB_SFB           0x03
#define S7COMMP_EXPLORE_CLASS_LIB_FBT           0x04
#define S7COMMP_EXPLORE_CLASS_LIB_FB            0x05
#define S7COMMP_EXPLORE_CLASS_LIB_FC            0x06
#define S7COMMP_EXPLORE_CLASS_LIB_FCT           0x07
#define S7COMMP_EXPLORE_CLASS_LIB_UDT           0x08
#define S7COMMP_EXPLORE_CLASS_LIB_STRUCT        0x09
static const value_string explore_class_lib_names[] = {
    { S7COMMP_EXPLORE_CLASS_LIB_STYPE,          "SimpleType" },
    { S7COMMP_EXPLORE_CLASS_LIB_STYPEARR,       "SimpleTypeArray" },
    { S7COMMP_EXPLORE_CLASS_LIB_SFC,            "SFC" },
    { S7COMMP_EXPLORE_CLASS_LIB_SFB,            "SFB" },
    { S7COMMP_EXPLORE_CLASS_LIB_FBT,            "FBT" },
    { S7COMMP_EXPLORE_CLASS_LIB_FB,             "FB" },
    { S7COMMP_EXPLORE_CLASS_LIB_FC,             "FC" },
    { S7COMMP_EXPLORE_CLASS_LIB_FCT,            "FCT" },
    { S7COMMP_EXPLORE_CLASS_LIB_UDT,            "UDT" },
    { S7COMMP_EXPLORE_CLASS_LIB_STRUCT,         "STRUCT" },
    { 0,                                        NULL }
};

static const value_string no_yes_names[] = {
    { 0,                                        "No" },
    { 1,                                        "Yes" },
    { 0,                                        NULL }
};

static const char mon_names[][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

/* Class Id flags. 32 Bits, just as a starting point for analysis */
static gint s7commp_object_classflags_bit00 = -1;
static gint s7commp_object_classflags_bit01 = -1;
static gint s7commp_object_classflags_bit02 = -1;
static gint s7commp_object_classflags_bit03 = -1;
static gint s7commp_object_classflags_bit04 = -1;
static gint s7commp_object_classflags_bit05 = -1;
static gint s7commp_object_classflags_bit06 = -1;
static gint s7commp_object_classflags_bit07 = -1;
static gint s7commp_object_classflags_bit08 = -1;
static gint s7commp_object_classflags_bit09 = -1;
static gint s7commp_object_classflags_bit10 = -1;
static gint s7commp_object_classflags_bit11 = -1;
static gint s7commp_object_classflags_bit12 = -1;
static gint s7commp_object_classflags_bit13 = -1;
static gint s7commp_object_classflags_bit14 = -1;
static gint s7commp_object_classflags_bit15 = -1;
static gint s7commp_object_classflags_bit16 = -1;
static gint s7commp_object_classflags_bit17 = -1;
static gint s7commp_object_classflags_bit18 = -1;
static gint s7commp_object_classflags_bit19 = -1;
static gint s7commp_object_classflags_bit20 = -1;
static gint s7commp_object_classflags_bit21 = -1;
static gint s7commp_object_classflags_bit22 = -1;
static gint s7commp_object_classflags_bit23 = -1;
static gint s7commp_object_classflags_bit24 = -1;
static gint s7commp_object_classflags_bit25 = -1;
static gint s7commp_object_classflags_bit26 = -1;
static gint s7commp_object_classflags_bit27 = -1;
static gint s7commp_object_classflags_bit28 = -1;
static gint s7commp_object_classflags_bit29 = -1;
static gint s7commp_object_classflags_bit30 = -1;
static gint s7commp_object_classflags_bit31 = -1;

static gint ett_s7commp_object_classflags = -1;
static const int *s7commp_object_classflags_fields[] = {
    &s7commp_object_classflags_bit00,
    &s7commp_object_classflags_bit01,
    &s7commp_object_classflags_bit02,
    &s7commp_object_classflags_bit03,
    &s7commp_object_classflags_bit04,
    &s7commp_object_classflags_bit05,
    &s7commp_object_classflags_bit06,
    &s7commp_object_classflags_bit07,
    &s7commp_object_classflags_bit08,
    &s7commp_object_classflags_bit09,
    &s7commp_object_classflags_bit10,
    &s7commp_object_classflags_bit11,
    &s7commp_object_classflags_bit12,
    &s7commp_object_classflags_bit13,
    &s7commp_object_classflags_bit14,
    &s7commp_object_classflags_bit15,
    &s7commp_object_classflags_bit16,
    &s7commp_object_classflags_bit17,
    &s7commp_object_classflags_bit18,
    &s7commp_object_classflags_bit19,
    &s7commp_object_classflags_bit20,
    &s7commp_object_classflags_bit21,
    &s7commp_object_classflags_bit22,
    &s7commp_object_classflags_bit23,
    &s7commp_object_classflags_bit24,
    &s7commp_object_classflags_bit25,
    &s7commp_object_classflags_bit26,
    &s7commp_object_classflags_bit27,
    &s7commp_object_classflags_bit28,
    &s7commp_object_classflags_bit29,
    &s7commp_object_classflags_bit30,
    &s7commp_object_classflags_bit31,
    NULL
};

/* Attribute flags in tag description (old S7-1200 FW2) */
#define S7COMMP_TAGDESCR_ATTRIBUTE_HOSTRELEVANT         0x08000000
#define S7COMMP_TAGDESCR_ATTRIBUTE_PLAINMEMBERRETAIN    0x02000000
#define S7COMMP_TAGDESCR_ATTRIBUTE_PLAINMEMBERCLASSIC   0x01000000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMIVISIBLE           0x00800000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMIREADONLY          0x00400000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMICACHED            0x00200000
#define S7COMMP_TAGDESCR_ATTRIBUTE_HMIACCESSIBLE        0x00100000
#define S7COMMP_TAGDESCR_ATTRIBUTE_ISQUALIFIER          0x00040000
#define S7COMMP_TAGDESCR_ATTRIBUTE_NORMALACCESS         0x00008000
#define S7COMMP_TAGDESCR_ATTRIBUTE_NEEDSLEGITIMIZATION  0x00004000
#define S7COMMP_TAGDESCR_ATTRIBUTE_CHANGEBLEINRUN       0x00002000
#define S7COMMP_TAGDESCR_ATTRIBUTE_SERVERONLY           0x00000800
#define S7COMMP_TAGDESCR_ATTRIBUTE_CLIENTREADRONLY      0x00000400
#define S7COMMP_TAGDESCR_ATTRIBUTE_SEPLOADMEMFA         0x00000200
#define S7COMMP_TAGDESCR_ATTRIBUTE_ASEVALREQ            0x00000100
#define S7COMMP_TAGDESCR_ATTRIBUTE_BL                   0x00000040
#define S7COMMP_TAGDESCR_ATTRIBUTE_PERSISTENT           0x00000020
#define S7COMMP_TAGDESCR_ATTRIBUTE_CORE                 0x00000010
#define S7COMMP_TAGDESCR_ATTRIBUTE_ISOUT                0x00000008
#define S7COMMP_TAGDESCR_ATTRIBUTE_ISIN                 0x00000004
#define S7COMMP_TAGDESCR_ATTRIBUTE_APPWRITEABLE         0x00000002
#define S7COMMP_TAGDESCR_ATTRIBUTE_APPREADABLE          0x00000001

/* flags in tag description for 1500 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_OFFSETINFOTYPE      0xf000      /* Bits 13..16 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_HMIVISIBLE          0x0800      /* Bit 12 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_BIT11               0x0400      /* Bit 11 HMIREADONLY */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_HMIACCESSIBLE       0x0200      /* Bit 10 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_BIT09               0x0100      /* Bit 09 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_OPTIMIZEDACCESS     0x0080      /* Bit 08 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_SECTION             0x0070      /* Bits 05..07 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_BIT04               0x0008      /* Bit 04 */
#define S7COMMP_TAGDESCR_ATTRIBUTE2_BITOFFSET           0x0007      /* Bits 01..03 */

/* Offsetinfo type for tag description (S7-1500) */
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STD             1
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRING          2
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAY1DIM       3
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAYMDIM       4
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT          5
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT1DIM      6
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCTMDIM      7
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STD                        8
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRING                     9
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAY1DIM                  10
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAYMDIM                  11
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT                     12
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT1DIM                 13
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTMDIM                 14
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE2_PROGRAMALARM               15

static const value_string tagdescr_offsetinfotype2_names[] = {
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STD,              "LibStructElem_Std" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRING,           "LibStructElem_String" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAY1DIM,        "LibStructElem_Array1Dim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAYMDIM,        "LibStructElem_ArrayMDim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT,           "LibStructElem_Struct" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT1DIM,       "LibStructElem_StructArray1Dim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCTMDIM,       "LibStructElem_StructArrayMDim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STD,                         "Std" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRING,                      "String" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAY1DIM,                   "Array1Dim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAYMDIM,                   "ArrayMDim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT,                      "Struct" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT1DIM,                  "StructArray1Dim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTMDIM,                  "StructArrayMDim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE2_PROGRAMALARM,                "ProgramAlarm" },
    { 0,                                                            NULL }
};

/* Offsetinfo type for tag description (old S7-1200 FW2) */
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_LIBELEMENT                  0x00
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_BOOLINUDT                   0x01
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_STRUCTELEM_ARRAY1DIM        0x02
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_STRUCTELEM_ARRAYMDIM        0x03
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_PLAINSTATIC                 0x04
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_BOOL                        0x05
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_ARRAY1DIM                   0x06
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_ARRAYMDIM                   0x07
#define S7COMMP_TAGDESCR_OFFSETINFOTYPE_SFBINSTANCE                 0x08

static const value_string tagdescr_offsetinfotype_names[] = {
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_LIBELEMENT,                   "LibraryElement" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_BOOLINUDT,                    "BoolInUdt" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_STRUCTELEM_ARRAY1DIM,         "StructElem_Array1Dim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_STRUCTELEM_ARRAYMDIM,         "StructElem_ArrayMDim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_PLAINSTATIC,                  "Plain/Static" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_BOOL,                         "Bool" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_ARRAY1DIM,                    "Array1Dim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_ARRAYMDIM,                    "ArrayMDim" },
    { S7COMMP_TAGDESCR_OFFSETINFOTYPE_SFBINSTANCE,                  "SFB_Instance" },
    { 0,                                                            NULL }
};

#define S7COMMP_TAGDESCR_BITOFFSETINFO_RETAIN                       0x80
#define S7COMMP_TAGDESCR_BITOFFSETINFO_NONOPTBITOFFSET              0x70
#define S7COMMP_TAGDESCR_BITOFFSETINFO_CLASSIC                      0x08
#define S7COMMP_TAGDESCR_BITOFFSETINFO_OPTBITOFFSET                 0x07

/* Section for tag description (S7-1500) */
#define S7COMMP_TAGDESCR_SECTION_NONE              0
#define S7COMMP_TAGDESCR_SECTION_INPUT             1
#define S7COMMP_TAGDESCR_SECTION_OUTPUT            2
#define S7COMMP_TAGDESCR_SECTION_INOUT             3
#define S7COMMP_TAGDESCR_SECTION_STATIC            4
#define S7COMMP_TAGDESCR_SECTION_DYNAMIC           5
#define S7COMMP_TAGDESCR_SECTION_RETVAL            6
#define S7COMMP_TAGDESCR_SECTION_OPERAND           7

static const value_string tagdescr_section_names[] = {
    { S7COMMP_TAGDESCR_SECTION_NONE,             "Undefined" },
    { S7COMMP_TAGDESCR_SECTION_INPUT,           "Input" },
    { S7COMMP_TAGDESCR_SECTION_OUTPUT,          "Output" },
    { S7COMMP_TAGDESCR_SECTION_INOUT,           "InOut" },
    { S7COMMP_TAGDESCR_SECTION_STATIC,          "Static" },
    { S7COMMP_TAGDESCR_SECTION_DYNAMIC,         "Dynamic" },
    { S7COMMP_TAGDESCR_SECTION_RETVAL,          "Retval" },
    { S7COMMP_TAGDESCR_SECTION_OPERAND,         "Operand" },
    { 0,                                        NULL }
};

#define S7COMMP_SOFTDATATYPE_VOID               0
#define S7COMMP_SOFTDATATYPE_BOOL               1
#define S7COMMP_SOFTDATATYPE_BYTE               2
#define S7COMMP_SOFTDATATYPE_CHAR               3
#define S7COMMP_SOFTDATATYPE_WORD               4
#define S7COMMP_SOFTDATATYPE_INT                5
#define S7COMMP_SOFTDATATYPE_DWORD              6
#define S7COMMP_SOFTDATATYPE_DINT               7
#define S7COMMP_SOFTDATATYPE_REAL               8
#define S7COMMP_SOFTDATATYPE_DATE               9
#define S7COMMP_SOFTDATATYPE_TIMEOFDAY          10
#define S7COMMP_SOFTDATATYPE_TIME               11
#define S7COMMP_SOFTDATATYPE_S5TIME             12
#define S7COMMP_SOFTDATATYPE_S5COUNT            13
#define S7COMMP_SOFTDATATYPE_DATEANDTIME        14
#define S7COMMP_SOFTDATATYPE_INTERNETTIME       15
#define S7COMMP_SOFTDATATYPE_ARRAY              16
#define S7COMMP_SOFTDATATYPE_STRUCT             17
#define S7COMMP_SOFTDATATYPE_ENDSTRUCT          18
#define S7COMMP_SOFTDATATYPE_STRING             19
#define S7COMMP_SOFTDATATYPE_POINTER            20
#define S7COMMP_SOFTDATATYPE_MULTIFB            21
#define S7COMMP_SOFTDATATYPE_ANY                22
#define S7COMMP_SOFTDATATYPE_BLOCKFB            23
#define S7COMMP_SOFTDATATYPE_BLOCKFC            24
#define S7COMMP_SOFTDATATYPE_BLOCKDB            25
#define S7COMMP_SOFTDATATYPE_BLOCKSDB           26
#define S7COMMP_SOFTDATATYPE_MULTISFB           27
#define S7COMMP_SOFTDATATYPE_COUNTER            28
#define S7COMMP_SOFTDATATYPE_TIMER              29
#define S7COMMP_SOFTDATATYPE_IECCOUNTER         30
#define S7COMMP_SOFTDATATYPE_IECTIMER           31
#define S7COMMP_SOFTDATATYPE_BLOCKSFB           32
#define S7COMMP_SOFTDATATYPE_BLOCKSFC           33
#define S7COMMP_SOFTDATATYPE_BLOCKCB            34
#define S7COMMP_SOFTDATATYPE_BLOCKSCB           35
#define S7COMMP_SOFTDATATYPE_BLOCKOB            36
#define S7COMMP_SOFTDATATYPE_BLOCKUDT           37
#define S7COMMP_SOFTDATATYPE_OFFSET             38
#define S7COMMP_SOFTDATATYPE_BLOCKSDT           39
#define S7COMMP_SOFTDATATYPE_BBOOL              40
#define S7COMMP_SOFTDATATYPE_BLOCKEXT           41
#define S7COMMP_SOFTDATATYPE_LREAL              48
#define S7COMMP_SOFTDATATYPE_ULINT              49
#define S7COMMP_SOFTDATATYPE_LINT               50
#define S7COMMP_SOFTDATATYPE_LWORD              51
#define S7COMMP_SOFTDATATYPE_USINT              52
#define S7COMMP_SOFTDATATYPE_UINT               53
#define S7COMMP_SOFTDATATYPE_UDINT              54
#define S7COMMP_SOFTDATATYPE_SINT               55
#define S7COMMP_SOFTDATATYPE_BCD8               56
#define S7COMMP_SOFTDATATYPE_BCD16              57
#define S7COMMP_SOFTDATATYPE_BCD32              58
#define S7COMMP_SOFTDATATYPE_BCD64              59
#define S7COMMP_SOFTDATATYPE_AREF               60
#define S7COMMP_SOFTDATATYPE_WCHAR              61
#define S7COMMP_SOFTDATATYPE_WSTRING            62
#define S7COMMP_SOFTDATATYPE_VARIANT            63
#define S7COMMP_SOFTDATATYPE_LTIME              64
#define S7COMMP_SOFTDATATYPE_LTOD               65
#define S7COMMP_SOFTDATATYPE_LDT                66
#define S7COMMP_SOFTDATATYPE_DTL                67
#define S7COMMP_SOFTDATATYPE_IECLTIMER          68
#define S7COMMP_SOFTDATATYPE_SCOUNTER           69
#define S7COMMP_SOFTDATATYPE_DCOUNTER           70
#define S7COMMP_SOFTDATATYPE_LCOUNTER           71
#define S7COMMP_SOFTDATATYPE_UCOUNTER           72
#define S7COMMP_SOFTDATATYPE_USCOUNTER          73
#define S7COMMP_SOFTDATATYPE_UDCOUNTER          74
#define S7COMMP_SOFTDATATYPE_ULCOUNTER          75
#define S7COMMP_SOFTDATATYPE_REMOTE             96
#define S7COMMP_SOFTDATATYPE_ERRORSTRUCT        97
#define S7COMMP_SOFTDATATYPE_NREF               98
#define S7COMMP_SOFTDATATYPE_VREF               99
#define S7COMMP_SOFTDATATYPE_FBTREF             100
#define S7COMMP_SOFTDATATYPE_CREF               101
#define S7COMMP_SOFTDATATYPE_VAREF              102
#define S7COMMP_SOFTDATATYPE_AOMIDENT           128
#define S7COMMP_SOFTDATATYPE_EVENTANY           129
#define S7COMMP_SOFTDATATYPE_EVENTATT           130
#define S7COMMP_SOFTDATATYPE_EVENTHWINT         131
#define S7COMMP_SOFTDATATYPE_FOLDER             132
#define S7COMMP_SOFTDATATYPE_AOMAID             133
#define S7COMMP_SOFTDATATYPE_AOMLINK            134
#define S7COMMP_SOFTDATATYPE_HWANY              144
#define S7COMMP_SOFTDATATYPE_HWIOSYSTEM         145
#define S7COMMP_SOFTDATATYPE_HWDPMASTER         146
#define S7COMMP_SOFTDATATYPE_HWDEVICE           147
#define S7COMMP_SOFTDATATYPE_HWDPSLAVE          148
#define S7COMMP_SOFTDATATYPE_HWIO               149
#define S7COMMP_SOFTDATATYPE_HWMODULE           150
#define S7COMMP_SOFTDATATYPE_HWSUBMODULE        151
#define S7COMMP_SOFTDATATYPE_HWHSC              152
#define S7COMMP_SOFTDATATYPE_HWPWM              153
#define S7COMMP_SOFTDATATYPE_HWPTO              154
#define S7COMMP_SOFTDATATYPE_HWINTERFACE        155
#define S7COMMP_SOFTDATATYPE_OBANY              160
#define S7COMMP_SOFTDATATYPE_OBDELAY            161
#define S7COMMP_SOFTDATATYPE_OBTOD              162
#define S7COMMP_SOFTDATATYPE_OBCYCLIC           163
#define S7COMMP_SOFTDATATYPE_OBATT              164
#define S7COMMP_SOFTDATATYPE_CONNANY            168
#define S7COMMP_SOFTDATATYPE_CONNPRG            169
#define S7COMMP_SOFTDATATYPE_CONNOUC            170
#define S7COMMP_SOFTDATATYPE_HWNR               172
#define S7COMMP_SOFTDATATYPE_PORT               173
#define S7COMMP_SOFTDATATYPE_RTM                174
#define S7COMMP_SOFTDATATYPE_CALARM             176
#define S7COMMP_SOFTDATATYPE_CALARMS            177
#define S7COMMP_SOFTDATATYPE_CALARM8            178
#define S7COMMP_SOFTDATATYPE_CALARM8P           179
#define S7COMMP_SOFTDATATYPE_CALARMT            180
#define S7COMMP_SOFTDATATYPE_CARSEND            181
#define S7COMMP_SOFTDATATYPE_CNOTIFY            182
#define S7COMMP_SOFTDATATYPE_CNOTIFY8P          183
#define S7COMMP_SOFTDATATYPE_OBPCYCLE           192
#define S7COMMP_SOFTDATATYPE_OBHWINT            193
#define S7COMMP_SOFTDATATYPE_OBCOMM             194
#define S7COMMP_SOFTDATATYPE_OBDIAG             195
#define S7COMMP_SOFTDATATYPE_OBTIMEERROR        196
#define S7COMMP_SOFTDATATYPE_OBSTARTUP          197
#define S7COMMP_SOFTDATATYPE_PARA               253
#define S7COMMP_SOFTDATATYPE_LABEL              254
#define S7COMMP_SOFTDATATYPE_UDEFINED           255
#define S7COMMP_SOFTDATATYPE_NOTCHOSEN          256

static const value_string tagdescr_softdatatype_names[] = {
    { S7COMMP_SOFTDATATYPE_VOID,                "Void" },
    { S7COMMP_SOFTDATATYPE_BOOL,                "Bool" },
    { S7COMMP_SOFTDATATYPE_BYTE,                "Byte" },
    { S7COMMP_SOFTDATATYPE_CHAR,                "Char" },
    { S7COMMP_SOFTDATATYPE_WORD,                "Word" },
    { S7COMMP_SOFTDATATYPE_INT,                 "Int" },
    { S7COMMP_SOFTDATATYPE_DWORD,               "DWord" },
    { S7COMMP_SOFTDATATYPE_DINT,                "DInt" },
    { S7COMMP_SOFTDATATYPE_REAL,                "Real" },
    { S7COMMP_SOFTDATATYPE_DATE,                "Date" },
    { S7COMMP_SOFTDATATYPE_TIMEOFDAY,           "Time_Of_Day" },
    { S7COMMP_SOFTDATATYPE_TIME,                "Time" },
    { S7COMMP_SOFTDATATYPE_S5TIME,              "S5Time" },
    { S7COMMP_SOFTDATATYPE_S5COUNT,             "S5Count" },
    { S7COMMP_SOFTDATATYPE_DATEANDTIME,         "Date_And_Time" },
    { S7COMMP_SOFTDATATYPE_INTERNETTIME,        "Internet_Time" },
    { S7COMMP_SOFTDATATYPE_ARRAY,               "Array" },
    { S7COMMP_SOFTDATATYPE_STRUCT,              "Struct" },
    { S7COMMP_SOFTDATATYPE_ENDSTRUCT,           "Endstruct" },
    { S7COMMP_SOFTDATATYPE_STRING,              "String" },
    { S7COMMP_SOFTDATATYPE_POINTER,             "Pointer" },
    { S7COMMP_SOFTDATATYPE_MULTIFB,             "Multi_FB" },
    { S7COMMP_SOFTDATATYPE_ANY,                 "Any" },
    { S7COMMP_SOFTDATATYPE_BLOCKFB,             "Block_FB" },
    { S7COMMP_SOFTDATATYPE_BLOCKFC,             "Block_FC" },
    { S7COMMP_SOFTDATATYPE_BLOCKDB,             "Block_DB" },
    { S7COMMP_SOFTDATATYPE_BLOCKSDB,            "Block_SDB" },
    { S7COMMP_SOFTDATATYPE_MULTISFB,            "Multi_SFB" },
    { S7COMMP_SOFTDATATYPE_COUNTER,             "Counter" },
    { S7COMMP_SOFTDATATYPE_TIMER,               "Timer" },
    { S7COMMP_SOFTDATATYPE_IECCOUNTER,          "IEC_Counter" },
    { S7COMMP_SOFTDATATYPE_IECTIMER,            "IEC_Timer" },
    { S7COMMP_SOFTDATATYPE_BLOCKSFB,            "Block_SFB" },
    { S7COMMP_SOFTDATATYPE_BLOCKSFC,            "Block_SFC" },
    { S7COMMP_SOFTDATATYPE_BLOCKCB,             "Block_CB" },
    { S7COMMP_SOFTDATATYPE_BLOCKSCB,            "Block_SCB" },
    { S7COMMP_SOFTDATATYPE_BLOCKOB,             "Block_OB" },
    { S7COMMP_SOFTDATATYPE_BLOCKUDT,            "Block_UDT" },
    { S7COMMP_SOFTDATATYPE_OFFSET,              "Offset" },
    { S7COMMP_SOFTDATATYPE_BLOCKSDT,            "Block_SDT" },
    { S7COMMP_SOFTDATATYPE_BBOOL,               "BBOOL" },
    { S7COMMP_SOFTDATATYPE_BLOCKEXT,            "BLOCK_EXT" },
    { S7COMMP_SOFTDATATYPE_LREAL,               "LReal" },
    { S7COMMP_SOFTDATATYPE_ULINT,               "ULInt" },
    { S7COMMP_SOFTDATATYPE_LINT,                "LInt" },
    { S7COMMP_SOFTDATATYPE_LWORD,               "LWord" },
    { S7COMMP_SOFTDATATYPE_USINT,               "USInt" },
    { S7COMMP_SOFTDATATYPE_UINT,                "UInt" },
    { S7COMMP_SOFTDATATYPE_UDINT,               "UDInt" },
    { S7COMMP_SOFTDATATYPE_SINT,                "SInt" },
    { S7COMMP_SOFTDATATYPE_BCD8,                "Bcd8" },
    { S7COMMP_SOFTDATATYPE_BCD16,               "Bcd16" },
    { S7COMMP_SOFTDATATYPE_BCD32,               "Bcd32" },
    { S7COMMP_SOFTDATATYPE_BCD64,               "Bcd64" },
    { S7COMMP_SOFTDATATYPE_AREF,                "ARef" },
    { S7COMMP_SOFTDATATYPE_WCHAR,               "WChar" },
    { S7COMMP_SOFTDATATYPE_WSTRING,             "WString" },
    { S7COMMP_SOFTDATATYPE_VARIANT,             "Variant" },
    { S7COMMP_SOFTDATATYPE_LTIME,               "LTime" },
    { S7COMMP_SOFTDATATYPE_LTOD,                "LTOD" },
    { S7COMMP_SOFTDATATYPE_LDT,                 "LDT" },
    { S7COMMP_SOFTDATATYPE_DTL,                 "DTL" },
    { S7COMMP_SOFTDATATYPE_IECLTIMER,           "IEC_LTimer" },
    { S7COMMP_SOFTDATATYPE_SCOUNTER,            "SCounter" },
    { S7COMMP_SOFTDATATYPE_DCOUNTER,            "DCounter" },
    { S7COMMP_SOFTDATATYPE_LCOUNTER,            "LCounter" },
    { S7COMMP_SOFTDATATYPE_UCOUNTER,            "UCounter" },
    { S7COMMP_SOFTDATATYPE_USCOUNTER,           "USCounter" },
    { S7COMMP_SOFTDATATYPE_UDCOUNTER,           "UDCounter" },
    { S7COMMP_SOFTDATATYPE_ULCOUNTER,           "ULCounter" },
    { S7COMMP_SOFTDATATYPE_REMOTE,              "REMOTE" },
    { S7COMMP_SOFTDATATYPE_ERRORSTRUCT,         "Error_Struct" },
    { S7COMMP_SOFTDATATYPE_NREF,                "NREF" },
    { S7COMMP_SOFTDATATYPE_VREF,                "VREF" },
    { S7COMMP_SOFTDATATYPE_FBTREF,              "FBTREF" },
    { S7COMMP_SOFTDATATYPE_CREF,                "CREF" },
    { S7COMMP_SOFTDATATYPE_VAREF,               "VAREF" },
    { S7COMMP_SOFTDATATYPE_AOMIDENT,            "AOM_IDENT" },
    { S7COMMP_SOFTDATATYPE_EVENTANY,            "EVENT_ANY" },
    { S7COMMP_SOFTDATATYPE_EVENTATT,            "EVENT_ATT" },
    { S7COMMP_SOFTDATATYPE_EVENTHWINT,          "EVENT_HWINT" },
    { S7COMMP_SOFTDATATYPE_FOLDER,              "FOLDER" },
    { S7COMMP_SOFTDATATYPE_AOMAID,              "AOM_AID" },
    { S7COMMP_SOFTDATATYPE_AOMLINK,             "AOM_LINK" },
    { S7COMMP_SOFTDATATYPE_HWANY,               "HW_ANY" },
    { S7COMMP_SOFTDATATYPE_HWIOSYSTEM,          "HW_IOSYSTEM" },
    { S7COMMP_SOFTDATATYPE_HWDPMASTER,          "HW_DPMASTER" },
    { S7COMMP_SOFTDATATYPE_HWDEVICE,            "HW_DEVICE" },
    { S7COMMP_SOFTDATATYPE_HWDPSLAVE,           "HW_DPSLAVE" },
    { S7COMMP_SOFTDATATYPE_HWIO,                "HW_IO" },
    { S7COMMP_SOFTDATATYPE_HWMODULE,            "HW_MODULE" },
    { S7COMMP_SOFTDATATYPE_HWSUBMODULE,         "HW_SUBMODULE" },
    { S7COMMP_SOFTDATATYPE_HWHSC,               "HW_HSC" },
    { S7COMMP_SOFTDATATYPE_HWPWM,               "HW_PWM" },
    { S7COMMP_SOFTDATATYPE_HWPTO,               "HW_PTO" },
    { S7COMMP_SOFTDATATYPE_HWINTERFACE,         "HW_INTERFACE" },
    { S7COMMP_SOFTDATATYPE_OBANY,               "OB_ANY" },
    { S7COMMP_SOFTDATATYPE_OBDELAY,             "OB_DELAY" },
    { S7COMMP_SOFTDATATYPE_OBTOD,               "OB_TOD" },
    { S7COMMP_SOFTDATATYPE_OBCYCLIC,            "OB_CYCLIC" },
    { S7COMMP_SOFTDATATYPE_OBATT,               "OB_ATT" },
    { S7COMMP_SOFTDATATYPE_CONNANY,             "CONN_ANY" },
    { S7COMMP_SOFTDATATYPE_CONNPRG,             "CONN_PRG" },
    { S7COMMP_SOFTDATATYPE_CONNOUC,             "CONN_OUC" },
    { S7COMMP_SOFTDATATYPE_HWNR,                "HW_NR" },
    { S7COMMP_SOFTDATATYPE_PORT,                "PORT" },
    { S7COMMP_SOFTDATATYPE_RTM,                 "RTM" },
    { S7COMMP_SOFTDATATYPE_CALARM,              "C_ALARM" },
    { S7COMMP_SOFTDATATYPE_CALARMS,             "C_ALARM_S" },
    { S7COMMP_SOFTDATATYPE_CALARM8,             "C_ALARM_8" },
    { S7COMMP_SOFTDATATYPE_CALARM8P,            "C_ALARM_8P" },
    { S7COMMP_SOFTDATATYPE_CALARMT,             "C_ALARM_T" },
    { S7COMMP_SOFTDATATYPE_CARSEND,             "C_AR_SEND" },
    { S7COMMP_SOFTDATATYPE_CNOTIFY,             "C_NOTIFY" },
    { S7COMMP_SOFTDATATYPE_CNOTIFY8P,           "C_NOTIFY_8P" },
    { S7COMMP_SOFTDATATYPE_OBPCYCLE,            "OB_PCYCLE" },
    { S7COMMP_SOFTDATATYPE_OBHWINT,             "OB_HWINT" },
    { S7COMMP_SOFTDATATYPE_OBCOMM,              "OB_COMM" },
    { S7COMMP_SOFTDATATYPE_OBDIAG,              "OB_DIAG" },
    { S7COMMP_SOFTDATATYPE_OBTIMEERROR,         "OB_TIMEERROR" },
    { S7COMMP_SOFTDATATYPE_OBSTARTUP,           "OB_STARTUP" },
    { S7COMMP_SOFTDATATYPE_PARA,                "Para" },
    { S7COMMP_SOFTDATATYPE_LABEL,               "Label" },
    { S7COMMP_SOFTDATATYPE_UDEFINED,            "Undefined" },
    { S7COMMP_SOFTDATATYPE_NOTCHOSEN,           "NotChosen" },
    { 0,                                         NULL }
};
static value_string_ext tagdescr_softdatatype_names_ext = VALUE_STRING_EXT_INIT(tagdescr_softdatatype_names);

static const value_string tagdescr_accessability_names[] = {
    { 0,        "Public" },
    { 1,        "ReadOnly" },
    { 2,        "Internal" },
    { 3,        "InternalReadOnly" },
    { 4,        "Protected" },
    { 5,        "ProtectedReadOnly" },
    { 6,        "Constant" },
    { 7,        "ConstantReadOnly" },
    { 0,        NULL }
};

static const value_string lid_access_aid_names[] = {
    { 1,        "LID_OMS_STB_DescriptionRID" },
    { 2,        "LID_OMS_STB_Structured" },
    { 3,        "LID_OMS_STB_ClassicBlob" },
    { 4,        "LID_OMS_STB_RetainBlob" },
    { 5,        "LID_OMS_STB_VolatileBlob" },
    { 6,        "LID_OMS_STB_TypeInfoModificationTime" },
    { 8,        "LID_OMS_STB_BaseClass" },
    { 9,        "LID_OMS_STB_1stFreeLID" },
    { 11,       "LID_PoolUsagePoolName" },
    { 13,       "LID_PoolUsageItemsTotal" },
    { 14,       "LID_PoolUsageItemsUsedCur" },
    { 15,       "LID_PoolUsageBytesUsedCur" },
    { 16,       "LID_PoolUsageItemsUsedMax" },
    { 17,       "LID_PoolUsageAllocCounter" },
    { 18,       "LID_PoolUsageBytesUsedMax" },
    { 19,       "LID_PoolUsageBytesTotal" },
    { 20,       "LID_PoolUsageAllocSize" },
    { 0,        NULL }
};

static const value_string attrib_blocklanguage_names[] = {
    { 0,       "Undefined" },
    { 1,        "STL" },
    { 2,        "LAD_CLASSIC" },
    { 3,        "FBD_CLASSIC" },
    { 4,        "SCL" },
    { 5,        "DB" },
    { 6,        "GRAPH" },
    { 7,        "SDB" },
    { 8,        "CPU_DB" },
    { 17,       "CPU_SDB" },
    { 21,       "CforS7" },
    { 22,       "HIGRAPH" },
    { 23,       "CFC" },
    { 24,       "SFC" },
    { 26,       "S7_PDIAG" },
    { 29,       "RSE" },
    { 31,       "F_STL" },
    { 32,       "F_LAD" },
    { 33,       "F_FBD" },
    { 34,       "F_DB" },
    { 35,       "F_CALL" },
    { 37,       "TechnoDB" },
    { 38,       "F_LAD_LIB" },
    { 39,       "F_FBD_LIB" },
    { 41,       "ClassicEncryption" },
    { 50,       "FCP" },
    { 100,      "LAD_IEC" },
    { 101,      "FBD_IEC" },
    { 102,      "FLD" },
    { 150,      "UDT" },
    { 151,      "SDT" },
    { 152,      "FBT" },
    { 201,      "Motion_DB" },
    { 300,      "GRAPH_ACTIONS" },
    { 301,      "GRAPH_SEQUENCE" },
    { 303,      "GRAPH_ADDINFOS" },
    { 310,      "GRAPH_PLUS" },
    { 400,      "MC7plus" },
    { 500,      "ProDiag" },
    { 501,      "ProDiag_OB" },
    { 0,        NULL }
};

static const value_string attrib_serversessionrole[] = {
    { 0x00000000,   "Undefined" },
    { 0x00000001,   "ES" },
    { 0x00000002,   "HMI" },
    { 0x20000000,   "Response role 0x20000000 unknown (with Auth/Integrity?)" },
    { 0,            NULL }
};

static const value_string attrib_filteroperation[] = {
    { 1,            "Equal" },
    { 2,            "Unequal" },
    { 3,            "LessThan" },
    { 4,            "LessOrEqual" },
    { 5,            "GreaterThan" },
    { 6,            "GreaterOrEqual" },
    { 8,            "InstanceOf" },
    { 10,           "ResolveAddress" },
    { 12,           "ValueIsInSet" },
    { 13,           "DeliverResultSubset" },
    { 14,           "OrDivider" },
    { 15,           "LinkedToOtherObjects" },
    { 0,            NULL }
};

/* blob decompression dictionaries */
#ifdef HAVE_ZLIB
#define BLOB_DECOMPRESS_BUFSIZE     16384
#endif

#define S7COMMP_DICTID_NWT_98000001     0x845fc605
static const char s7commp_dict_NWT_98000001[] = {
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61,
    0x72, 0x79, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x54, 0x69, 0x74, 0x6c, 0x65,
    0x73, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45,
    0x6e, 0x74, 0x72, 0x79, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x4c, 0x61, 0x6e,
    0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x3d, 0x22, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65,
    0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x4e, 0x65,
    0x74, 0x77, 0x6f, 0x72, 0x6b, 0x54, 0x69, 0x74, 0x6c, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x43, 0x6f,
    0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52,
    0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x30, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e,
    0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x64, 0x65,
    0x2d, 0x44, 0x45, 0x22, 0x3e, 0x20, 0x22, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x50, 0x72, 0x6f, 0x67,
    0x72, 0x61, 0x6d, 0x20, 0x53, 0x77, 0x65, 0x65, 0x70, 0x20, 0x28, 0x43, 0x79, 0x63, 0x6c, 0x65,
    0x29, 0x22, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f,
    0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74,
    0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x32, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74,
    0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22,
    0x66, 0x72, 0x2d, 0x46, 0x52, 0x22, 0x3e, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74,
    0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f,
    0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x31, 0x36, 0x22,
    0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67,
    0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x69, 0x74, 0x2d, 0x49, 0x54, 0x22, 0x3e, 0x74, 0x68, 0x69,
    0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x68, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x6f,
    0x20, 0x61, 0x6e, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61,
    0x72, 0x65, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x6e, 0x64, 0x3c, 0x2f,
    0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d,
    0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66,
    0x49, 0x44, 0x3d, 0x22, 0x32, 0x36, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74,
    0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d,
    0x55, 0x53, 0x22, 0x3e, 0x64, 0x69, 0x65, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e,
    0x20, 0x64, 0x65, 0x72, 0x20, 0x64, 0x69, 0x65, 0x20, 0x64, 0x61, 0x73, 0x20, 0x69, 0x6d, 0x20,
    0x6e, 0x61, 0x63, 0x68, 0x20, 0x65, 0x69, 0x6e, 0x65, 0x6e, 0x20, 0x6b, 0x61, 0x6e, 0x6e, 0x20,
    0x73, 0x65, 0x69, 0x6e, 0x20, 0x66, 0xc3, 0xbc, 0x72, 0x20, 0x73, 0x69, 0x6e, 0x64, 0x20, 0x4e,
    0x65, 0x74, 0x7a, 0x77, 0x65, 0x72, 0x6b, 0x20, 0x75, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63,
    0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
    0x54, 0x69, 0x74, 0x6c, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74,
    0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e
};

#define S7COMMP_DICTID_BodyDesc_90000001    0xefaeae49
static const char s7commp_dict_BodyDesc_90000001[] = {
    0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
    0x72, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x3d,
    0x22, 0x4c, 0x41, 0x44, 0x5f, 0x43, 0x4c, 0x41, 0x53, 0x53, 0x49, 0x43, 0x22, 0x20, 0x50, 0x72,
    0x6f, 0x67, 0x72, 0x61, 0x6d, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
    0x3d, 0x22, 0x50, 0x6c, 0x61, 0x69, 0x6e, 0x22, 0x20, 0x4d, 0x6e, 0x65, 0x6d, 0x6f, 0x6e, 0x69,
    0x63, 0x3d, 0x22, 0x47, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64,
    0x3d, 0x22, 0x31, 0x22, 0x3e, 0x3c, 0x46, 0x6c, 0x67, 0x4e, 0x65, 0x74, 0x20, 0x56, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x30, 0x2e, 0x35, 0x2e, 0x30, 0x2e, 0x30, 0x22, 0x20,
    0x4c, 0x61, 0x6e, 0x67, 0x3d, 0x22, 0x4c, 0x41, 0x44, 0x5f, 0x43, 0x4c, 0x41, 0x53, 0x53, 0x49,
    0x43, 0x22, 0x20, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x64, 0x3d, 0x22, 0x74, 0x72, 0x75, 0x65, 0x22,
    0x3e, 0x3c, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x52, 0x65, 0x66,
    0x20, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x45, 0x6e,
    0x64, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x35, 0x22, 0x20, 0x55, 0x49,
    0x64, 0x3d, 0x22, 0x33, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x4c, 0x61, 0x62, 0x65, 0x6c,
    0x73, 0x3e, 0x3c, 0x50, 0x61, 0x72, 0x74, 0x73, 0x3e, 0x3c, 0x50, 0x61, 0x72, 0x74, 0x20, 0x55,
    0x49, 0x64, 0x3d, 0x22, 0x33, 0x22, 0x20, 0x47, 0x61, 0x74, 0x65, 0x3d, 0x22, 0x43, 0x6f, 0x6e,
    0x74, 0x61, 0x63, 0x74, 0x22, 0x3e, 0x3c, 0x4e, 0x65, 0x67, 0x61, 0x74, 0x65, 0x64, 0x20, 0x50,
    0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x22,
    0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x50, 0x61, 0x72, 0x74, 0x3e, 0x3c, 0x4f, 0x52, 0x65, 0x66,
    0x20, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x22, 0x54,
    0x61, 0x67, 0x5f, 0x31, 0x22, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x37,
    0x22, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x50, 0x61,
    0x72, 0x74, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x36, 0x22, 0x20, 0x47, 0x61, 0x74, 0x65, 0x3d,
    0x22, 0x41, 0x64, 0x64, 0x22, 0x20, 0x53, 0x72, 0x63, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x44,
    0x49, 0x6e, 0x74, 0x22, 0x20, 0x43, 0x61, 0x72, 0x64, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x2f, 0x3e,
    0x20, 0x3c, 0x50, 0x61, 0x72, 0x74, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x34, 0x22, 0x20,
    0x47, 0x61, 0x74, 0x65, 0x3d, 0x22, 0x45, 0x71, 0x22, 0x20, 0x53, 0x72, 0x63, 0x54, 0x79, 0x70,
    0x65, 0x3d, 0x22, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x50, 0x61, 0x72, 0x74,
    0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x47, 0x61, 0x74, 0x65, 0x3d, 0x22, 0x52,
    0x6f, 0x75, 0x6e, 0x64, 0x22, 0x20, 0x53, 0x72, 0x63, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x52,
    0x65, 0x61, 0x6c, 0x22, 0x20, 0x44, 0x65, 0x73, 0x74, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x44,
    0x49, 0x6e, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x4f, 0x52, 0x65, 0x66, 0x20, 0x44, 0x69,
    0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x22, 0x54, 0x61, 0x67, 0x5f,
    0x32, 0x22, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x32, 0x37, 0x22, 0x20, 0x55,
    0x49, 0x64, 0x3d, 0x22, 0x31, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x4f, 0x52, 0x65, 0x66,
    0x20, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x4c, 0x23,
    0x33, 0x34, 0x35, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x34, 0x22, 0x20,
    0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x36, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x43, 0x52,
    0x65, 0x66, 0x20, 0x43, 0x61, 0x6c, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x46, 0x75, 0x6e,
    0x63, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x61, 0x6c, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64,
    0x3d, 0x22, 0x34, 0x22, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x3e, 0x20, 0x20, 0x3c,
    0x4f, 0x52, 0x65, 0x66, 0x20, 0x44, 0x69, 0x73, 0x70, 0x6c, 0x61, 0x79, 0x4e, 0x61, 0x6d, 0x65,
    0x3d, 0x22, 0x26, 0x71, 0x75, 0x6f, 0x74, 0x3b, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63,
    0x65, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x39,
    0x30, 0x26, 0x71, 0x75, 0x6f, 0x74, 0x3b, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22,
    0x33, 0x22, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x36, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c,
    0x56, 0x69, 0x65, 0x77, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x48, 0x65, 0x69, 0x67, 0x68, 0x74, 0x3d,
    0x22, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x43, 0x52, 0x65, 0x66, 0x3e, 0x3c, 0x2f, 0x50,
    0x61, 0x72, 0x74, 0x73, 0x3e, 0x3c, 0x57, 0x69, 0x72, 0x65, 0x73, 0x3e, 0x3c, 0x57, 0x69, 0x72,
    0x65, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x50, 0x6f, 0x77,
    0x65, 0x72, 0x72, 0x61, 0x69, 0x6c, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x50, 0x43, 0x6f,
    0x6e, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x50, 0x69, 0x6e, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x56, 0x69, 0x65,
    0x77, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x53, 0x74, 0x61, 0x72, 0x74, 0x3d, 0x22, 0x74, 0x72, 0x75,
    0x65, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x57, 0x69, 0x72, 0x65, 0x3e, 0x3c, 0x57, 0x69,
    0x72, 0x65, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x43,
    0x6f, 0x6e, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20,
    0x3c, 0x50, 0x43, 0x6f, 0x6e, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x50, 0x69,
    0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x6f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x22, 0x20,
    0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x57, 0x69, 0x72, 0x65, 0x3e, 0x3c, 0x57, 0x69, 0x72, 0x65, 0x20,
    0x55, 0x49, 0x64, 0x3d, 0x22, 0x37, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x50, 0x43, 0x6f, 0x6e, 0x20,
    0x55, 0x49, 0x64, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x50, 0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x4f, 0x55, 0x54, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x4f, 0x43, 0x6f,
    0x6e, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x37, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x57,
    0x69, 0x72, 0x65, 0x3e, 0x3c, 0x57, 0x69, 0x72, 0x65, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x35,
    0x22, 0x3e, 0x20, 0x20, 0x3c, 0x50, 0x6f, 0x77, 0x65, 0x72, 0x72, 0x61, 0x69, 0x6c, 0x20, 0x2f,
    0x3e, 0x20, 0x20, 0x20, 0x3c, 0x50, 0x43, 0x6f, 0x6e, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x36,
    0x22, 0x20, 0x50, 0x69, 0x6e, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20, 0x2f,
    0x3e, 0x20, 0x20, 0x20, 0x3c, 0x56, 0x69, 0x65, 0x77, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x53, 0x74,
    0x61, 0x72, 0x74, 0x3d, 0x22, 0x74, 0x72, 0x75, 0x65, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f,
    0x57, 0x69, 0x72, 0x65, 0x3e, 0x3c, 0x2f, 0x57, 0x69, 0x72, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x46,
    0x6c, 0x67, 0x4e, 0x65, 0x74, 0x3e, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f,
    0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x30, 0x2e, 0x35, 0x2e, 0x31,
    0x38, 0x2e, 0x34, 0x22, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x3d, 0x22,
    0x31, 0x32, 0x38, 0x36, 0x39, 0x36, 0x37, 0x35, 0x32, 0x38, 0x30, 0x30, 0x33, 0x31, 0x33, 0x38,
    0x30, 0x35, 0x22, 0x20, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d,
    0x3d, 0x22, 0x4d, 0x43, 0x37, 0x50, 0x6c, 0x75, 0x73, 0x22, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x3d,
    0x22, 0x4c, 0x41, 0x44, 0x5f, 0x43, 0x4c, 0x41, 0x53, 0x53, 0x49, 0x43, 0x22, 0x3e, 0x20, 0x20,
    0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22,
    0x32, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
    0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
    0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20, 0x4f, 0x70,
    0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x30,
    0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65,
    0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x42, 0x69, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x31, 0x22, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x4e, 0x61, 0x74, 0x69,
    0x76, 0x65, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42,
    0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x4e, 0x61, 0x74, 0x69, 0x76,
    0x65, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x20, 0x53, 0x6c, 0x6f, 0x74, 0x42, 0x69, 0x74, 0x20, 0x30,
    0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x4e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x4c,
    0x6f, 0x63, 0x61, 0x6c, 0x22, 0x20, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22,
    0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x53, 0x6c, 0x6f, 0x74, 0x42, 0x69, 0x74, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x20, 0x3c, 0x44, 0x65,
    0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x32, 0x22, 0x20,
    0x53, 0x41, 0x43, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d,
    0x62, 0x65, 0x72, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x42, 0x61, 0x68,
    0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61,
    0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74,
    0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x52,
    0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x3d, 0x22,
    0x4e, 0x65, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20,
    0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22,
    0x33, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
    0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70,
    0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20, 0x4f, 0x70,
    0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x31,
    0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x46, 0x6c, 0x61, 0x67,
    0x73, 0x3d, 0x22, 0x4e, 0x65, 0x67, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x22, 0x20, 0x2f, 0x3e,
    0x20, 0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49,
    0x64, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x47, 0x72,
    0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x47, 0x72,
    0x6f, 0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x4f, 0x55, 0x54,
    0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x32, 0x22, 0x20, 0x52, 0x4c, 0x4f, 0x3d, 0x22, 0x54, 0x72, 0x75, 0x65, 0x22, 0x20,
    0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20,
    0x55, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x33, 0x22, 0x20,
    0x47, 0x72, 0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x33, 0x22, 0x20,
    0x47, 0x72, 0x6f, 0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x4f,
    0x55, 0x54, 0x22, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x33, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e,
    0x64, 0x65, 0x78, 0x3d, 0x22, 0x33, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x36,
    0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66,
    0x6f, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x36, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x34,
    0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x34,
    0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d,
    0x22, 0x4f, 0x55, 0x54, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49,
    0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x52, 0x4c, 0x4f, 0x3d, 0x22, 0x54, 0x72,
    0x75, 0x65, 0x22, 0x20, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x3d, 0x22, 0x44, 0x49, 0x49, 0x6e, 0x76,
    0x61, 0x6c, 0x69, 0x64, 0x46, 0x6f, 0x72, 0x4b, 0x6f, 0x70, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20,
    0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49, 0x64, 0x3d,
    0x22, 0x37, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75,
    0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75,
    0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20, 0x4f,
    0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x35, 0x22, 0x20,
    0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22,
    0x35, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x37, 0x22, 0x20, 0x2f, 0x3e, 0x20,
    0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49, 0x64,
    0x3d, 0x22, 0x38, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x36, 0x22, 0x20, 0x47, 0x72, 0x6f,
    0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x36, 0x22, 0x20, 0x47, 0x72, 0x6f,
    0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x4f, 0x55, 0x54, 0x22,
    0x20, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x36,
    0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x36, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x2f,
    0x3e, 0x20, 0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20, 0x55,
    0x49, 0x64, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x37, 0x22, 0x20, 0x47,
    0x72, 0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x37, 0x22, 0x20, 0x47,
    0x72, 0x6f, 0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22, 0x4f, 0x55,
    0x54, 0x22, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d,
    0x22, 0x37, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64,
    0x65, 0x78, 0x3d, 0x22, 0x37, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x39, 0x22,
    0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f,
    0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x38, 0x22,
    0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x38, 0x22,
    0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69, 0x6f, 0x72, 0x3d, 0x22,
    0x49, 0x4e, 0x22, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x38, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e,
    0x64, 0x65, 0x78, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x30,
    0x22, 0x20, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x3d, 0x22, 0x4e, 0x65, 0x67, 0x52, 0x65, 0x73, 0x75,
    0x6c, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x20, 0x3c, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49,
    0x6e, 0x66, 0x6f, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x53, 0x41, 0x43, 0x3d,
    0x22, 0x35, 0x36, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
    0x3d, 0x22, 0x30, 0x22, 0x20, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x42, 0x61, 0x68, 0x61, 0x76, 0x69,
    0x6f, 0x72, 0x3d, 0x22, 0x4f, 0x55, 0x54, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65,
    0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x31, 0x33, 0x22, 0x20, 0x52, 0x4c, 0x4f,
    0x3d, 0x22, 0x54, 0x72, 0x75, 0x65, 0x22, 0x20, 0x43, 0x61, 0x6c, 0x6c, 0x50, 0x61, 0x72, 0x61,
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x30, 0x22, 0x3e, 0x3c, 0x43, 0x61, 0x6c, 0x6c, 0x49,
    0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x61, 0x6c, 0x6c, 0x20, 0x53, 0x41, 0x43, 0x3d,
    0x22, 0x33, 0x38, 0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e,
    0x64, 0x65, 0x78, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x61, 0x6c,
    0x6c, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x35, 0x34,
    0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x31, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4e, 0x65, 0x78, 0x74, 0x53,
    0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x41, 0x66, 0x74, 0x65, 0x72, 0x43, 0x61, 0x6c,
    0x6c, 0x45, 0x78, 0x65, 0x63, 0x75, 0x74, 0x65, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x35, 0x35,
    0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x31, 0x32, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x61, 0x6c, 0x6c, 0x46, 0x72,
    0x61, 0x6d, 0x65, 0x43, 0x6c, 0x65, 0x61, 0x72, 0x20, 0x53, 0x41, 0x43, 0x3d, 0x22, 0x35, 0x35,
    0x22, 0x20, 0x53, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78,
    0x3d, 0x22, 0x31, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x43, 0x61, 0x6c, 0x6c, 0x49, 0x6e,
    0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f,
    0x3e, 0x3c, 0x2f, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x2f, 0x4e,
    0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20,
    0x4c, 0x61, 0x6e, 0x67, 0x3d, 0x22, 0x4c, 0x41, 0x44, 0x5f, 0x43, 0x4c, 0x41, 0x53, 0x53, 0x49,
    0x43, 0x22, 0x20, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x6d, 0x69, 0x6e, 0x67, 0x43, 0x6f,
    0x6e, 0x74, 0x65, 0x78, 0x74, 0x3d, 0x22, 0x50, 0x6c, 0x61, 0x69, 0x6e, 0x22, 0x20, 0x4d, 0x6e,
    0x65, 0x6d, 0x6f, 0x6e, 0x69, 0x63, 0x3d, 0x22, 0x47, 0x65, 0x72, 0x6d, 0x61, 0x6e, 0x22, 0x20,
    0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x35, 0x36, 0x22, 0x3e, 0x3c, 0x2f, 0x4e, 0x65, 0x74,
    0x77, 0x6f, 0x72, 0x6b, 0x3e, 0x3c, 0x2f, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x43, 0x6f,
    0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
    0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x20, 0x2f, 0x3e
};

#define S7COMMP_DICTID_NWC_90000001     0xab6fa31e
static const char s7commp_dict_NWC_90000001[] = {
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61,
    0x72, 0x79, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x43, 0x6f, 0x6d, 0x6d, 0x65,
    0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66,
    0x49, 0x44, 0x3d, 0x22, 0x32, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72,
    0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55,
    0x53, 0x22, 0x3e, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c,
    0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e,
    0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x3e, 0x3c, 0x44, 0x69,
    0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,
    0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x3e, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73,
    0x20, 0x61, 0x20, 0x74, 0x68, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20,
    0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6e,
    0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74,
    0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e,
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22,
    0x32, 0x36, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c,
    0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x3e,
    0x64, 0x69, 0x65, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e, 0x20, 0x64, 0x65, 0x72,
    0x20, 0x64, 0x69, 0x65, 0x20, 0x64, 0x61, 0x73, 0x20, 0x69, 0x6d, 0x20, 0x6e, 0x61, 0x63, 0x68,
    0x20, 0x65, 0x69, 0x6e, 0x65, 0x6e, 0x20, 0x6b, 0x61, 0x6e, 0x6e, 0x20, 0x73, 0x65, 0x69, 0x6e,
    0x20, 0x66, 0xc3, 0xbc, 0x72, 0x20, 0x73, 0x69, 0x6e, 0x64, 0x20, 0x4e, 0x65, 0x74, 0x7a, 0x77,
    0x65, 0x72, 0x6b, 0x20, 0x75, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74,
    0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x4e,
    0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3e, 0x3c,
    0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61,
    0x72, 0x79, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69,
    0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x20, 0x20, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
    0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d,
    0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e
};

#define S7COMMP_DICTID_NWC_98000001     0xc5d26ac3
static const char s7commp_dict_NWC_98000001[] = {
    0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x68, 0x65, 0x20, 0x69, 0x6e,
    0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x66, 0x6f,
    0x72, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x6e,
    0x64, 0x20, 0x64, 0x69, 0x65, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e, 0x20, 0x64,
    0x65, 0x72, 0x20, 0x64, 0x69, 0x65, 0x20, 0x64, 0x61, 0x73, 0x20, 0x69, 0x6d, 0x20, 0x6e, 0x61,
    0x63, 0x68, 0x20, 0x65, 0x69, 0x6e, 0x65, 0x6e, 0x20, 0x6b, 0x61, 0x6e, 0x6e, 0x20, 0x73, 0x65,
    0x69, 0x6e, 0x20, 0x66, 0xc3, 0xbc, 0x72, 0x20, 0x73, 0x69, 0x6e, 0x64, 0x20, 0x4e, 0x65, 0x74,
    0x7a, 0x77, 0x65, 0x72, 0x6b, 0x20, 0x75, 0x6e, 0x64, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e,
    0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x4e, 0x65, 0x74,
    0x77, 0x6f, 0x72, 0x6b, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x43, 0x6f,
    0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x32, 0x22, 0x3e,
    0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75,
    0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x64, 0x65, 0x2d, 0x44, 0x45,
    0x22, 0x69, 0x74, 0x2d, 0x49, 0x54, 0x22, 0x66, 0x72, 0x2d, 0x46, 0x52, 0x22, 0x3e, 0x3c, 0x2f,
    0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d,
    0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x43, 0x6f, 0x6d,
    0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44,
    0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f,
    0x72, 0x6b, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x2f, 0x3e
};

#define S7COMMP_DICTID_NWT_90000001     0xfd9ac74
static const char s7commp_dict_NWT_90000001[] = {
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61,
    0x72, 0x79, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x54, 0x69, 0x74, 0x6c, 0x65,
    0x73, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x20, 0x20, 0x20,
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22,
    0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20,
    0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22,
    0x3e, 0x20, 0x22, 0x4d, 0x61, 0x69, 0x6e, 0x20, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20,
    0x53, 0x77, 0x65, 0x65, 0x70, 0x20, 0x28, 0x43, 0x79, 0x63, 0x6c, 0x65, 0x29, 0x22, 0x3c, 0x2f,
    0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d,
    0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66,
    0x49, 0x44, 0x3d, 0x22, 0x32, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72,
    0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55,
    0x53, 0x22, 0x3e, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c,
    0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e,
    0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x3e, 0x3c, 0x44, 0x69,
    0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65,
    0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x3e, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73,
    0x20, 0x61, 0x20, 0x74, 0x68, 0x65, 0x20, 0x69, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20,
    0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6e,
    0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74,
    0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e,
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22,
    0x32, 0x36, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c,
    0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x3e,
    0x64, 0x69, 0x65, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e, 0x20, 0x64, 0x65, 0x72,
    0x20, 0x64, 0x69, 0x65, 0x20, 0x64, 0x61, 0x73, 0x20, 0x69, 0x6d, 0x20, 0x6e, 0x61, 0x63, 0x68,
    0x20, 0x65, 0x69, 0x6e, 0x65, 0x6e, 0x20, 0x6b, 0x61, 0x6e, 0x6e, 0x20, 0x73, 0x65, 0x69, 0x6e,
    0x20, 0x66, 0xc3, 0xbc, 0x72, 0x20, 0x73, 0x69, 0x6e, 0x64, 0x20, 0x4e, 0x65, 0x74, 0x7a, 0x77,
    0x65, 0x72, 0x6b, 0x20, 0x75, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74,
    0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x54, 0x69, 0x74, 0x6c,
    0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74,
    0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e
};

#define S7COMMP_DICTID_DebugInfo_90000001   0x1bac39f0
static const char s7commp_dict_DebugInfo_90000001[] = {
    0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x20,
    0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x30, 0x2e, 0x35, 0x2e, 0x31, 0x38,
    0x2e, 0x34, 0x22, 0x20, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x3d, 0x22, 0x31,
    0x32, 0x38, 0x36, 0x38, 0x30, 0x39, 0x32, 0x34, 0x35, 0x30, 0x36, 0x35, 0x32, 0x37, 0x32, 0x35,
    0x38, 0x22, 0x3e, 0x3c, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d,
    0x22, 0x4d, 0x43, 0x37, 0x50, 0x6c, 0x75, 0x73, 0x22, 0x3e, 0x3c, 0x4e, 0x65, 0x74, 0x20, 0x49,
    0x64, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x45, 0x6e, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
    0x3d, 0x22, 0x36, 0x30, 0x22, 0x20, 0x45, 0x6e, 0x64, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
    0x58, 0x6d, 0x6c, 0x3d, 0x22, 0x2d, 0x31, 0x22, 0x20, 0x45, 0x6e, 0x64, 0x53, 0x74, 0x61, 0x74,
    0x65, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x33, 0x31, 0x22, 0x20,
    0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x3e, 0x3c, 0x2f, 0x42, 0x6c,
    0x6f, 0x63, 0x6b, 0x44, 0x65, 0x62, 0x75, 0x67, 0x49, 0x6e, 0x66, 0x6f, 0x3e
};

#define S7COMMP_DICTID_DebugInfo_IntfDesc_98000001   0x66052b13
static const char s7commp_dict_DebugInfo_IntfDesc_98000001[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x42, 0x61, 0x73, 0x65, 0x3c, 0x46, 0x42, 0x54,
    0x20, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x64, 0x54, 0x79, 0x70, 0x65, 0x73,
    0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x53,
    0x6c, 0x6f, 0x74, 0x3d, 0x22, 0x20, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x53, 0x6c,
    0x6f, 0x74, 0x3d, 0x22, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x53, 0x6c, 0x6f, 0x74, 0x3d,
    0x22, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x55, 0x6e, 0x69, 0x74, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x3e, 0x3c, 0x4d, 0x66, 0x62, 0x55, 0x44, 0x54, 0x20, 0x49, 0x64, 0x65, 0x6e, 0x74,
    0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x50, 0x61,
    0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x3d, 0x22, 0x20, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69,
    0x6c, 0x65, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x3d, 0x22, 0x20, 0x43, 0x6c,
    0x61, 0x73, 0x73, 0x69, 0x63, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x3d, 0x22,
    0x3c, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x3c, 0x49,
    0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x49,
    0x64, 0x65, 0x6e, 0x74, 0x3c, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66,
    0x6f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79,
    0x70, 0x65, 0x3d, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x20,
    0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72, 0x65, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65,
    0x64, 0x54, 0x53, 0x3d, 0x22, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x4d,
    0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x54, 0x53, 0x3d, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65,
    0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x52, 0x49, 0x64, 0x3d, 0x22,
    0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x4d, 0x49, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x50,
    0x61, 0x64, 0x64, 0x65, 0x64, 0x42, 0x69, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x4d,
    0x49, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x50, 0x61, 0x64, 0x64, 0x65, 0x64, 0x42,
    0x69, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x4d, 0x49, 0x43, 0x6c, 0x61, 0x73, 0x73,
    0x69, 0x63, 0x50, 0x61, 0x64, 0x64, 0x65, 0x64, 0x42, 0x69, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x20, 0x4d, 0x49, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69,
    0x76, 0x65, 0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x4d, 0x49,
    0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x76, 0x65,
    0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x4d, 0x49, 0x43, 0x6c,
    0x61, 0x73, 0x73, 0x69, 0x63, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x76, 0x65, 0x42, 0x69, 0x74,
    0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22,
    0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65,
    0x6d, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x55, 0x73,
    0x61, 0x67, 0x65, 0x3d, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f,
    0x6e, 0x3d, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x58, 0x52, 0x65, 0x66,
    0x48, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f, 0x74, 0x4e, 0x75, 0x6d,
    0x62, 0x65, 0x72, 0x3d, 0x22, 0x3c, 0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x54, 0x79,
    0x70, 0x65, 0x73, 0x3c, 0x44, 0x61, 0x74, 0x61, 0x74, 0x79, 0x70, 0x65, 0x20, 0x43, 0x6c, 0x61,
    0x73, 0x73, 0x69, 0x63, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x52, 0x65,
    0x74, 0x61, 0x69, 0x6e, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x56, 0x6f,
    0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x3c,
    0x45, 0x78, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x54, 0x79, 0x70, 0x65, 0x3c, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x53, 0x74, 0x6f, 0x72, 0x61, 0x67, 0x65, 0x3e, 0x3c, 0x50, 0x61, 0x72, 0x74, 0x3e,
    0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x5f, 0x53,
    0x74, 0x61, 0x72, 0x74, 0x4f, 0x66, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x50, 0x61, 0x72, 0x74,
    0x3d, 0x22, 0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65,
    0x5f, 0x53, 0x74, 0x61, 0x72, 0x74, 0x4f, 0x66, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65,
    0x50, 0x61, 0x72, 0x74, 0x3d, 0x22, 0x20, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x69, 0x6e, 0x73, 0x74,
    0x61, 0x6e, 0x63, 0x65, 0x5f, 0x53, 0x74, 0x61, 0x72, 0x74, 0x4f, 0x66, 0x43, 0x6c, 0x61, 0x73,
    0x73, 0x69, 0x63, 0x50, 0x61, 0x72, 0x74, 0x3d, 0x22, 0x3c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73,
    0x20, 0x57, 0x69, 0x64, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x42, 0x69, 0x74,
    0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x50, 0x61, 0x64, 0x64, 0x65, 0x64, 0x45, 0x6c, 0x65,
    0x6d, 0x65, 0x6e, 0x74, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x49, 0x64,
    0x65, 0x6e, 0x74, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x4f, 0x70, 0x65, 0x72, 0x61,
    0x6e, 0x64, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x20, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x4d,
    0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70,
    0x3d, 0x22, 0x20, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
    0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x3d, 0x22, 0x3c, 0x43, 0x61, 0x6c, 0x6c,
    0x53, 0x74, 0x61, 0x63, 0x6b, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x55, 0x73, 0x65, 0x41, 0x6e,
    0x6e, 0x6f, 0x74, 0x61, 0x74, 0x65, 0x64, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x73, 0x3d, 0x22,
    0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31,
    0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x75, 0x74,
    0x66, 0x2d, 0x31, 0x36, 0x22, 0x3f, 0x3e, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x3c, 0x55, 0x73, 0x61, 0x67, 0x65, 0x20, 0x4c, 0x69, 0x62,
    0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x78, 0x6d, 0x6c, 0x6e, 0x73,
    0x3d, 0x22, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x73, 0x63, 0x68, 0x65, 0x6d, 0x61, 0x73,
    0x2e, 0x73, 0x69, 0x65, 0x6d, 0x65, 0x6e, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x53, 0x69, 0x6d,
    0x61, 0x74, 0x69, 0x63, 0x2f, 0x45, 0x53, 0x2f, 0x31, 0x31, 0x2f, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x2f, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65,
    0x2f, 0x56, 0x31, 0x31, 0x5f, 0x30, 0x31, 0x2e, 0x78, 0x73, 0x64, 0x20, 0x54, 0x79, 0x70, 0x65,
    0x49, 0x6e, 0x66, 0x6f, 0x52, 0x75, 0x6e, 0x74, 0x69, 0x6d, 0x65, 0x49, 0x64, 0x3d, 0x22, 0x3c,
    0x52, 0x6f, 0x6f, 0x74, 0x3c, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x44, 0x61, 0x74, 0x61, 0x20,
    0x58, 0x6d, 0x6c, 0x50, 0x61, 0x72, 0x74, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x42, 0x6c, 0x6f, 0x63,
    0x6b, 0x54, 0x79, 0x70, 0x65, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x3d, 0x22, 0x20, 0x42, 0x69,
    0x74, 0x53, 0x6c, 0x6f, 0x74, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f,
    0x74, 0x38, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f, 0x74, 0x31, 0x36,
    0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f, 0x74, 0x33, 0x32, 0x43, 0x6f,
    0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f, 0x74, 0x36, 0x34, 0x43, 0x6f, 0x75, 0x6e,
    0x74, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f, 0x74, 0x53, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x44, 0x6f,
    0x75, 0x62, 0x6c, 0x65, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x53, 0x6c, 0x6f, 0x74,
    0x50, 0x6f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x3c, 0x53,
    0x75, 0x62, 0x50, 0x61, 0x72, 0x74, 0x73, 0x3e, 0x20, 0x52, 0x49, 0x64, 0x53, 0x6c, 0x6f, 0x74,
    0x73, 0x3d, 0x22, 0x20, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x55, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x50,
    0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x3d, 0x22, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72,
    0x66, 0x61, 0x63, 0x65, 0x47, 0x75, 0x69, 0x64, 0x3d, 0x22, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69,
    0x6f, 0x6e, 0x47, 0x75, 0x69, 0x64, 0x3d, 0x22, 0x3c, 0x44, 0x61, 0x74, 0x61, 0x74, 0x79, 0x70,
    0x65, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x3c, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x44, 0x61,
    0x74, 0x61, 0x4d, 0x61, 0x70, 0x20, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x73, 0x73,
    0x69, 0x67, 0x6e, 0x65, 0x64, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x49, 0x64, 0x3d, 0x22, 0x3c, 0x50,
    0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x20, 0x4c, 0x53, 0x74,
    0x61, 0x63, 0x6b, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x49, 0x6e, 0x66,
    0x6f, 0x5f, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x50, 0x61, 0x72, 0x74, 0x53, 0x69, 0x7a,
    0x65, 0x3d, 0x22, 0x20, 0x49, 0x6e, 0x66, 0x6f, 0x5f, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c,
    0x65, 0x50, 0x61, 0x72, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x49, 0x6e, 0x66, 0x6f,
    0x5f, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x50, 0x61, 0x72, 0x74, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x3c, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x20, 0x41,
    0x63, 0x63, 0x65, 0x73, 0x73, 0x69, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x20, 0x49,
    0x6e, 0x66, 0x6f, 0x5f, 0x41, 0x72, 0x72, 0x61, 0x79, 0x5f, 0x50, 0x61, 0x64, 0x64, 0x65, 0x64,
    0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x49, 0x6e,
    0x66, 0x6f, 0x5f, 0x41, 0x72, 0x72, 0x61, 0x79, 0x5f, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65,
    0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x42, 0x69,
    0x74, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x4e, 0x65, 0x6e, 0x61, 0x42, 0x69,
    0x74, 0x6f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74,
    0x53, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x3c,
    0x53, 0x69, 0x7a, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3c, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74,
    0x65, 0x72, 0x50, 0x61, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x3c, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72,
    0x79, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x4d, 0x65, 0x6d, 0x62,
    0x65, 0x72, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x4d, 0x46, 0x6c, 0x61, 0x67, 0x73,
    0x3d, 0x22, 0x20, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x76, 0x65, 0x42, 0x69, 0x74, 0x6f, 0x66,
    0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65,
    0x3d, 0x22, 0x3c, 0x50, 0x61, 0x72, 0x74, 0x3c, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x3e,
    0x3c, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x50, 0x65,
    0x6e, 0x61, 0x6c, 0x74, 0x79, 0x42, 0x79, 0x74, 0x65, 0x73, 0x49, 0x6e, 0x42, 0x69, 0x74, 0x73,
    0x3d, 0x22, 0x20, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x73, 0x73, 0x69, 0x67, 0x6e,
    0x65, 0x64, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x53,
    0x75, 0x62, 0x50, 0x61, 0x72, 0x74, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x3d, 0x22, 0x20, 0x49, 0x6e,
    0x66, 0x6f, 0x5f, 0x57, 0x69, 0x64, 0x65, 0x73, 0x74, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x3d,
    0x22, 0x20, 0x50, 0x61, 0x64, 0x64, 0x65, 0x64, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x3c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x20, 0x4b, 0x69, 0x6e, 0x64, 0x3d, 0x22, 0x20, 0x56,
    0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x32, 0x2e, 0x30, 0x22, 0x20, 0x78, 0x6d, 0x6c,
    0x6e, 0x73, 0x3d, 0x22, 0x3c, 0x4d, 0x65, 0x6d, 0x62, 0x65, 0x72, 0x20, 0x43, 0x68, 0x61, 0x6e,
    0x67, 0x65, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x3d, 0x22, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x3d,
    0x22, 0x20, 0x52, 0x65, 0x70, 0x72, 0x65, 0x73, 0x65, 0x6e, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
    0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x20, 0x50, 0x61, 0x73, 0x73, 0x65, 0x64, 0x41, 0x73, 0x3d,
    0x22, 0x20, 0x52, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x4c, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x54, 0x79,
    0x70, 0x65, 0x3d, 0x22, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x42, 0x23, 0x31, 0x36,
    0x23, 0x57, 0x23, 0x31, 0x36, 0x23, 0x52, 0x65, 0x74, 0x5f, 0x56, 0x61, 0x6c, 0x46, 0x75, 0x6e,
    0x63, 0x74, 0x69, 0x6f, 0x6e, 0x43, 0x4c, 0x41, 0x53, 0x53, 0x49, 0x43, 0x5f, 0x50, 0x4c, 0x45,
    0x41, 0x53, 0x45, 0x4e, 0x45, 0x4e, 0x41, 0x5f, 0x50, 0x4c, 0x45, 0x41, 0x53, 0x45, 0x56, 0x6f,
    0x69, 0x64, 0x54, 0x72, 0x75, 0x65, 0x74, 0x72, 0x75, 0x65, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x66,
    0x61, 0x6c, 0x73, 0x65, 0x53, 0x37, 0x5f, 0x56, 0x69, 0x73, 0x69, 0x62, 0x6c, 0x65, 0x33, 0x32,
    0x35, 0x31, 0x3a, 0x35, 0x32, 0x3a, 0x35, 0x33, 0x3a, 0x35, 0x34, 0x3a, 0x35, 0x35, 0x3a, 0x35,
    0x38, 0x44, 0x54, 0x4c, 0x55, 0x53, 0x49, 0x6e, 0x74, 0x75, 0x6e, 0x64, 0x65, 0x66, 0x55, 0x6e,
    0x64, 0x65, 0x66, 0x52, 0x65, 0x61, 0x6c, 0x48, 0x4d, 0x49, 0x5f, 0x56, 0x69, 0x73, 0x69, 0x62,
    0x6c, 0x65, 0x30, 0x78, 0x30, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x57, 0x6f, 0x72, 0x64,
    0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x30, 0x78, 0x30, 0x30, 0x30, 0x30, 0x46, 0x46, 0x46, 0x46,
    0x4d, 0x61, 0x6e, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x79, 0x3c, 0x44, 0x61, 0x74, 0x61, 0x20, 0x49,
    0x44, 0x3d, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x20, 0x42, 0x61, 0x73, 0x65, 0x3d,
    0x22, 0x20, 0x52, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x76, 0x65, 0x3d, 0x22, 0x20, 0x53, 0x69, 0x7a,
    0x65, 0x3d, 0x22, 0x20, 0x50, 0x61, 0x64, 0x64, 0x65, 0x64, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22,
    0x20, 0x50, 0x61, 0x74, 0x68, 0x3d, 0x22, 0x3d, 0x22, 0x3e
};

#define S7COMMP_DICTID_ExtRefData_90000001  0x9b6a3a92
static const char s7commp_dict_ExtRefData_90000001[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e,
    0x20, 0x20, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54,
    0x61, 0x67, 0x5f, 0x32, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f,
    0x62, 0x61, 0x6c, 0x22, 0x3e, 0x3c, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49, 0x6e,
    0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55,
    0x49, 0x64, 0x3d, 0x22, 0x37, 0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65,
    0x61, 0x64, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d,
    0x22, 0x31, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x2f, 0x3e,
    0x20, 0x20, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d,
    0x22, 0x38, 0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22,
    0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x22,
    0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20,
    0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x39,
    0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49,
    0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4e,
    0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x33, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x58,
    0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x30, 0x22,
    0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49, 0x6e,
    0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4e, 0x65,
    0x74, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x39, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x58, 0x52,
    0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x31, 0x22, 0x20,
    0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49, 0x6e, 0x73,
    0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4e, 0x65, 0x74,
    0x49, 0x64, 0x3d, 0x22, 0x34, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x43, 0x72, 0x6f, 0x73,
    0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65,
    0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c,
    0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x52,
    0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x20, 0x57, 0x69, 0x64,
    0x74, 0x68, 0x3d, 0x22, 0x42, 0x69, 0x74, 0x22, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d,
    0x62, 0x65, 0x72, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65,
    0x72, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
    0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x4c, 0x23, 0x33, 0x34, 0x35, 0x22, 0x20,
    0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x3e, 0x3c,
    0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x58, 0x52,
    0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x36, 0x31, 0x22,
    0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49, 0x6e,
    0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65,
    0x74, 0x49, 0x64, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x43, 0x72, 0x6f, 0x73,
    0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65,
    0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x44, 0x49, 0x6e, 0x74, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c,
    0x61, 0x73, 0x73, 0x3d, 0x22, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x22, 0x3e, 0x3c,
    0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x4c,
    0x23, 0x33, 0x34, 0x35, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f,
    0x62, 0x61, 0x6c, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x44, 0x49, 0x6e, 0x74, 0x22,
    0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x3d, 0x22, 0x44, 0x65, 0x63, 0x5f, 0x73, 0x69, 0x67,
    0x6e, 0x65, 0x64, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44, 0x57, 0x6f, 0x72,
    0x64, 0x22, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x3d, 0x22, 0x35, 0x39, 0x30, 0x31, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f,
    0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c,
    0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e,
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e,
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x31, 0x22, 0x20,
    0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x3e, 0x3c,
    0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x58, 0x52,
    0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x31, 0x22, 0x20,
    0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49, 0x6e, 0x73,
    0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x74,
    0x49, 0x64, 0x3d, 0x22, 0x33, 0x33, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49,
    0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x55, 0x73, 0x61,
    0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75,
    0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d,
    0x22, 0x33, 0x39, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d,
    0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d,
    0x22, 0x52, 0x65, 0x61, 0x64, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69,
    0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x34, 0x30,
    0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49,
    0x64, 0x3d, 0x22, 0x37, 0x33, 0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65,
    0x61, 0x64, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d,
    0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x34, 0x31, 0x22, 0x20, 0x2f,
    0x3e, 0x3c, 0x2f, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x3e,
    0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70, 0x65,
    0x3d, 0x22, 0x52, 0x65, 0x61, 0x6c, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70,
    0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c,
    0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x52, 0x65,
    0x61, 0x6c, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x4d, 0x65, 0x6d, 0x6f, 0x72,
    0x79, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44, 0x57, 0x6f, 0x72, 0x64, 0x22,
    0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x35, 0x36, 0x37,
    0x22, 0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20,
    0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69,
    0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69,
    0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x54, 0x61, 0x67, 0x5f, 0x31, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47,
    0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x3e, 0x3c, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66,
    0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55,
    0x49, 0x64, 0x3d, 0x22, 0x31, 0x32, 0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x57,
    0x72, 0x69, 0x74, 0x65, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f,
    0x6e, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x36, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x55, 0x49, 0x64,
    0x3d, 0x22, 0x31, 0x38, 0x22, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61,
    0x64, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22,
    0x30, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x20, 0x2f, 0x3e,
    0x3c, 0x2f, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c,
    0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d,
    0x22, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20,
    0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65,
    0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41,
    0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x49, 0x6e, 0x74, 0x22,
    0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x4d, 0x65, 0x6d, 0x6f, 0x72, 0x79, 0x22, 0x20,
    0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x57, 0x6f, 0x72, 0x64, 0x22, 0x20, 0x42, 0x79, 0x74,
    0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x31, 0x36, 0x37, 0x22, 0x20, 0x42, 0x69,
    0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f,
    0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c,
    0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e
};

#define S7COMMP_DICTID_IntRefData_90000001  0xda4a88f4
static const char s7commp_dict_IntRefData_90000001[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e,
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x45, 0x6e, 0x64,
    0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x4c, 0x61, 0x62, 0x65, 0x6c, 0x22, 0x20,
    0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x32, 0x22, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x4c, 0x61, 0x62, 0x65,
    0x6c, 0x22, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64,
    0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c,
    0x65, 0x55, 0x6e, 0x69, 0x74, 0x20, 0x30, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22,
    0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x33,
    0x22, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61,
    0x73, 0x73, 0x3d, 0x22, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x55, 0x6e, 0x69, 0x74, 0x49,
    0x64, 0x65, 0x6e, 0x74, 0x22, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x55, 0x6e,
    0x69, 0x74, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e,
    0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63,
    0x65, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x30,
    0x31, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x55, 0x6e, 0x64, 0x65, 0x66, 0x22,
    0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x34, 0x22, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x42, 0x6c, 0x6f,
    0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x22,
    0x3e, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65,
    0x20, 0x52, 0x65, 0x66, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65,
    0x6e, 0x63, 0x65, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72,
    0x5f, 0x30, 0x31, 0x22, 0x20, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x31, 0x22, 0x20,
    0x43, 0x61, 0x6c, 0x6c, 0x65, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6c, 0x6f, 0x63,
    0x6b, 0x5f, 0x46, 0x43, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x6e,
    0x64, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x38, 0x30, 0x22, 0x20, 0x50, 0x61, 0x72, 0x61,
    0x6d, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x54, 0x53, 0x3d,
    0x22, 0x31, 0x32, 0x38, 0x36, 0x36, 0x30, 0x33, 0x37, 0x35, 0x36, 0x31, 0x32, 0x34, 0x31, 0x33,
    0x31, 0x37, 0x37, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e,
    0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43,
    0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20,
    0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x61, 0x67, 0x5f, 0x31, 0x22, 0x20, 0x53, 0x63, 0x6f,
    0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49,
    0x44, 0x3d, 0x22, 0x33, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70,
    0x65, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x2f, 0x3e,
    0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73,
    0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e,
    0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20,
    0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67,
    0x65, 0x3d, 0x22, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d,
    0x22, 0x42, 0x69, 0x74, 0x22, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
    0x3d, 0x22, 0x31, 0x22, 0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22,
    0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x54, 0x61, 0x67, 0x5f, 0x35, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d,
    0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22,
    0x37, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x20, 0x54,
    0x79, 0x70, 0x65, 0x3d, 0x22, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63,
    0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69,
    0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53,
    0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x54, 0x79, 0x70, 0x65,
    0x3d, 0x22, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x49, 0x6e,
    0x70, 0x75, 0x74, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x57, 0x6f, 0x72, 0x64,
    0x22, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22,
    0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x2f,
    0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e,
    0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54,
    0x61, 0x67, 0x5f, 0x31, 0x32, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c,
    0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x31, 0x33, 0x22,
    0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70,
    0x65, 0x3d, 0x22, 0x44, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d,
    0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x69,
    0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d,
    0x22, 0x44, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x49, 0x6e,
    0x70, 0x75, 0x74, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44, 0x57, 0x6f, 0x72,
    0x64, 0x22, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x31,
    0x22, 0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20,
    0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22,
    0x54, 0x61, 0x67, 0x5f, 0x33, 0x32, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47,
    0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x33, 0x34,
    0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79,
    0x70, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x6c, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63,
    0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69,
    0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53,
    0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x54, 0x79, 0x70, 0x65,
    0x3d, 0x22, 0x52, 0x65, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x4d,
    0x65, 0x6d, 0x6f, 0x72, 0x79, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44, 0x57,
    0x6f, 0x72, 0x64, 0x22, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d,
    0x22, 0x35, 0x36, 0x37, 0x22, 0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d,
    0x22, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c,
    0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61,
    0x6d, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x5f, 0x62, 0x6c,
    0x6f, 0x63, 0x6b, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x39, 0x31, 0x22, 0x20, 0x53,
    0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65,
    0x66, 0x49, 0x44, 0x3d, 0x22, 0x36, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54,
    0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x5f,
    0x46, 0x43, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75,
    0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x46, 0x43, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x22,
    0x3e, 0x20, 0x20, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22,
    0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f,
    0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x5f, 0x39, 0x31, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65,
    0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22,
    0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x46, 0x43, 0x22, 0x20, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72,
    0x3d, 0x22, 0x39, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
    0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20,
    0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x50, 0x5f, 0x31, 0x61, 0x22, 0x20, 0x53, 0x63, 0x6f,
    0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49,
    0x44, 0x3d, 0x22, 0x37, 0x39, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79,
    0x70, 0x65, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x44,
    0x42, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62,
    0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x4f, 0x70, 0x65, 0x72, 0x61, 0x6e, 0x64, 0x22, 0x3e,
    0x20, 0x20, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54,
    0x50, 0x5f, 0x31, 0x61, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f,
    0x62, 0x61, 0x6c, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x5f, 0x44, 0x42, 0x22, 0x20, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x33, 0x37, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64,
    0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x54, 0x23, 0x32, 0x73, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c,
    0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x38, 0x30, 0x22,
    0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x20, 0x54, 0x79, 0x70,
    0x65, 0x3d, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x43, 0x6f, 0x6e,
    0x73, 0x74, 0x61, 0x6e, 0x74, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61,
    0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x23, 0x32, 0x73, 0x22, 0x20, 0x53,
    0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x54, 0x79,
    0x70, 0x65, 0x3d, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x20, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74,
    0x3d, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44,
    0x57, 0x6f, 0x72, 0x64, 0x22, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x3d, 0x22, 0x44, 0x30, 0x30,
    0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x22, 0x20, 0x2f,
    0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e,
    0x74, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e,
    0x65, 0x72, 0x3e
};

#define S7COMMP_DICTID_IntRefData_98000001  0xb0155ff8
static const char s7commp_dict_IntRefData_98000001[] = {
    0x3c, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x41, 0x62, 0x73, 0x4f,
    0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x41, 0x62,
    0x73, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69,
    0x6c, 0x65, 0x41, 0x62, 0x73, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x3c, 0x4c, 0x61,
    0x62, 0x65, 0x6c, 0x3e, 0x54, 0x79, 0x70, 0x65, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x49, 0x64,
    0x3d, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x3c, 0x46, 0x42, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x3c, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e,
    0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x49,
    0x6e, 0x66, 0x6f, 0x20, 0x4f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x61, 0x6c, 0x50, 0x61, 0x72, 0x74,
    0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74,
    0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e, 0x3c, 0x46, 0x43, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x4c,
    0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x4f, 0x62, 0x6a, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x4e, 0x65,
    0x65, 0x64, 0x73, 0x49, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x3c, 0x41, 0x75,
    0x66, 0x44, 0x42, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x43, 0x72, 0x65, 0x61, 0x74, 0x69, 0x6f,
    0x6e, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x3d,
    0x22, 0x3c, 0x44, 0x65, 0x70, 0x44, 0x42, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x54, 0x65, 0x6d,
    0x70, 0x6c, 0x61, 0x74, 0x65, 0x52, 0x65, 0x66, 0x65, 0x72, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22,
    0x20, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69,
    0x65, 0x64, 0x54, 0x53, 0x3d, 0x22, 0x3c, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x65, 0x74, 0x65, 0x72,
    0x20, 0x41, 0x72, 0x72, 0x61, 0x79, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x3c, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x54, 0x53,
    0x3d, 0x22, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3c,
    0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
    0x55, 0x6e, 0x69, 0x74, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x53, 0x74, 0x72, 0x75, 0x63,
    0x74, 0x75, 0x72, 0x65, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x54, 0x53, 0x3d, 0x22,
    0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x20, 0x53, 0x65, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x20, 0x41, 0x72, 0x65, 0x61, 0x3d, 0x22, 0x20, 0x49, 0x6e,
    0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x3d, 0x22, 0x53, 0x37,
    0x5f, 0x56, 0x69, 0x73, 0x69, 0x62, 0x6c, 0x65, 0x22, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61,
    0x63, 0x65, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x3d, 0x22, 0x4d, 0x61, 0x6e, 0x64, 0x61, 0x74, 0x6f,
    0x72, 0x79, 0x2c, 0x20, 0x53, 0x37, 0x5f, 0x56, 0x69, 0x73, 0x69, 0x62, 0x6c, 0x65, 0x22, 0x3c,
    0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x52, 0x61, 0x6e,
    0x67, 0x65, 0x3d, 0x22, 0x20, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x72, 0x3d, 0x22, 0x20, 0x46, 0x6f, 0x72, 0x6d,
    0x61, 0x74, 0x3d, 0x22, 0x20, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x3d, 0x22, 0x20, 0x46, 0x6f, 0x72,
    0x6d, 0x61, 0x74, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x3d, 0x22, 0x20, 0x44, 0x62, 0x4e, 0x75, 0x6d,
    0x62, 0x65, 0x72, 0x3d, 0x22, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4f, 0x62, 0x6a, 0x65,
    0x63, 0x74, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x2f,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x43, 0x72, 0x6f, 0x73, 0x73, 0x52, 0x65, 0x66, 0x49,
    0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x4d, 0x66, 0x62,
    0x55, 0x44, 0x54, 0x20, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d,
    0x22, 0x20, 0x41, 0x62, 0x73, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x20, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x4d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, 0x72, 0x3d, 0x22, 0x20, 0x54,
    0x79, 0x70, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x20,
    0x2f, 0x3e, 0x3c, 0x58, 0x52, 0x65, 0x66, 0x49, 0x74, 0x65, 0x6d, 0x20, 0x53, 0x63, 0x6f, 0x70,
    0x65, 0x3d, 0x22, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
    0x22, 0x4c, 0x6f, 0x6b, 0x61, 0x6c, 0x22, 0x43, 0x6f, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x74, 0x22,
    0x20, 0x52, 0x65, 0x66, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x54, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x20, 0x55, 0x49,
    0x64, 0x3d, 0x22, 0x31, 0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x64,
    0x22, 0x4e, 0x6f, 0x6e, 0x65, 0x22, 0x4d, 0x75, 0x6c, 0x74, 0x69, 0x69, 0x6e, 0x73, 0x74, 0x61,
    0x6e, 0x63, 0x65, 0x22, 0x20, 0x49, 0x6e, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x74, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x20, 0x58, 0x52,
    0x65, 0x66, 0x48, 0x69, 0x64, 0x64, 0x65, 0x6e, 0x3d, 0x22, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x22,
    0x20, 0x55, 0x73, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x57, 0x72, 0x69, 0x74, 0x65, 0x22, 0x49, 0x6e,
    0x74, 0x22, 0x55, 0x49, 0x6e, 0x74, 0x22, 0x52, 0x65, 0x61, 0x6c, 0x22, 0x55, 0x53, 0x49, 0x6e,
    0x74, 0x22, 0x57, 0x6f, 0x72, 0x64, 0x22, 0x44, 0x49, 0x6e, 0x74, 0x22, 0x42, 0x6f, 0x6f, 0x6c,
    0x22, 0x53, 0x49, 0x6e, 0x74, 0x22, 0x42, 0x79, 0x74, 0x65, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22,
    0x55, 0x44, 0x49, 0x6e, 0x74, 0x22, 0x44, 0x57, 0x6f, 0x72, 0x64, 0x22, 0x43, 0x68, 0x61, 0x72,
    0x22, 0x44, 0x54, 0x4c, 0x22, 0x4c, 0x52, 0x65, 0x61, 0x6c, 0x22, 0x53, 0x74, 0x72, 0x69, 0x6e,
    0x67, 0x22, 0x74, 0x72, 0x75, 0x65, 0x22, 0x3d, 0x22, 0x3e
};

#define S7COMMP_DICTID_IntfDescTag_90000001  0xce9b821b
static const char s7commp_dict_IntfDescTag_90000001[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e,
    0x20, 0x20, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54,
    0x61, 0x67, 0x5f, 0x31, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f,
    0x62, 0x61, 0x6c, 0x22, 0x20, 0x4c, 0x49, 0x44, 0x3d, 0x22, 0x39, 0x22, 0x3e, 0x3c, 0x53, 0x69,
    0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x42, 0x6f, 0x6f, 0x6c, 0x3c, 0x2f, 0x53,
    0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70,
    0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d,
    0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d,
    0x62, 0x65, 0x72, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62,
    0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x42, 0x69,
    0x74, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x2f,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e,
    0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x61, 0x67, 0x5f, 0x32, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70,
    0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x64, 0x3d, 0x22,
    0x31, 0x32, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e,
    0x49, 0x6e, 0x74, 0x3c, 0x2f, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e,
    0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73,
    0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e,
    0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20,
    0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x57,
    0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x57, 0x6f, 0x72, 0x64, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67,
    0x65, 0x3d, 0x22, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20,
    0x20, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x61,
    0x67, 0x5f, 0x33, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62,
    0x61, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x64, 0x3d, 0x22, 0x32, 0x33, 0x22, 0x3e, 0x3c, 0x53, 0x69,
    0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x49, 0x6e, 0x74, 0x3c, 0x2f, 0x53,
    0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70,
    0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d,
    0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75,
    0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22,
    0x44, 0x57, 0x6f, 0x72, 0x64, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x49, 0x6e,
    0x70, 0x75, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e,
    0x20, 0x20, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x61, 0x67, 0x5f, 0x34, 0x22, 0x20,
    0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x4c,
    0x69, 0x64, 0x3d, 0x22, 0x33, 0x34, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54,
    0x79, 0x70, 0x65, 0x3e, 0x52, 0x65, 0x61, 0x6c, 0x3c, 0x2f, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65,
    0x54, 0x79, 0x70, 0x65, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62,
    0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63,
    0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d,
    0x22, 0x33, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44, 0x57, 0x6f, 0x72, 0x64,
    0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x20,
    0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x49,
    0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61,
    0x6d, 0x65, 0x3d, 0x22, 0x54, 0x61, 0x67, 0x5f, 0x35, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65,
    0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x64, 0x3d, 0x22, 0x34,
    0x35, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x42,
    0x6f, 0x6f, 0x6c, 0x3c, 0x2f, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e,
    0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73,
    0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e,
    0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20,
    0x42, 0x69, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x42, 0x79,
    0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x57, 0x69, 0x64,
    0x74, 0x68, 0x3d, 0x22, 0x42, 0x69, 0x74, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22,
    0x4f, 0x75, 0x74, 0x70, 0x75, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x20, 0x20, 0x3c,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x61, 0x67, 0x5f,
    0x36, 0x22, 0x20, 0x53, 0x63, 0x6f, 0x70, 0x65, 0x3d, 0x22, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c,
    0x22, 0x20, 0x4c, 0x69, 0x64, 0x3d, 0x22, 0x35, 0x36, 0x22, 0x3e, 0x3c, 0x53, 0x69, 0x6d, 0x70,
    0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x49, 0x6e, 0x74, 0x3c, 0x2f, 0x53, 0x69, 0x6d,
    0x70, 0x6c, 0x65, 0x54, 0x79, 0x70, 0x65, 0x3e, 0x3c, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20,
    0x53, 0x75, 0x62, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x3d, 0x22, 0x53, 0x69, 0x6d, 0x70, 0x6c, 0x65,
    0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x69, 0x6d, 0x70, 0x6c,
    0x65, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x20, 0x42, 0x79, 0x74, 0x65, 0x4e, 0x75, 0x6d, 0x62,
    0x65, 0x72, 0x3d, 0x22, 0x35, 0x22, 0x20, 0x57, 0x69, 0x64, 0x74, 0x68, 0x3d, 0x22, 0x44, 0x57,
    0x6f, 0x72, 0x64, 0x22, 0x20, 0x52, 0x61, 0x6e, 0x67, 0x65, 0x3d, 0x22, 0x4d, 0x65, 0x6d, 0x6f,
    0x72, 0x79, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20,
    0x20, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74,
    0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x3e
};

#define S7COMMP_DICTID_IntfDesc_90000001  0x4b8416f0
static const char s7commp_dict_IntfDesc_90000001[] = {
    0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31,
    0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x75, 0x74,
    0x66, 0x2d, 0x31, 0x36, 0x22, 0x3f, 0x3e, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22,
    0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x56,
    0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x3c, 0x53, 0x65,
    0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x53, 0x74, 0x61, 0x74,
    0x69, 0x63, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d,
    0x22, 0x39, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x53, 0x54, 0x41, 0x52, 0x54, 0x22,
    0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x20, 0x4c,
    0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x33, 0x32, 0x22,
    0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e,
    0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x52,
    0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69,
    0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x62, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49,
    0x64, 0x3d, 0x22, 0x31, 0x30, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x50, 0x52, 0x45,
    0x53, 0x45, 0x54, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x54, 0x69, 0x6d,
    0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x33, 0x32, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79,
    0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22,
    0x34, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f,
    0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x62, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e,
    0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x31, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x45, 0x4c, 0x41, 0x50, 0x53, 0x45, 0x44, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c,
    0x3d, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e,
    0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72,
    0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66,
    0x73, 0x65, 0x74, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63,
    0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64,
    0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x62, 0x22, 0x20, 0x2f, 0x3e, 0x20,
    0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x32, 0x22, 0x20,
    0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x52, 0x55, 0x4e, 0x4e, 0x49, 0x4e, 0x47, 0x22, 0x20, 0x53,
    0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62,
    0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c, 0x69,
    0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69, 0x74,
    0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x31, 0x32, 0x2e, 0x30, 0x22, 0x20, 0x52, 0x65,
    0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c,
    0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64,
    0x3d, 0x22, 0x31, 0x33, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x49, 0x4e, 0x22, 0x20,
    0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69,
    0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c,
    0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69,
    0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x31, 0x32, 0x2e, 0x31, 0x22, 0x20, 0x52,
    0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69,
    0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49,
    0x64, 0x3d, 0x22, 0x31, 0x34, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x51, 0x22, 0x20,
    0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69,
    0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c,
    0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69,
    0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x31, 0x32, 0x2e, 0x32, 0x22, 0x20, 0x52,
    0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69,
    0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30,
    0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49,
    0x64, 0x3d, 0x22, 0x31, 0x35, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x50, 0x41, 0x44,
    0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x79, 0x74, 0x65, 0x22, 0x20,
    0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x38, 0x22,
    0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e,
    0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x31, 0x33, 0x22, 0x20,
    0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74,
    0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c,
    0x49, 0x64, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x50, 0x41,
    0x44, 0x5f, 0x31, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x79, 0x74,
    0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x38, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f,
    0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x31,
    0x34, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f,
    0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e,
    0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x37, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x50, 0x41, 0x44, 0x5f, 0x32, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22,
    0x42, 0x79, 0x74, 0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69,
    0x7a, 0x65, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c,
    0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74,
    0x3d, 0x22, 0x31, 0x35, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d,
    0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22,
    0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x53,
    0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x53, 0x6f, 0x75, 0x72, 0x63,
    0x65, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x74, 0x61, 0x72, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73,
    0x3e, 0x3c, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x65, 0x6e, 0x74,
    0x72, 0x69, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72,
    0x79, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x53, 0x74,
    0x61, 0x72, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x42, 0x6c, 0x6f, 0x63,
    0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x3e, 0x3c, 0x3f, 0x78, 0x6d, 0x6c,
    0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65,
    0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x75, 0x74, 0x66, 0x2d, 0x31, 0x36, 0x22,
    0x3f, 0x3e, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63,
    0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e,
    0x20, 0x20, 0x3c, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
    0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x78, 0x74, 0x46, 0x72, 0x65, 0x65,
    0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x30, 0x22, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63,
    0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x53,
    0x69, 0x7a, 0x65, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65,
    0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
    0x2e, 0x4c, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22,
    0x30, 0x22, 0x3e, 0x3c, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65,
    0x3d, 0x22, 0x49, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x53, 0x65, 0x63, 0x74,
    0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x4f, 0x75, 0x74, 0x70, 0x75, 0x74,
    0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x49, 0x6e, 0x4f, 0x75, 0x74, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x53, 0x65, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54, 0x65, 0x6d, 0x70, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65,
    0x3d, 0x22, 0x52, 0x65, 0x74, 0x75, 0x72, 0x6e, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e,
    0x65, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x52, 0x65, 0x74, 0x5f, 0x56, 0x61, 0x6c, 0x22,
    0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x56, 0x6f, 0x69, 0x64, 0x22, 0x20, 0x4c,
    0x49, 0x64, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x69, 0x62, 0x69,
    0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0x20, 0x52, 0x65,
    0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c,
    0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x30, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f,
    0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30,
    0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3e, 0x20, 0x20,
    0x3c, 0x2f, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x3e, 0x3c, 0x2f, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x3e, 0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20,
    0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e,
    0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d, 0x22, 0x75, 0x74, 0x66, 0x2d, 0x31, 0x36, 0x22, 0x3f,
    0x3e, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65,
    0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20,
    0x20, 0x3c, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3d, 0x22, 0x54,
    0x72, 0x75, 0x65, 0x22, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x53, 0x69, 0x7a, 0x65,
    0x3d, 0x22, 0x30, 0x22, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x30, 0x22, 0x20, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x53, 0x69, 0x7a, 0x65,
    0x3d, 0x22, 0x30, 0x22, 0x20, 0x4e, 0x65, 0x78, 0x74, 0x46, 0x72, 0x65, 0x65, 0x4c, 0x49, 0x64,
    0x3d, 0x22, 0x31, 0x31, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x53,
    0x74, 0x61, 0x63, 0x6b, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x30, 0x22, 0x3e,
    0x3c, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x54,
    0x65, 0x6d, 0x70, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64,
    0x3d, 0x22, 0x39, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x66, 0x69, 0x72, 0x73, 0x74,
    0x5f, 0x73, 0x63, 0x61, 0x6e, 0x22, 0x20, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x69, 0x62, 0x69,
    0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0x20, 0x52, 0x65,
    0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c,
    0x65, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22,
    0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x22,
    0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22,
    0x31, 0x30, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x72, 0x65, 0x6d, 0x61, 0x6e, 0x65,
    0x6e, 0x63, 0x65, 0x22, 0x20, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x69, 0x62, 0x69, 0x6c, 0x69,
    0x74, 0x79, 0x3d, 0x22, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61,
    0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22,
    0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x52,
    0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x22, 0x20, 0x2f,
    0x3e, 0x3c, 0x2f, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x53,
    0x6f, 0x75, 0x72, 0x63, 0x65, 0x3e, 0x3c, 0x2f, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74,
    0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x3e, 0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e, 0x63, 0x6f, 0x64,
    0x69, 0x6e, 0x67, 0x3d, 0x22, 0x75, 0x74, 0x66, 0x2d, 0x31, 0x36, 0x22, 0x3f, 0x3e, 0x3c, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x20, 0x56, 0x65,
    0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53,
    0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31,
    0x2e, 0x30, 0x22, 0x20, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x32, 0x37, 0x36, 0x38, 0x22, 0x20, 0x52, 0x65, 0x74, 0x61, 0x69, 0x6e, 0x53, 0x69, 0x7a,
    0x65, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x53, 0x69,
    0x7a, 0x65, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x4e, 0x65, 0x78, 0x74, 0x46, 0x72, 0x65, 0x65,
    0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x32, 0x38, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72,
    0x79, 0x2e, 0x4c, 0x53, 0x74, 0x61, 0x63, 0x6b, 0x42, 0x69, 0x74, 0x73, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x30, 0x22, 0x3e, 0x3c, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x53, 0x74, 0x61, 0x74, 0x69, 0x63, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69,
    0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x31, 0x22, 0x20, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x69,
    0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0x20,
    0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74,
    0x69, 0x6c, 0x65, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x49, 0x6e, 0x74,
    0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22,
    0x31, 0x36, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f,
    0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30,
    0x22, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x3d, 0x22, 0x31, 0x32, 0x22, 0x20, 0x52,
    0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x35, 0x22, 0x20, 0x2f,
    0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x30,
    0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x32, 0x22, 0x20,
    0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x69, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50,
    0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65,
    0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62,
    0x6f, 0x6c, 0x3d, 0x22, 0x52, 0x65, 0x61, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72,
    0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72,
    0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f,
    0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x32, 0x22, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61,
    0x6c, 0x3d, 0x22, 0x31, 0x2e, 0x35, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x38, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e,
    0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x31, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d,
    0x22, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x33, 0x22, 0x20, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x69,
    0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x22, 0x20,
    0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74,
    0x69, 0x6c, 0x65, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f,
    0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d,
    0x22, 0x31, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f,
    0x75, 0x74, 0x2e, 0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x36, 0x2e,
    0x30, 0x22, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x3d, 0x22, 0x22, 0x20, 0x52, 0x49,
    0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e,
    0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x35, 0x22,
    0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x34, 0x22, 0x20, 0x41,
    0x63, 0x63, 0x65, 0x73, 0x73, 0x69, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50, 0x75,
    0x62, 0x6c, 0x69, 0x63, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d,
    0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f,
    0x6c, 0x3d, 0x22, 0x54, 0x69, 0x6d, 0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
    0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x33, 0x32, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61,
    0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66,
    0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x31, 0x38, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30,
    0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x62, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c,
    0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x39, 0x22, 0x20, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x35, 0x22, 0x20, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x69, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x3d, 0x22, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63,
    0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c,
    0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x57,
    0x6f, 0x72, 0x64, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a,
    0x65, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c,
    0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74,
    0x3d, 0x22, 0x33, 0x30, 0x22, 0x20, 0x49, 0x6e, 0x69, 0x74, 0x69, 0x61, 0x6c, 0x3d, 0x22, 0x31,
    0x32, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30,
    0x34, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3e, 0x20,
    0x20, 0x3c, 0x2f, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x74, 0x61,
    0x72, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x3e, 0x3c, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f,
    0x6e, 0x61, 0x72, 0x79, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x64,
    0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65,
    0x73, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x53, 0x74, 0x61, 0x72, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65,
    0x73, 0x3e, 0x3c, 0x2f, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61,
    0x63, 0x65, 0x3e, 0x3c, 0x3f, 0x78, 0x6d, 0x6c, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x20, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x3d,
    0x22, 0x75, 0x74, 0x66, 0x2d, 0x31, 0x36, 0x22, 0x3f, 0x3e, 0x3c, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
    0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x6f, 0x75, 0x72, 0x63,
    0x65, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e,
    0x3c, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x53,
    0x74, 0x61, 0x74, 0x69, 0x63, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c,
    0x49, 0x64, 0x3d, 0x22, 0x39, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x43, 0x4f, 0x55,
    0x4e, 0x54, 0x5f, 0x55, 0x50, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42,
    0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a,
    0x65, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61,
    0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22,
    0x30, 0x2e, 0x30, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22,
    0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30,
    0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c,
    0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x30, 0x22, 0x20, 0x4e, 0x61, 0x6d,
    0x65, 0x3d, 0x22, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x5f, 0x44, 0x4f, 0x57, 0x4e, 0x22, 0x20, 0x53,
    0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62,
    0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c, 0x69,
    0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69, 0x74,
    0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20, 0x52, 0x65, 0x6d,
    0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65,
    0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
    0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d,
    0x22, 0x31, 0x31, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x52, 0x45, 0x53, 0x45, 0x54,
    0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20,
    0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x22,
    0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e,
    0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30, 0x2e, 0x32, 0x22, 0x20,
    0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74,
    0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c,
    0x49, 0x64, 0x3d, 0x22, 0x31, 0x32, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x4c, 0x4f,
    0x41, 0x44, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c,
    0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22,
    0x31, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75,
    0x74, 0x2e, 0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30, 0x2e, 0x33,
    0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c,
    0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30,
    0x30, 0x30, 0x30, 0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65,
    0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x33, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22,
    0x51, 0x5f, 0x55, 0x50, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x42, 0x6f,
    0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65,
    0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79,
    0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x30,
    0x2e, 0x34, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56,
    0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78,
    0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69,
    0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x34, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65,
    0x3d, 0x22, 0x51, 0x5f, 0x44, 0x4f, 0x57, 0x4e, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c,
    0x3d, 0x22, 0x42, 0x6f, 0x6f, 0x6c, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e,
    0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
    0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x69, 0x74, 0x4f, 0x66, 0x66, 0x73, 0x65,
    0x74, 0x3d, 0x22, 0x30, 0x2e, 0x35, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63,
    0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64,
    0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20,
    0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x35, 0x22, 0x20,
    0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x50, 0x41, 0x44, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f,
    0x6c, 0x3d, 0x22, 0x42, 0x79, 0x74, 0x65, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
    0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x38, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72,
    0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66,
    0x73, 0x65, 0x74, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63,
    0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64,
    0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x22, 0x20, 0x2f, 0x3e, 0x20,
    0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20, 0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x20,
    0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x50, 0x52, 0x45, 0x53, 0x45, 0x54, 0x5f, 0x56, 0x41, 0x4c,
    0x55, 0x45, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x3d, 0x22, 0x49, 0x6e, 0x74, 0x22,
    0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31,
    0x36, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75,
    0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66, 0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x32, 0x22,
    0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e, 0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61,
    0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x35, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4c, 0x69, 0x6e, 0x65, 0x20,
    0x4c, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x37, 0x22, 0x20, 0x4e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x43,
    0x4f, 0x55, 0x4e, 0x54, 0x5f, 0x56, 0x41, 0x4c, 0x55, 0x45, 0x22, 0x20, 0x53, 0x79, 0x6d, 0x62,
    0x6f, 0x6c, 0x3d, 0x22, 0x49, 0x6e, 0x74, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79,
    0x2e, 0x53, 0x69, 0x7a, 0x65, 0x3d, 0x22, 0x31, 0x36, 0x22, 0x20, 0x4c, 0x69, 0x62, 0x72, 0x61,
    0x72, 0x79, 0x2e, 0x4c, 0x61, 0x79, 0x6f, 0x75, 0x74, 0x2e, 0x42, 0x79, 0x74, 0x65, 0x4f, 0x66,
    0x66, 0x73, 0x65, 0x74, 0x3d, 0x22, 0x34, 0x22, 0x20, 0x52, 0x65, 0x6d, 0x61, 0x6e, 0x65, 0x6e,
    0x63, 0x65, 0x3d, 0x22, 0x56, 0x6f, 0x6c, 0x61, 0x74, 0x69, 0x6c, 0x65, 0x22, 0x20, 0x52, 0x49,
    0x64, 0x3d, 0x22, 0x30, 0x78, 0x32, 0x30, 0x30, 0x30, 0x30, 0x30, 0x35, 0x22, 0x20, 0x2f, 0x3e,
    0x3c, 0x2f, 0x53, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3e, 0x20, 0x20, 0x3c, 0x2f, 0x53, 0x6f,
    0x75, 0x72, 0x63, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x53, 0x74, 0x61, 0x72, 0x74, 0x56, 0x61, 0x6c,
    0x75, 0x65, 0x73, 0x3e, 0x3c, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x5f,
    0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x64, 0x69, 0x63, 0x74, 0x69, 0x6f,
    0x6e, 0x61, 0x72, 0x79, 0x5f, 0x65, 0x6e, 0x74, 0x72, 0x69, 0x65, 0x73, 0x3e, 0x20, 0x20, 0x3c,
    0x2f, 0x53, 0x74, 0x61, 0x72, 0x74, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x73, 0x3e, 0x3c, 0x2f, 0x42,
    0x6c, 0x6f, 0x63, 0x6b, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x3e
};

#define S7COMMP_DICTID_TagLineComm_90000001  0xe2729ea1
static const char s7commp_dict_TagLineComm_90000001[] = {
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61,
    0x72, 0x79, 0x3e, 0x3c, 0x54, 0x61, 0x67, 0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65,
    0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66,
    0x49, 0x44, 0x3d, 0x22, 0x31, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72,
    0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55,
    0x53, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e,
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22,
    0x31, 0x31, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c,
    0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x3e,
    0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x68, 0x65, 0x20, 0x69, 0x6e,
    0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x66, 0x6f,
    0x72, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x61, 0x6e,
    0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43,
    0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x20,
    0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x31, 0x31, 0x31, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63,
    0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d,
    0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x22, 0x3e, 0x64, 0x69, 0x65, 0x73, 0x20, 0x69, 0x73, 0x74,
    0x20, 0x65, 0x69, 0x6e, 0x20, 0x64, 0x65, 0x72, 0x20, 0x64, 0x69, 0x65, 0x20, 0x64, 0x61, 0x73,
    0x20, 0x69, 0x6d, 0x20, 0x6e, 0x61, 0x63, 0x68, 0x20, 0x65, 0x69, 0x6e, 0x65, 0x6e, 0x20, 0x6b,
    0x61, 0x6e, 0x6e, 0x20, 0x73, 0x65, 0x69, 0x6e, 0x20, 0x66, 0xc3, 0xbc, 0x72, 0x20, 0x73, 0x69,
    0x6e, 0x64, 0x20, 0x4e, 0x65, 0x74, 0x7a, 0x77, 0x65, 0x72, 0x6b, 0x20, 0x75, 0x6e, 0x64, 0x3c,
    0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d,
    0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x2f, 0x54, 0x61, 0x67, 0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f,
    0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74,
    0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d,
    0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x20, 0x20,
    0x3c, 0x54, 0x61, 0x67, 0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73,
    0x20, 0x2f, 0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74,
    0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e
};

#define S7COMMP_DICTID_LineComm_90000001  0x79b2bda3
static const char s7commp_dict_LineComm_90000001[] = {
    0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61,
    0x72, 0x79, 0x3e, 0x3c, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x4c, 0x69, 0x6e,
    0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65,
    0x6e, 0x74, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x31, 0x22, 0x20, 0x4c, 0x69, 0x6e, 0x65, 0x49,
    0x64, 0x3d, 0x22, 0x33, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79,
    0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53,
    0x22, 0x3e, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x69, 0x6e, 0x20, 0x74, 0x6f, 0x20, 0x61, 0x6e, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20,
    0x66, 0x6f, 0x72, 0x20, 0x61, 0x72, 0x65, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20,
    0x61, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x3e, 0x20,
    0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65,
    0x6e, 0x74, 0x20, 0x55, 0x49, 0x64, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x4c, 0x69, 0x6e, 0x65, 0x49,
    0x64, 0x3d, 0x22, 0x32, 0x22, 0x3e, 0x3c, 0x44, 0x69, 0x63, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79,
    0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53,
    0x22, 0x3e, 0x64, 0x69, 0x65, 0x73, 0x20, 0x69, 0x73, 0x74, 0x20, 0x65, 0x69, 0x6e, 0x20, 0x64,
    0x65, 0x72, 0x20, 0x64, 0x69, 0x65, 0x20, 0x64, 0x61, 0x73, 0x20, 0x69, 0x6d, 0x20, 0x6e, 0x61,
    0x63, 0x68, 0x20, 0x65, 0x69, 0x6e, 0x65, 0x6e, 0x20, 0x6b, 0x61, 0x6e, 0x6e, 0x20, 0x73, 0x65,
    0x69, 0x6e, 0x20, 0x66, 0xc3, 0xbc, 0x72, 0x20, 0x73, 0x69, 0x6e, 0x64, 0x20, 0x4e, 0x65, 0x74,
    0x7a, 0x77, 0x65, 0x72, 0x6b, 0x20, 0x75, 0x6e, 0x64, 0x3c, 0x2f, 0x44, 0x69, 0x63, 0x74, 0x45,
    0x6e, 0x74, 0x72, 0x79, 0x3e, 0x20, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x3e,
    0x3c, 0x2f, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x4c, 0x69, 0x6e, 0x65, 0x43,
    0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3e, 0x3c, 0x42, 0x6f, 0x64, 0x79, 0x4c, 0x69, 0x6e,
    0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x2f, 0x3e, 0x20, 0x3c, 0x2f, 0x43,
    0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79,
    0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e,
    0x61, 0x72, 0x79, 0x3e, 0x3c, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x4c, 0x69,
    0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x2f, 0x3e, 0x3c, 0x42, 0x6f,
    0x64, 0x79, 0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x2f,
    0x3e, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69, 0x6f,
    0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61,
    0x63, 0x65, 0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x2f,
    0x3e, 0x20, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69,
    0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e
};

#define S7COMMP_DICTID_LineComm_98000001  0x3c55436a
static const char s7commp_dict_LineComm_98000001[] = {
    0x55, 0x49, 0x64, 0x3d, 0x22, 0x20, 0x52, 0x65, 0x66, 0x49, 0x44, 0x3d, 0x22, 0x3c, 0x50, 0x61,
    0x72, 0x74, 0x3e, 0x35, 0x31, 0x3a, 0x35, 0x32, 0x3a, 0x35, 0x33, 0x3a, 0x35, 0x34, 0x3a, 0x35,
    0x35, 0x3c, 0x42, 0x6f, 0x64, 0x79, 0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e,
    0x74, 0x73, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x44, 0x69, 0x63, 0x74, 0x69,
    0x6f, 0x6e, 0x61, 0x72, 0x79, 0x3e, 0x3c, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65,
    0x4c, 0x69, 0x6e, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x3c, 0x50, 0x61, 0x72,
    0x74, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x32, 0x2e, 0x30, 0x22, 0x20,
    0x49, 0x44, 0x3d, 0x22, 0x20, 0x4b, 0x69, 0x6e, 0x64, 0x3d, 0x22, 0x20, 0x50, 0x61, 0x72, 0x65,
    0x6e, 0x74, 0x49, 0x44, 0x3d, 0x22, 0x3c, 0x43, 0x6f, 0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x43, 0x6f,
    0x6d, 0x6d, 0x65, 0x6e, 0x74, 0x49, 0x44, 0x3d, 0x22, 0x20, 0x50, 0x61, 0x74, 0x68, 0x3d, 0x22,
    0x20, 0x66, 0x72, 0x2d, 0x46, 0x52, 0x69, 0x74, 0x2d, 0x49, 0x54, 0x3c, 0x44, 0x69, 0x63, 0x74,
    0x45, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3d, 0x22,
    0x64, 0x65, 0x2d, 0x44, 0x45, 0x22, 0x65, 0x6e, 0x2d, 0x55, 0x53, 0x3d, 0x22, 0x3e
};

#define S7COMMP_DICTID_IdentES_90000001  0xdf91b6bb
static const char s7commp_dict_IdentES_90000001[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75,
    0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x46, 0x43, 0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75,
    0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54,
    0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x43, 0x6f, 0x64, 0x65, 0x42, 0x6c, 0x6f, 0x63,
    0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70,
    0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
    0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x36,
    0x34, 0x30, 0x30, 0x30, 0x36, 0x37, 0x31, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
    0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62,
    0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65,
    0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61,
    0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22,
    0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x74,
    0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53,
    0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20,
    0x20, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x42,
    0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20,
    0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e,
    0x44, 0x61, 0x74, 0x61, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f,
    0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20,
    0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33,
    0x37, 0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x38, 0x31, 0x33, 0x34, 0x35, 0x39, 0x37, 0x35, 0x3c,
    0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c,
    0x44, 0x61, 0x74, 0x61, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x20, 0x74, 0x79,
    0x70, 0x65, 0x3d, 0x22, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x44, 0x42, 0x22, 0x20, 0x6f, 0x66,
    0x74, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x55, 0x6e, 0x64, 0x65, 0x66, 0x22, 0x20, 0x6f, 0x66, 0x6e,
    0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4f,
    0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73,
    0x73, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d,
    0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x48,
    0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
    0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53,
    0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x74, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79,
    0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d,
    0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62,
    0x74, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x42, 0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62,
    0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79,
    0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x44, 0x61, 0x74, 0x61, 0x42, 0x6c, 0x6f, 0x63, 0x6b,
    0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65,
    0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54,
    0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x38, 0x37,
    0x31, 0x32, 0x37, 0x37, 0x34, 0x33, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54,
    0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x44, 0x61, 0x74, 0x61, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
    0x54, 0x79, 0x70, 0x65, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x49, 0x44, 0x42, 0x6f, 0x66,
    0x53, 0x44, 0x54, 0x22, 0x20, 0x6f, 0x66, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x53, 0x44, 0x54,
    0x22, 0x20, 0x6f, 0x66, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x6f,
    0x66, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x49, 0x45, 0x43, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54,
    0x45, 0x52, 0x22, 0x20, 0x6f, 0x66, 0x54, 0x79, 0x70, 0x65, 0x54, 0x79, 0x70, 0x65, 0x47, 0x75,
    0x69, 0x64, 0x3d, 0x22, 0x37, 0x65, 0x39, 0x33, 0x66, 0x63, 0x33, 0x34, 0x2d, 0x35, 0x33, 0x39,
    0x38, 0x2d, 0x34, 0x38, 0x62, 0x31, 0x2d, 0x61, 0x33, 0x31, 0x37, 0x2d, 0x33, 0x38, 0x62, 0x38,
    0x63, 0x64, 0x33, 0x37, 0x62, 0x38, 0x65, 0x38, 0x22, 0x20, 0x6f, 0x66, 0x54, 0x79, 0x70, 0x65,
    0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x47, 0x75, 0x69, 0x64, 0x3d, 0x22, 0x30, 0x30, 0x37,
    0x65, 0x64, 0x37, 0x63, 0x36, 0x2d, 0x35, 0x31, 0x62, 0x64, 0x2d, 0x34, 0x30, 0x35, 0x63, 0x2d,
    0x62, 0x37, 0x65, 0x35, 0x2d, 0x65, 0x31, 0x66, 0x64, 0x33, 0x66, 0x32, 0x35, 0x61, 0x36, 0x63,
    0x30, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62,
    0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x54, 0x72, 0x75, 0x65, 0x3c,
    0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63,
    0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74,
    0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20,
    0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x66, 0x61,
    0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f,
    0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53,
    0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20,
    0x20, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x4f, 0x42,
    0x2e, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x43, 0x79, 0x63, 0x6c, 0x65, 0x3c, 0x2f, 0x43,
    0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x62,
    0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x43, 0x6f, 0x64,
    0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65,
    0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f,
    0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30, 0x36,
    0x33, 0x35, 0x34, 0x34, 0x32, 0x34, 0x35, 0x34, 0x36, 0x35, 0x31, 0x39, 0x3c, 0x2f, 0x43, 0x6f,
    0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x6e, 0x6c,
    0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e,
    0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f,
    0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61,
    0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d,
    0x22, 0x30, 0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73,
    0x74, 0x65, 0x6d, 0x3e, 0x74, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e
};

#define S7COMMP_DICTID_IdentES_90000002  0x81d8db20
static const char s7commp_dict_IdentES_90000002[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75,
    0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x46, 0x43, 0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75,
    0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54,
    0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x43, 0x6f, 0x64, 0x65, 0x42, 0x6c, 0x6f, 0x63,
    0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70,
    0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
    0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x36,
    0x34, 0x30, 0x30, 0x30, 0x36, 0x37, 0x31, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65,
    0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62,
    0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65,
    0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63,
    0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x65, 0x63, 0x43, 0x68, 0x65, 0x63, 0x6b,
    0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x49, 0x65, 0x63, 0x43, 0x68, 0x65, 0x63, 0x6b,
    0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56,
    0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20,
    0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x74, 0x72, 0x75, 0x65, 0x3c,
    0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e,
    0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72,
    0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f,
    0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x42, 0x3c, 0x2f, 0x43, 0x6f,
    0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x62, 0x6a,
    0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x44, 0x61, 0x74, 0x61,
    0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63,
    0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x6d,
    0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30, 0x36, 0x33,
    0x35, 0x33, 0x35, 0x38, 0x31, 0x33, 0x34, 0x35, 0x39, 0x37, 0x35, 0x3c, 0x2f, 0x43, 0x6f, 0x6d,
    0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x44, 0x61, 0x74, 0x61,
    0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x22,
    0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x44, 0x42, 0x22, 0x20, 0x6f, 0x66, 0x74, 0x79, 0x70, 0x65,
    0x3d, 0x22, 0x55, 0x6e, 0x64, 0x65, 0x66, 0x22, 0x20, 0x6f, 0x66, 0x6e, 0x75, 0x6d, 0x62, 0x65,
    0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x4f, 0x6e, 0x6c, 0x79, 0x53,
    0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x46, 0x61,
    0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69,
    0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x65, 0x63, 0x43, 0x68,
    0x65, 0x63, 0x6b, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x49, 0x65, 0x63, 0x43, 0x68,
    0x65, 0x63, 0x6b, 0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74,
    0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20,
    0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x74, 0x72,
    0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f, 0x49,
    0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20,
    0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x20, 0x20,
    0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x42, 0x3c,
    0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20, 0x3c,
    0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x44,
    0x61, 0x74, 0x61, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62,
    0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20, 0x3c,
    0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37,
    0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x38, 0x37, 0x31, 0x32, 0x37, 0x37, 0x34, 0x33, 0x3c, 0x2f,
    0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c, 0x44,
    0x61, 0x74, 0x61, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x20, 0x74, 0x79, 0x70,
    0x65, 0x3d, 0x22, 0x49, 0x44, 0x42, 0x6f, 0x66, 0x53, 0x44, 0x54, 0x22, 0x20, 0x6f, 0x66, 0x74,
    0x79, 0x70, 0x65, 0x3d, 0x22, 0x53, 0x44, 0x54, 0x22, 0x20, 0x6f, 0x66, 0x6e, 0x75, 0x6d, 0x62,
    0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x6f, 0x66, 0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x22, 0x49,
    0x45, 0x43, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x45, 0x52, 0x22, 0x20, 0x6f, 0x66, 0x54, 0x79,
    0x70, 0x65, 0x54, 0x79, 0x70, 0x65, 0x47, 0x75, 0x69, 0x64, 0x3d, 0x22, 0x37, 0x65, 0x39, 0x33,
    0x66, 0x63, 0x33, 0x34, 0x2d, 0x35, 0x33, 0x39, 0x38, 0x2d, 0x34, 0x38, 0x62, 0x31, 0x2d, 0x61,
    0x33, 0x31, 0x37, 0x2d, 0x33, 0x38, 0x62, 0x38, 0x63, 0x64, 0x33, 0x37, 0x62, 0x38, 0x65, 0x38,
    0x22, 0x20, 0x6f, 0x66, 0x54, 0x79, 0x70, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x47,
    0x75, 0x69, 0x64, 0x3d, 0x22, 0x30, 0x30, 0x37, 0x65, 0x64, 0x37, 0x63, 0x36, 0x2d, 0x35, 0x31,
    0x62, 0x64, 0x2d, 0x34, 0x30, 0x35, 0x63, 0x2d, 0x62, 0x37, 0x65, 0x35, 0x2d, 0x65, 0x31, 0x66,
    0x64, 0x33, 0x66, 0x32, 0x35, 0x61, 0x36, 0x63, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c,
    0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x3e, 0x54, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d,
    0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c, 0x49,
    0x65, 0x63, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x3e, 0x54, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x65,
    0x63, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
    0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e,
    0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d,
    0x3e, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d,
    0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e,
    0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30,
    0x22, 0x3e, 0x20, 0x20, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65,
    0x3e, 0x4f, 0x42, 0x2e, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x43, 0x79, 0x63, 0x6c, 0x65,
    0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x20, 0x20,
    0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e,
    0x43, 0x6f, 0x64, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f,
    0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x20, 0x20,
    0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33,
    0x37, 0x30, 0x36, 0x33, 0x35, 0x34, 0x34, 0x32, 0x34, 0x35, 0x34, 0x36, 0x35, 0x31, 0x39, 0x3c,
    0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x20, 0x20, 0x3c,
    0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79,
    0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x20, 0x20, 0x3c,
    0x49, 0x65, 0x63, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f,
    0x49, 0x65, 0x63, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x3e, 0x20, 0x20, 0x3c, 0x48, 0x65, 0x61, 0x64,
    0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22,
    0x30, 0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x20, 0x20, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x3e, 0x74, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e
};

#define S7COMMP_DICTID_IdentES_98000001  0x5814b03b
static const char s7commp_dict_IdentES_98000001[] = {
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74,
    0x79, 0x70, 0x65, 0x3e, 0x46, 0x43, 0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74,
    0x79, 0x70, 0x65, 0x3e, 0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49,
    0x6e, 0x66, 0x6f, 0x3e, 0x43, 0x6f, 0x64, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74,
    0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66,
    0x6f, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36,
    0x33, 0x33, 0x37, 0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x36, 0x34, 0x30, 0x30, 0x30, 0x36, 0x37,
    0x31, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x3c,
    0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65,
    0x73, 0x73, 0x3e, 0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79,
    0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x48, 0x65,
    0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74,
    0x65, 0x6d, 0x3e, 0x74, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65,
    0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e,
    0x30, 0x22, 0x3e, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e,
    0x44, 0x42, 0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e,
    0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e,
    0x44, 0x61, 0x74, 0x61, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f,
    0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x43,
    0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30,
    0x36, 0x33, 0x35, 0x33, 0x35, 0x38, 0x31, 0x33, 0x34, 0x35, 0x39, 0x37, 0x35, 0x3c, 0x2f, 0x43,
    0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x3c, 0x44, 0x61, 0x74, 0x61,
    0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79, 0x70, 0x65, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x22,
    0x53, 0x68, 0x61, 0x72, 0x65, 0x64, 0x44, 0x42, 0x22, 0x20, 0x6f, 0x66, 0x74, 0x79, 0x70, 0x65,
    0x3d, 0x22, 0x55, 0x6e, 0x64, 0x65, 0x66, 0x22, 0x20, 0x6f, 0x66, 0x6e, 0x75, 0x6d, 0x62, 0x65,
    0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d,
    0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x46, 0x61, 0x6c, 0x73,
    0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41,
    0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74,
    0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20,
    0x2f, 0x3e, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x74, 0x72, 0x75, 0x65,
    0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65,
    0x6e, 0x74, 0x45, 0x53, 0x3e, 0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65,
    0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x3c, 0x43, 0x6f, 0x72,
    0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x44, 0x42, 0x3c, 0x2f, 0x43, 0x6f, 0x72,
    0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65, 0x3e, 0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74,
    0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x44, 0x61, 0x74, 0x61, 0x42, 0x6c, 0x6f,
    0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79,
    0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54,
    0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37, 0x30, 0x36, 0x33, 0x35, 0x33, 0x35, 0x38, 0x37,
    0x31, 0x32, 0x37, 0x37, 0x34, 0x33, 0x3c, 0x2f, 0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54,
    0x69, 0x6d, 0x65, 0x3e, 0x3c, 0x44, 0x61, 0x74, 0x61, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x54, 0x79,
    0x70, 0x65, 0x20, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x49, 0x44, 0x42, 0x6f, 0x66, 0x53, 0x44,
    0x54, 0x22, 0x20, 0x6f, 0x66, 0x74, 0x79, 0x70, 0x65, 0x3d, 0x22, 0x53, 0x44, 0x54, 0x22, 0x20,
    0x6f, 0x66, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x3d, 0x22, 0x30, 0x22, 0x20, 0x6f, 0x66, 0x6e,
    0x61, 0x6d, 0x65, 0x3d, 0x22, 0x49, 0x45, 0x43, 0x5f, 0x43, 0x4f, 0x55, 0x4e, 0x54, 0x45, 0x52,
    0x22, 0x20, 0x6f, 0x66, 0x54, 0x79, 0x70, 0x65, 0x54, 0x79, 0x70, 0x65, 0x47, 0x75, 0x69, 0x64,
    0x3d, 0x22, 0x37, 0x65, 0x39, 0x33, 0x66, 0x63, 0x33, 0x34, 0x2d, 0x35, 0x33, 0x39, 0x38, 0x2d,
    0x34, 0x38, 0x62, 0x31, 0x2d, 0x61, 0x33, 0x31, 0x37, 0x2d, 0x33, 0x38, 0x62, 0x38, 0x63, 0x64,
    0x33, 0x37, 0x62, 0x38, 0x65, 0x38, 0x22, 0x20, 0x6f, 0x66, 0x54, 0x79, 0x70, 0x65, 0x56, 0x65,
    0x72, 0x73, 0x69, 0x6f, 0x6e, 0x47, 0x75, 0x69, 0x64, 0x3d, 0x22, 0x30, 0x30, 0x37, 0x65, 0x64,
    0x37, 0x63, 0x36, 0x2d, 0x35, 0x31, 0x62, 0x64, 0x2d, 0x34, 0x30, 0x35, 0x63, 0x2d, 0x62, 0x37,
    0x65, 0x35, 0x2d, 0x65, 0x31, 0x66, 0x64, 0x33, 0x66, 0x32, 0x35, 0x61, 0x36, 0x63, 0x30, 0x22,
    0x20, 0x2f, 0x3e, 0x3c, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63,
    0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x54, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c,
    0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e,
    0x3c, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73,
    0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30, 0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x49, 0x73, 0x53,
    0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53,
    0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c, 0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e,
    0x3c, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x20, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
    0x3d, 0x22, 0x31, 0x2e, 0x30, 0x22, 0x3e, 0x3c, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74,
    0x79, 0x70, 0x65, 0x3e, 0x4f, 0x42, 0x2e, 0x50, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x43, 0x79,
    0x63, 0x6c, 0x65, 0x3c, 0x2f, 0x43, 0x6f, 0x72, 0x65, 0x53, 0x75, 0x62, 0x74, 0x79, 0x70, 0x65,
    0x3e, 0x3c, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f,
    0x3e, 0x43, 0x6f, 0x64, 0x65, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x44, 0x61, 0x74, 0x61, 0x3c, 0x2f,
    0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x54, 0x79, 0x70, 0x65, 0x49, 0x6e, 0x66, 0x6f, 0x3e, 0x3c,
    0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x36, 0x33, 0x33, 0x37,
    0x30, 0x36, 0x33, 0x35, 0x34, 0x34, 0x32, 0x34, 0x35, 0x34, 0x36, 0x35, 0x31, 0x39, 0x3c, 0x2f,
    0x43, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x3e, 0x3c, 0x4f, 0x6e, 0x6c,
    0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f, 0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e,
    0x46, 0x61, 0x6c, 0x73, 0x65, 0x3c, 0x2f, 0x4f, 0x6e, 0x6c, 0x79, 0x53, 0x79, 0x6d, 0x62, 0x6f,
    0x6c, 0x69, 0x63, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x3e, 0x3c, 0x48, 0x65, 0x61, 0x64, 0x65,
    0x72, 0x44, 0x61, 0x74, 0x61, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x30,
    0x2e, 0x31, 0x22, 0x20, 0x2f, 0x3e, 0x3c, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e,
    0x74, 0x72, 0x75, 0x65, 0x3c, 0x2f, 0x49, 0x73, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3e, 0x3c,
    0x2f, 0x49, 0x64, 0x65, 0x6e, 0x74, 0x45, 0x53, 0x3e
};

#define S7COMMP_DICTID_CompilerSettings_90000001  0x1398a37f
static const char s7commp_dict_CompilerSettings_90000001[] = {
    0x3c, 0x41, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x20, 0x4b, 0x65, 0x79, 0x3d, 0x56, 0x61,
    0x6c, 0x75, 0x65, 0x3d, 0x22, 0x22, 0x20, 0x2f, 0x3e, 0x66, 0x61, 0x6c, 0x73, 0x65, 0x74, 0x72,
    0x75, 0x65, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x73, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x43, 0x6f, 0x6d,
    0x70, 0x69, 0x6c, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x4f, 0x70, 0x74, 0x69, 0x6d, 0x69, 0x7a,
    0x61, 0x74, 0x69, 0x6f, 0x6e, 0x46, 0x6c, 0x61, 0x67, 0x73, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74,
    0x54, 0x79, 0x70, 0x65, 0x4d, 0x43, 0x37, 0x50, 0x6c, 0x75, 0x73, 0x49, 0x45, 0x43, 0x53, 0x68,
    0x6f, 0x72, 0x74, 0x57, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x78, 0x30, 0x30, 0x32, 0x43, 0x5f, 0x5f,
    0x78, 0x30, 0x30, 0x32, 0x30, 0x5f, 0x4e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x50, 0x6f, 0x69, 0x6e,
    0x74, 0x65, 0x72, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x6c, 0x6c, 0x43, 0x68, 0x65, 0x63,
    0x6b, 0x5f, 0x43, 0x6c, 0x61, 0x73, 0x73, 0x69, 0x63, 0x3c, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74,
    0x20, 0x4b, 0x65, 0x79, 0x3d, 0x22, 0x3c, 0x2f, 0x53, 0x74, 0x72, 0x75, 0x63, 0x74, 0x3e, 0x3c,
    0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x20, 0x4b, 0x65, 0x79, 0x3d, 0x22, 0x3c, 0x2f,
    0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x3e, 0x3c, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74,
    0x3e, 0x3c, 0x2f, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x3e, 0x3c, 0x43, 0x6f, 0x6d, 0x70, 0x69,
    0x6c, 0x65, 0x72, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x44, 0x6f, 0x63, 0x75, 0x6d,
    0x65, 0x6e, 0x74, 0x20, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x22, 0x3c, 0x2f, 0x43,
    0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x44,
    0x6f, 0x63, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x3e, 0x46, 0x77, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f,
    0x6e, 0x4c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x4d, 0x6c,
    0x66, 0x62, 0x50, 0x6c, 0x63, 0x46, 0x61, 0x6d, 0x69, 0x6c, 0x79, 0x43, 0x61, 0x6c, 0x6c, 0x65,
    0x65, 0x52, 0x65, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x69, 0x6e, 0x67, 0x50, 0x6f, 0x73, 0x73,
    0x69, 0x62, 0x6c, 0x65, 0x43, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x46, 0x42, 0x44, 0x5f, 0x43, 0x4c,
    0x41, 0x53, 0x53, 0x49, 0x43, 0x46, 0x42, 0x44, 0x5f, 0x49, 0x45, 0x43, 0x4c, 0x41, 0x44, 0x5f,
    0x43, 0x4c, 0x41, 0x53, 0x53, 0x49, 0x43, 0x4c, 0x41, 0x44, 0x5f, 0x49, 0x45, 0x43, 0x53, 0x54,
    0x4c, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x45, 0x78, 0x74, 0x65, 0x6e, 0x64, 0x65, 0x64, 0x44,
    0x65, 0x62, 0x75, 0x67, 0x4d, 0x6f, 0x6e, 0x69, 0x74, 0x6f, 0x72, 0x41, 0x72, 0x72, 0x61, 0x79,
    0x4c, 0x69, 0x6d, 0x69, 0x74, 0x73, 0x53, 0x65, 0x74, 0x46, 0x6c, 0x61, 0x67, 0x41, 0x75, 0x74,
    0x6f, 0x6d, 0x61, 0x74, 0x69, 0x63, 0x61, 0x6c, 0x6c, 0x79
};

/**************************************************************************
 **************************************************************************/
/* Header Block */
static gint hf_s7commp_header = -1;
static gint hf_s7commp_header_protid = -1;              /* Header Byte  0 */
static gint hf_s7commp_header_protocolversion = -1;     /* Header Bytes 1 */
static gint hf_s7commp_header_datlg = -1;               /* Header Bytes 2, 3*/
static gint hf_s7commp_header_keepaliveseqnum = -1;     /* Sequence number in keep alive telegrams */

static gint hf_s7commp_data = -1;
static gint hf_s7commp_data_item_address = -1;
static gint hf_s7commp_data_item_value = -1;
static gint hf_s7commp_data_data = -1;
static gint hf_s7commp_data_opcode = -1;
static gint hf_s7commp_data_reserved1 = -1;
static gint hf_s7commp_data_reserved2 = -1;
static gint hf_s7commp_data_unknown1 = -1;
static gint hf_s7commp_data_function = -1;
static gint hf_s7commp_data_sessionid = -1;
static gint hf_s7commp_data_seqnum = -1;
static gint hf_s7commp_objectqualifier = -1;

static gint hf_s7commp_valuelist = -1;
static gint hf_s7commp_errorvaluelist = -1;
static gint hf_s7commp_addresslist = -1;
static gint ett_s7commp_valuelist = -1;
static gint ett_s7commp_errorvaluelist = -1;
static gint ett_s7commp_addresslist = -1;

static gint hf_s7commp_trailer = -1;
static gint hf_s7commp_trailer_protid = -1;
static gint hf_s7commp_trailer_protocolversion = -1;
static gint hf_s7commp_trailer_datlg = -1;

/* Extended Keep alive */
static gint hf_s7commp_extkeepalive_reserved1 = -1;
static gint hf_s7commp_extkeepalive_confirmedbytes = -1;
static gint hf_s7commp_extkeepalive_reserved2 = -1;
static gint hf_s7commp_extkeepalive_reserved3 = -1;
static gint hf_s7commp_extkeepalive_message = -1;

/* Read Response */
static gint hf_s7commp_data_req_set = -1;
static gint hf_s7commp_data_res_set = -1;

static gint hf_s7commp_data_id_number = -1;

static gint hf_s7commp_notification_set = -1;

/* Fields for object traversion */
static gint hf_s7commp_element_object = -1;
static gint hf_s7commp_element_attribute = -1;
static gint hf_s7commp_element_relation = -1;
static gint hf_s7commp_element_tagdescription = -1;
static gint hf_s7commp_element_block = -1;
static gint ett_s7commp_element_object = -1;
static gint ett_s7commp_element_attribute = -1;
static gint ett_s7commp_element_relation = -1;
static gint ett_s7commp_element_tagdescription = -1;
static gint ett_s7commp_element_block = -1;

/* Error value and subfields */
static gint hf_s7commp_data_returnvalue = -1;
static gint hf_s7commp_data_retval_errorcode = -1;
static gint hf_s7commp_data_retval_omsline = -1;
static gint hf_s7commp_data_retval_errorsource = -1;
static gint hf_s7commp_data_retval_genericerrorcode = -1;
static gint hf_s7commp_data_retval_servererror = -1;
static gint hf_s7commp_data_retval_debuginfo = -1;
static gint hf_s7commp_data_retval_errorextension = -1;
/* Z.Zt. nicht verwendet, da 64 Bit Feld nicht vernuenftig unterstuetzt wird. */
static const int *s7commp_data_returnvalue_fields[] = {
    &hf_s7commp_data_retval_errorcode,
    &hf_s7commp_data_retval_omsline,
    &hf_s7commp_data_retval_errorsource,
    &hf_s7commp_data_retval_genericerrorcode,
    &hf_s7commp_data_retval_servererror,
    &hf_s7commp_data_retval_debuginfo,
    &hf_s7commp_data_retval_errorextension,
    NULL
};

/* These are the ids of the subtrees that we are creating */
static gint ett_s7commp = -1;                           /* S7 communication tree, parent of all other subtree */
static gint ett_s7commp_header = -1;                    /* Subtree for header block */
static gint ett_s7commp_data = -1;                      /* Subtree for data block */
static gint ett_s7commp_data_returnvalue = -1;          /* Subtree for returnvalue */
static gint ett_s7commp_data_item = -1;                 /* Subtree for an item in data block */
static gint ett_s7commp_trailer = -1;                   /* Subtree for trailer block */

static gint ett_s7commp_data_req_set = -1;              /* Subtree for data request set*/
static gint ett_s7commp_data_res_set = -1;              /* Subtree for data response set*/
static gint ett_s7commp_notification_set = -1;          /* Subtree for notification data set */

static gint ett_s7commp_itemaddr_area = -1;             /* Subtree for item address area */
static gint ett_s7commp_itemval_array = -1;             /* Subtree if item value is an array */
static gint ett_s7commp_objectqualifier = -1;           /* Subtree for object qualifier data */
static gint ett_s7commp_integrity = -1;                 /* Subtree for integrity block */

static gint ett_s7commp_streamdata = -1;                /* Subtree for stream data in setvarsubstream */
static gint ett_s7commp_attrib_general = -1;            /* Subtree for attributes */

/* Item Address */
static gint hf_s7commp_item_count = -1;
static gint hf_s7commp_item_no_of_fields = -1;
static gint hf_s7commp_itemaddr_crc = -1;
static gint hf_s7commp_itemaddr_area_base = -1;
static gint hf_s7commp_itemaddr_area = -1;
static gint hf_s7commp_itemaddr_area1 = -1;
static gint hf_s7commp_itemaddr_dbnumber = -1;
static gint hf_s7commp_itemaddr_area_sub = -1;
static gint hf_s7commp_itemaddr_lid_value = -1;
static gint hf_s7commp_itemaddr_idcount = -1;

/* Item Value */
static gint hf_s7commp_itemval_itemnumber = -1;
static gint hf_s7commp_itemval_elementid = -1;
static gint hf_s7commp_itemval_datatype_flags = -1;
static gint hf_s7commp_itemval_datatype_flags_array = -1;               /* 0x10 for array */
static gint hf_s7commp_itemval_datatype_flags_address_array = -1;       /* 0x20 for address-array */
static gint hf_s7commp_itemval_datatype_flags_sparsearray = -1;         /* 0x40 for nullterminated array with key/value */
static gint hf_s7commp_itemval_datatype_flags_0x80unkn = -1;            /* 0x80 unknown, seen in S7-1500 */
static gint ett_s7commp_itemval_datatype_flags = -1;
static const int *s7commp_itemval_datatype_flags_fields[] = {
    &hf_s7commp_itemval_datatype_flags_array,
    &hf_s7commp_itemval_datatype_flags_address_array,
    &hf_s7commp_itemval_datatype_flags_sparsearray,
    &hf_s7commp_itemval_datatype_flags_0x80unkn,
    NULL
};
static gint hf_s7commp_itemval_sparsearray_term = -1;
static gint hf_s7commp_itemval_varianttypeid = -1;
static gint hf_s7commp_itemval_sparsearray_key = -1;
static gint hf_s7commp_itemval_stringactlen = -1;
static gint hf_s7commp_itemval_blobrootid = -1;
static gint hf_s7commp_itemval_blobsize = -1;
static gint hf_s7commp_itemval_datatype = -1;
static gint hf_s7commp_itemval_arraysize = -1;
static gint hf_s7commp_itemval_value = -1;

/* Get/Set a packed struct */
static gint ett_s7commp_packedstruct = -1;
static gint hf_s7commp_packedstruct = -1;
static gint hf_s7commp_packedstruct_interfacetimestamp = -1;
static gint hf_s7commp_packedstruct_transpsize = -1;
static gint hf_s7commp_packedstruct_elementcount = -1;
static gint hf_s7commp_packedstruct_data = -1;

/* List elements */
static gint hf_s7commp_listitem_terminator = -1;
static gint hf_s7commp_errorvaluelist_terminator = -1;

static gint hf_s7commp_explore_req_id = -1;
static gint hf_s7commp_explore_req_childsrec = -1;
static gint hf_s7commp_explore_requnknown3 = -1;
static gint hf_s7commp_explore_req_parents = -1;
static gint hf_s7commp_explore_objectcount = -1;
static gint hf_s7commp_explore_addresscount = -1;
static gint hf_s7commp_explore_structvalue = -1;
static gint hf_s7commp_explore_resseqinteg = -1;

/* Explore result, variable (tag) description */
static gint hf_s7commp_tagdescr_offsetinfo = -1;
static gint ett_s7commp_tagdescr_offsetinfo = -1;
static gint hf_s7commp_tagdescr_offsetinfotype = -1;
static gint hf_s7commp_tagdescr_namelength = -1;
static gint hf_s7commp_tagdescr_name = -1;
static gint hf_s7commp_tagdescr_unknown2 = -1;
static gint hf_s7commp_tagdescr_datatype = -1;
static gint hf_s7commp_tagdescr_softdatatype = -1;
static gint hf_s7commp_tagdescr_accessability = -1;
static gint hf_s7commp_tagdescr_section = -1;

static gint hf_s7commp_tagdescr_attributeflags = -1;
static gint hf_s7commp_tagdescr_attributeflags_hostrelevant = -1;
static gint hf_s7commp_tagdescr_attributeflags_retain = -1;
static gint hf_s7commp_tagdescr_attributeflags_classic = -1;
static gint hf_s7commp_tagdescr_attributeflags_hmivisible = -1;
static gint hf_s7commp_tagdescr_attributeflags_hmireadonly = -1;
static gint hf_s7commp_tagdescr_attributeflags_hmicached = -1;
static gint hf_s7commp_tagdescr_attributeflags_hmiaccessible = -1;
static gint hf_s7commp_tagdescr_attributeflags_isqualifier = -1;
static gint hf_s7commp_tagdescr_attributeflags_normalaccess = -1;
static gint hf_s7commp_tagdescr_attributeflags_needslegitimization = -1;
static gint hf_s7commp_tagdescr_attributeflags_changeableinrun = -1;
static gint hf_s7commp_tagdescr_attributeflags_serveronly = -1;
static gint hf_s7commp_tagdescr_attributeflags_clientreadonly = -1;
static gint hf_s7commp_tagdescr_attributeflags_seploadmemfa = -1;
static gint hf_s7commp_tagdescr_attributeflags_asevaluationrequired = -1;
static gint hf_s7commp_tagdescr_attributeflags_bl = -1;
static gint hf_s7commp_tagdescr_attributeflags_persistent = -1;
static gint hf_s7commp_tagdescr_attributeflags_core = -1;
static gint hf_s7commp_tagdescr_attributeflags_isout = -1;
static gint hf_s7commp_tagdescr_attributeflags_isin = -1;
static gint hf_s7commp_tagdescr_attributeflags_appwriteable = -1;
static gint hf_s7commp_tagdescr_attributeflags_appreadable = -1;
static gint ett_s7commp_tagdescr_attributeflags = -1;
static const int *s7commp_tagdescr_attributeflags_fields[] = {
    &hf_s7commp_tagdescr_attributeflags_hostrelevant,
    &hf_s7commp_tagdescr_attributeflags_retain,
    &hf_s7commp_tagdescr_attributeflags_classic,
    &hf_s7commp_tagdescr_attributeflags_hmivisible,
    &hf_s7commp_tagdescr_attributeflags_hmireadonly,
    &hf_s7commp_tagdescr_attributeflags_hmicached,
    &hf_s7commp_tagdescr_attributeflags_hmiaccessible,
    &hf_s7commp_tagdescr_attributeflags_isqualifier,
    &hf_s7commp_tagdescr_attributeflags_normalaccess,
    &hf_s7commp_tagdescr_attributeflags_needslegitimization,
    &hf_s7commp_tagdescr_attributeflags_changeableinrun,
    &hf_s7commp_tagdescr_attributeflags_serveronly,
    &hf_s7commp_tagdescr_attributeflags_clientreadonly,
    &hf_s7commp_tagdescr_attributeflags_seploadmemfa,
    &hf_s7commp_tagdescr_attributeflags_asevaluationrequired,
    &hf_s7commp_tagdescr_attributeflags_bl,
    &hf_s7commp_tagdescr_attributeflags_persistent,
    &hf_s7commp_tagdescr_attributeflags_core,
    &hf_s7commp_tagdescr_attributeflags_isout,
    &hf_s7commp_tagdescr_attributeflags_isin,
    &hf_s7commp_tagdescr_attributeflags_appwriteable,
    &hf_s7commp_tagdescr_attributeflags_appreadable,
    NULL
};

static gint hf_s7commp_tagdescr_attributeflags2 = -1;
static gint hf_s7commp_tagdescr_attributeflags2_offsetinfotype = -1; /* 4 Bits, mask 0xf000 */
static gint hf_s7commp_tagdescr_attributeflags2_hmivisible = -1;
static gint hf_s7commp_tagdescr_attributeflags2_bit11 = -1;
static gint hf_s7commp_tagdescr_attributeflags2_hmiaccessible = -1;
static gint hf_s7commp_tagdescr_attributeflags2_bit09 = -1;
static gint hf_s7commp_tagdescr_attributeflags2_optimizedaccess = -1;
static gint hf_s7commp_tagdescr_attributeflags2_section = -1;       /* 3 Bits, mask 0x0070 */
static gint hf_s7commp_tagdescr_attributeflags2_bit04 = -1;
static gint hf_s7commp_tagdescr_attributeflags2_bitoffset = -1;     /* 3 Bits, mask 0x0007 */

static const int *s7commp_tagdescr_attributeflags2_fields[] = {
    &hf_s7commp_tagdescr_attributeflags2_offsetinfotype,
    &hf_s7commp_tagdescr_attributeflags2_hmivisible,
    &hf_s7commp_tagdescr_attributeflags2_bit11,
    &hf_s7commp_tagdescr_attributeflags2_hmiaccessible,
    &hf_s7commp_tagdescr_attributeflags2_bit09,
    &hf_s7commp_tagdescr_attributeflags2_optimizedaccess,
    &hf_s7commp_tagdescr_attributeflags2_section,
    &hf_s7commp_tagdescr_attributeflags2_bit04,
    &hf_s7commp_tagdescr_attributeflags2_bitoffset,
    NULL
};

static gint hf_s7commp_tagdescr_bitoffsetinfo = -1;
static gint hf_s7commp_tagdescr_bitoffsetinfo_retain = -1;
static gint hf_s7commp_tagdescr_bitoffsetinfo_nonoptbitoffset = -1;   /* 3 Bits, mask 0x70 */
static gint hf_s7commp_tagdescr_bitoffsetinfo_classic = -1;
static gint hf_s7commp_tagdescr_bitoffsetinfo_optbitoffset = -1;      /* 3 Bits, mask 0x07 */
static gint ett_s7commp_tagdescr_bitoffsetinfo = -1;

static const int *s7commp_tagdescr_bitoffsetinfo_fields[] = {
    &hf_s7commp_tagdescr_bitoffsetinfo_retain,
    &hf_s7commp_tagdescr_bitoffsetinfo_nonoptbitoffset,
    &hf_s7commp_tagdescr_bitoffsetinfo_classic,
    &hf_s7commp_tagdescr_bitoffsetinfo_optbitoffset,
    NULL
};

static gint hf_s7commp_tagdescr_lid = -1;
static gint hf_s7commp_tagdescr_subsymbolcrc = -1;
static gint hf_s7commp_tagdescr_s7stringlength = -1;
static gint hf_s7commp_tagdescr_structrelid = -1;
static gint hf_s7commp_tagdescr_lenunknown = -1;
static gint hf_s7commp_tagdescr_offsettype1 = -1;
static gint hf_s7commp_tagdescr_offsettype2 = -1;
static gint hf_s7commp_tagdescr_bitoffsettype1 = -1;
static gint hf_s7commp_tagdescr_bitoffsettype2 = -1;
static gint hf_s7commp_tagdescr_arraylowerbounds = -1;
static gint hf_s7commp_tagdescr_arrayelementcount = -1;
static gint hf_s7commp_tagdescr_paddingtype1 = -1;
static gint hf_s7commp_tagdescr_paddingtype2 = -1;
static gint hf_s7commp_tagdescr_numarraydimensions = -1;
static gint hf_s7commp_tagdescr_nonoptimized_addr = -1;
static gint hf_s7commp_tagdescr_optimized_addr = -1;
static gint hf_s7commp_tagdescr_nonoptimized_addr_16 = -1;
static gint hf_s7commp_tagdescr_optimized_addr_16 = -1;
static gint hf_s7commp_tagdescr_nonoptimized_struct_size = -1;
static gint hf_s7commp_tagdescr_optimized_struct_size = -1;

/* Object */
static gint hf_s7commp_object_relid = -1;
static gint hf_s7commp_object_classid = -1;
static gint hf_s7commp_object_classflags = -1;
static gint hf_s7commp_object_attributeid = -1;
static gint hf_s7commp_object_attributeidflags = -1;
static gint hf_s7commp_object_relunknown1 = -1;
static gint hf_s7commp_object_blocklength = -1;
static gint hf_s7commp_object_createobjidcount = -1;
static gint hf_s7commp_object_createobjid = -1;
static gint hf_s7commp_object_deleteobjid = -1;

/* Setmultivar/Setvariable */
static gint hf_s7commp_setvar_unknown1 = -1;
static gint hf_s7commp_setvar_objectid = -1;
static gint hf_s7commp_setvar_itemcount = -1;
static gint hf_s7commp_setvar_itemaddrcount = -1;
static gint hf_s7commp_setvar_rawvaluelen = -1;

/* Getmultivar/Getvariable */
static gint hf_s7commp_getmultivar_unknown1 = -1;
static gint hf_s7commp_getmultivar_linkid = -1;
static gint hf_s7commp_getmultivar_itemaddrcount = -1;
static gint hf_s7commp_getvar_itemcount = -1;

/* SetVarSubstreamed, stream data */
static gint hf_s7commp_streamdata = -1;
static gint hf_s7commp_streamdata_frag_data_len = -1;
static gint hf_s7commp_streamdata_frag_data = -1;

/* Notification */
static gint hf_s7commp_notification_vl_retval = -1;
static gint hf_s7commp_notification_vl_refnumber = -1;
static gint hf_s7commp_notification_vl_unknown0x9c = -1;

static gint hf_s7commp_notification_subscrobjectid = -1;
static gint hf_s7commp_notification_unknown2 = -1;
static gint hf_s7commp_notification_unknown3 = -1;
static gint hf_s7commp_notification_unknown4 = -1;
static gint hf_s7commp_notification_credittick = -1;
static gint hf_s7commp_notification_seqnum_vlq = -1;
static gint hf_s7commp_notification_seqnum_uint8 = -1;
static gint hf_s7commp_notification_unknown5 = -1;
static gint hf_s7commp_notification_p2_subscrobjectid = -1;
static gint hf_s7commp_notification_p2_unknown1 = -1;
static gint hf_s7commp_notification_p2_unknown2 = -1;
static gint hf_s7commp_notification_unknown3b = -1;

/* SubscriptionReferenceList */
static gint hf_s7commp_subscrreflist = -1;
static gint hf_s7commp_subscrreflist_unknown1 = -1;
static gint hf_s7commp_subscrreflist_itemcount_unsubscr = -1;
static gint hf_s7commp_subscrreflist_itemcount_subscr = -1;
static gint hf_s7commp_subscrreflist_unsubscr_list = -1;
static gint hf_s7commp_subscrreflist_subscr_list = -1;
static gint hf_s7commp_subscrreflist_item_head = -1;
static gint ett_s7commp_subscrreflist_item_head = -1;
static gint hf_s7commp_subscrreflist_item_head_unknown = -1;
static gint hf_s7commp_subscrreflist_item_head_lidcnt = -1;
static const int *s7commp_subscrreflist_item_head_fields[] = {
    &hf_s7commp_subscrreflist_item_head_unknown,
    &hf_s7commp_subscrreflist_item_head_lidcnt,
    NULL
};
static gint hf_s7commp_subscrreflist_item_unknown1 = -1;
static gint ett_s7commp_subscrreflist = -1;

/* SecurityKeyEncryptedKey */
static gint hf_s7commp_securitykeyencryptedkey = -1;
static gint ett_s7commp_securitykeyencryptedkey = -1;
static gint hf_s7commp_securitykeyencryptedkey_magic = -1;
static gint hf_s7commp_securitykeyencryptedkey_length = -1;
static gint hf_s7commp_securitykeyencryptedkey_unknown1 = -1;
static gint hf_s7commp_securitykeyencryptedkey_unknown2 = -1;
static gint hf_s7commp_securitykeyencryptedkey_symmetrickeychecksum = -1;
static gint hf_s7commp_securitykeyencryptedkey_symmetrickeyflags = -1;
static gint hf_s7commp_securitykeyencryptedkey_symmetrickeyflags_internal = -1;
static gint hf_s7commp_securitykeyencryptedkey_publickeychecksum = -1;
static gint hf_s7commp_securitykeyencryptedkey_publickeyflags = -1;
static gint hf_s7commp_securitykeyencryptedkey_publickeyflags_internal = -1;
static gint hf_s7commp_securitykeyencryptedkey_encrypted_random_seed = -1;
static gint hf_s7commp_securitykeyencryptedkey_encryption_init_vector = -1;
static gint hf_s7commp_securitykeyencryptedkey_encrypted_challenge = -1;

/* zlib compressed blob */
static gint hf_s7commp_compressedblob = -1;
static gint ett_s7commp_compressedblob = -1;
static gint hf_s7commp_compressedblob_dictionary_version = -1;
static gint hf_s7commp_compressedblob_dictionary_id = -1;

/* MultipleStai */
static gint hf_s7commp_multiplestai = -1;
static gint hf_s7commp_multiplestai_alid = -1;
static gint hf_s7commp_multiplestai_alarmdomain = -1;
static gint hf_s7commp_multiplestai_messagetype = -1;
static gint hf_s7commp_multiplestai_alarmenabled = -1;
static gint hf_s7commp_multiplestai_hmiinfo_length = -1;
static gint hf_s7commp_multiplestai_lidcount = -1;
static gint hf_s7commp_multiplestai_lid = -1;

/* Message types in MultipleStai */
#define S7COMMP_MULTIPLESTAI_MESSAGETYPE_INVALIDAP      0
#define S7COMMP_MULTIPLESTAI_MESSAGETYPE_ALARMAP        1
#define S7COMMP_MULTIPLESTAI_MESSAGETYPE_NOTIFYAP       2
#define S7COMMP_MULTIPLESTAI_MESSAGETYPE_INFOREPORTAP   3
#define S7COMMP_MULTIPLESTAI_MESSAGETYPE_EVENTACKAP     4

static const value_string multiplestai_messagetypes[] = {
    { S7COMMP_MULTIPLESTAI_MESSAGETYPE_INVALIDAP,       "Invalid AP" },
    { S7COMMP_MULTIPLESTAI_MESSAGETYPE_ALARMAP,         "Alarm AP" },
    { S7COMMP_MULTIPLESTAI_MESSAGETYPE_NOTIFYAP,        "Notify AP" },
    { S7COMMP_MULTIPLESTAI_MESSAGETYPE_INFOREPORTAP,    "Info Report AP" },
    { S7COMMP_MULTIPLESTAI_MESSAGETYPE_EVENTACKAP,      "Event Ack AP" },
    { 0,                                                NULL }
};

/* "Anzeigeklasse" / "Display class" when using Program_Alarm in plc program */
static const value_string multiplestai_alarmdomains[] = {
    { 1,            "Systemdiagnose" },
    { 3,            "Security" },
    { 256,          "UserClass_0" },
    { 257,          "UserClass_1" },
    { 258,          "UserClass_2" },
    { 259,          "UserClass_3" },
    { 260,          "UserClass_4" },
    { 261,          "UserClass_5" },
    { 262,          "UserClass_6" },
    { 263,          "UserClass_7" },
    { 264,          "UserClass_8" },
    { 265,          "UserClass_9" },
    { 266,          "UserClass_10" },
    { 267,          "UserClass_11" },
    { 268,          "UserClass_12" },
    { 269,          "UserClass_13" },
    { 270,          "UserClass_14" },
    { 271,          "UserClass_15" },
    { 272,          "UserClass_16" },
    { 0,            NULL }
};

/* HmiInfo */
static gint hf_s7commp_hmiinfo = -1;
static gint hf_s7commp_hmiinfo_syntaxid = -1;
static gint hf_s7commp_hmiinfo_version = -1;
static gint hf_s7commp_hmiinfo_clientalarmid = -1;
static gint hf_s7commp_hmiinfo_priority = -1;

/* Getlink */
static gint hf_s7commp_getlink_requnknown1 = -1;
static gint hf_s7commp_getlink_requnknown2 = -1;
static gint hf_s7commp_getlink_linkidcount = -1;
static gint hf_s7commp_getlink_linkid = -1;

/* BeginSequence */
static gint hf_s7commp_beginseq_transactiontype = -1;
static gint hf_s7commp_beginseq_valtype = -1;
static gint hf_s7commp_beginseq_requnknown3 = -1;
static gint hf_s7commp_beginseq_requestid = -1;

/* EndSequence */
static gint hf_s7commp_endseq_requnknown1 = -1;

/* Invoke */
static gint hf_s7commp_invoke_subsessionid = -1;
static gint hf_s7commp_invoke_requnknown1 = -1;
static gint hf_s7commp_invoke_requnknown2 = -1;
static gint hf_s7commp_invoke_resunknown1 = -1;

/* Integrity part, for 1500 */
static gint hf_s7commp_integrity = -1;
static gint hf_s7commp_integrity_id = -1;
static gint hf_s7commp_integrity_digestlen = -1;
static gint hf_s7commp_integrity_digest = -1;

/* These fields used when reassembling S7COMMP fragments */
static gint hf_s7commp_fragments = -1;
static gint hf_s7commp_fragment = -1;
static gint hf_s7commp_fragment_overlap = -1;
static gint hf_s7commp_fragment_overlap_conflict = -1;
static gint hf_s7commp_fragment_multiple_tails = -1;
static gint hf_s7commp_fragment_too_long_fragment = -1;
static gint hf_s7commp_fragment_error = -1;
static gint hf_s7commp_fragment_count = -1;
static gint hf_s7commp_reassembled_in = -1;
static gint hf_s7commp_reassembled_length = -1;
static gint ett_s7commp_fragment = -1;
static gint ett_s7commp_fragments = -1;

/* Expert info handles */
static expert_field ei_s7commp_blobdecompression_failed = EI_INIT;
static expert_field ei_s7commp_blobdecompression_nodictionary = EI_INIT;
static expert_field ei_s7commp_blobdecompression_xmlsubdissector_failed = EI_INIT;
static expert_field ei_s7commp_integrity_digestlen_error = EI_INIT;
static expert_field ei_s7commp_value_unknown_type = EI_INIT;
static expert_field ei_s7commp_notification_returnvalue_unknown = EI_INIT;
static expert_field ei_s7commp_data_opcode_unknown = EI_INIT;

static dissector_handle_t xml_handle;

static const fragment_items s7commp_frag_items = {
    /* Fragment subtrees */
    &ett_s7commp_fragment,
    &ett_s7commp_fragments,
    /* Fragment fields */
    &hf_s7commp_fragments,
    &hf_s7commp_fragment,
    &hf_s7commp_fragment_overlap,
    &hf_s7commp_fragment_overlap_conflict,
    &hf_s7commp_fragment_multiple_tails,
    &hf_s7commp_fragment_too_long_fragment,
    &hf_s7commp_fragment_error,
    &hf_s7commp_fragment_count,
    /* Reassembled in field */
    &hf_s7commp_reassembled_in,
    /* Reassembled length field */
    &hf_s7commp_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "S7COMM-PLUS fragments"
};

static gint hf_s7commp_proto_tree_add_text_dummy = -1;      /* dummy header field for conversion to wireshark 2.0 */

typedef struct {
    gboolean first_fragment;
    gboolean inner_fragment;
    gboolean last_fragment;
    guint32 start_frame;
    guint8 start_opcode;
    guint16 start_function;
} frame_state_t;

#define CONV_STATE_NEW         -1
#define CONV_STATE_NOFRAG      0
#define CONV_STATE_FIRST       1
#define CONV_STATE_INNER       2
#define CONV_STATE_LAST        3
typedef struct {
    int state;
    guint32 start_frame;
    guint8 start_opcode;
    guint16 start_function;
} conv_state_t;

/* options */
static gboolean s7commp_reassemble = TRUE;
#ifdef HAVE_ZLIB
static gboolean s7commp_opt_decompress_blobs = TRUE;
#else
static gboolean s7commp_opt_decompress_blobs = FALSE;
#endif

/*
 * reassembly of S7COMMP
 */
static reassembly_table s7commp_reassembly_table;

static void
s7commp_defragment_init(void)
{
    reassembly_table_init(&s7commp_reassembly_table,
                          &addresses_reassembly_table_functions);
}


/* Register this protocol */
void
proto_reg_handoff_s7commp(void)
{
    static gboolean initialized = FALSE;
    if (!initialized) {
        xml_handle = find_dissector_add_dependency("xml", proto_s7commp);
        #ifdef DONT_ADD_AS_HEURISTIC_DISSECTOR
            register_dissector("dlt", dissect_s7commp, proto_s7commp);
        #else
            heur_dissector_add("cotp", dissect_s7commp, "S7 Communication Plus over COTP", "s7comm_plus_cotp", proto_s7commp, HEURISTIC_ENABLE);
        #endif
        initialized = TRUE;
    }
}
/*******************************************************************************************************
* Callback function for id-name decoding
* In der globalen ID-Liste sind nur die statischen Werte vorhanden.
* Dynamische Werte sind z.B. DB-Nummern, Bibliotheksbaustein-Nummern, usw.
* Diese Funktion kann als BASE_CUSTOM in den header-fields verwendet werden.
* val_to_str() darf in der Callback function nicht verwendet werden, da es intern fuer die
* Strings Speicher aus dem Scope wmem_packet_scope verwendet, und dieser zum Zeitpunkt
* des Aufrufs ueber die Callback Funktion nicht gueltig ist.
*******************************************************************************************************/
static void
s7commp_idname_fmt(gchar *result, guint32 id_number)
{
    const guint8 *str;
    guint32 section;
    guint32 xindex;

    if ((str = try_val_to_str_ext(id_number, &id_number_names_ext))) {
        g_snprintf(result, ITEM_LABEL_LENGTH, "%s", str);
    } else {
        /*cls = ((id_number & 0xff000000) >> 24);*/
        xindex = ((id_number & 0x00ff0000) >> 16);
        section = (id_number & 0xffff);

        if (id_number >= 0x70000000 && id_number <= 0x7fffffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "DebugObject.%u.%u", xindex, section);
        } else if (id_number >= 0x89fd0000 && id_number <= 0x89fdffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "UDT.%u", section);
        } else if (id_number >= 0x8a0e0000 && id_number <= 0x8a0effff) {    /* Datenbaustein mit Nummer, 8a0e.... wird aber auch als AlarmID verwendet */
            g_snprintf(result, ITEM_LABEL_LENGTH, "DB.%u", section);
        } else if (id_number >= 0x8a110000 && id_number <= 0x8a11ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "UserConstants.%u", section);
        } else if (id_number >= 0x8a120000 && id_number <= 0x8a12ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "FB.%u", section);
        } else if (id_number >= 0x8a130000 && id_number <= 0x8a13ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "FC.%u", section);
        } else if (id_number >= 0x8a200000 && id_number <= 0x8a20ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "S_FB.%u", section);
        } else if (id_number >= 0x8a240000 && id_number <= 0x8a24ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "S_UDT.%u", section);
        } else if (id_number >= 0x8a320000 && id_number <= 0x8a32ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "OB.%u", section);
        } else if (id_number >= 0x8a360000 && id_number <= 0x8a36ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "AlarmTextList.%u", section);
        } else if (id_number >= 0x8a370000 && id_number <= 0x8a37ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "TextList.%u", section);
        } else if (id_number >= 0x8a380000 && id_number <= 0x8a38ffff) {
            g_snprintf(result, ITEM_LABEL_LENGTH, "TextContainer.%u", section);
        } else if (id_number >= 0x8a7e0000 && id_number <= 0x8a7effff) {    /* AS Alarms */
            g_snprintf(result, ITEM_LABEL_LENGTH, "ASAlarms.%u", section);
        } else if (id_number >= 0x90000000 && id_number <= 0x90ffffff) {    /* TypeInfo Bereich IQMCT, wofuer hier section steht ist nicht bekannt, bisher immer 0 gesehen. */
            str = try_val_to_str(xindex, explore_class_iqmct_names);
            if (str) {
                g_snprintf(result, ITEM_LABEL_LENGTH, "TI_%s.%u", str, section);
            } else {
                g_snprintf(result, ITEM_LABEL_LENGTH, "TI_IQMCT.unknown.%u.%u", xindex, section);
            }
        } else if (id_number >= 0x91000000 && id_number <= 0x91ffffff) {    /* TypeInfo Bereich im UDT */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_UDT.%u.%u", section, xindex);
        } else if (id_number >= 0x92000000 && id_number <= 0x92ffffff) {    /* TypeInfo Bereich im DB */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_DB.%u.%u", section, xindex);
        } else if (id_number >= 0x93000000 && id_number <= 0x93ffffff) {    /* TypeInfo Bereich im FB */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_FB.%u.%u", section, xindex);
        } else if (id_number >= 0x94000000 && id_number <= 0x94ffffff) {    /* TypeInfo Bereich im FC */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_FC.%u.%u", section, xindex);
        } else if (id_number >= 0x95000000 && id_number <= 0x95ffffff) {    /* TypeInfo Bereich im OB */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_OB.%u.%u", section, xindex);
        } else if (id_number >= 0x96000000 && id_number <= 0x96ffffff) {    /* TypeInfo Bereich im FBT */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_FBT.%u.%u", section, xindex);
        } else if (id_number >= 0x9a000000 && id_number <= 0x9affffff) {    /* Struct-Array in einem DB */
            g_snprintf(result, ITEM_LABEL_LENGTH, "TI_StructArrayDB.%u.%u", section, xindex);
        } else if (id_number >= 0x9eae0000 && id_number <= 0x9eaeffff) {    /* Haengt auch mit dem Alarmsystem zusammen??? TODO */
            g_snprintf(result, ITEM_LABEL_LENGTH, "?UnknownAlarms?.%u", section);
        } else if (id_number >= 0x02000000 && id_number <= 0x02ffffff) {    /* Explore Bereich LIB */
            str = try_val_to_str(xindex, explore_class_lib_names);
            if (str) {
                g_snprintf(result, ITEM_LABEL_LENGTH, "TI_LIB.%s.%u", str, section);
            } else {
                g_snprintf(result, ITEM_LABEL_LENGTH, "TI_Unknown.%u.%u", xindex, section);
            }
        } else {                                                            /* Komplett unbekannt */
            g_snprintf(result, ITEM_LABEL_LENGTH, "Unknown (%u)", id_number);
        }
    }
}
/*******************************************************************************************************/
void
proto_register_s7commp (void)
{
    static hf_register_info hf[] = {
        /*** Header fields ***/
        { &hf_s7commp_header,
          { "Header", "s7comm-plus.header", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is the header of S7 communication plus", HFILL }},
        { &hf_s7commp_header_protid,
          { "Protocol Id", "s7comm-plus.header.protid", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Protocol Identification", HFILL }},
        { &hf_s7commp_header_protocolversion,
          { "Protocol version", "s7comm-plus.header.protocolversion", FT_UINT8, BASE_HEX, VALS(protocolversion_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_header_datlg,
          { "Data length", "s7comm-plus.header.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Specifies the entire length of the data block in bytes", HFILL }},
        { &hf_s7commp_header_keepaliveseqnum,
          { "Keep alive sequence number", "s7comm-plus.header.keepalive_seqnum", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Sequence number in keep alive telegrams", HFILL }},

        /*** Fields in data part ***/
        { &hf_s7commp_data,
          { "Data", "s7comm-plus.data", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is the data part of S7 communication plus", HFILL }},

        { &hf_s7commp_data_returnvalue,
          { "Return value", "s7comm-plus.returnvalue", FT_UINT64, BASE_HEX, NULL, 0x0,
            "varuint64: Return value", HFILL }},
        { &hf_s7commp_data_retval_errorcode,
          { "Error code", "s7comm-plus.returnvalue.errorcode", FT_INT64, BASE_DEC|BASE_VAL64_STRING, VALS64(errorcode_names), G_GUINT64_CONSTANT(0x000000000000ffff),
            NULL, HFILL }},
        { &hf_s7commp_data_retval_omsline,
          { "OMS line", "s7comm-plus.returnvalue.omsline", FT_UINT64, BASE_DEC, NULL, G_GUINT64_CONSTANT(0x00000000ffff0000),
            NULL, HFILL }},
        { &hf_s7commp_data_retval_errorsource,
          { "Error source", "s7comm-plus.returnvalue.errorsource", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x000000ff00000000),
            NULL, HFILL }},
        { &hf_s7commp_data_retval_genericerrorcode,
          { "Generic error code", "s7comm-plus.returnvalue.genericerrorcode", FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(genericerrorcode_names), G_GUINT64_CONSTANT(0x00007f0000000000),
            NULL, HFILL }},
        { &hf_s7commp_data_retval_servererror,
          { "Server error", "s7comm-plus.returnvalue.servererror", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x0000800000000000),
            NULL, HFILL }},
        { &hf_s7commp_data_retval_debuginfo,
          { "Debug info", "s7comm-plus.returnvalue.debuginfo", FT_UINT64, BASE_HEX, NULL, G_GUINT64_CONSTANT(0x3fff000000000000),
            NULL, HFILL }},
        { &hf_s7commp_data_retval_errorextension,
          { "Error extension", "s7comm-plus.returnvalue.errorextension", FT_BOOLEAN, 64, NULL, G_GUINT64_CONSTANT(0x4000000000000000),
            NULL, HFILL }},

        { &hf_s7commp_data_opcode,
          { "Opcode", "s7comm-plus.data.opcode", FT_UINT8, BASE_HEX, VALS(opcode_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_data_reserved1,
          { "Reserved", "s7comm-plus.data.reserved1", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_data_function,
          { "Function", "s7comm-plus.data.function", FT_UINT16, BASE_HEX, VALS(data_functioncode_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_data_reserved2,
          { "Reserved", "s7comm-plus.data.reserved2", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_data_seqnum,
          { "Sequence number", "s7comm-plus.data.seqnum", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Sequence number (for reference)", HFILL }},
        { &hf_s7commp_data_unknown1,
          { "Unknown 1", "s7comm-plus.data.unknown1", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Unknown 1. Maybe flags or split into nibbles", HFILL }},
        { &hf_s7commp_data_sessionid,
          { "Session Id", "s7comm-plus.data.sessionid", FT_UINT32, BASE_HEX, NULL, 0x0,
            "Session Id, negotiated on session start", HFILL }},

        { &hf_s7commp_data_item_address,
          { "Item Address", "s7comm-plus.data.item_address", FT_NONE, BASE_NONE, NULL, 0x0,
            "Address of one Item", HFILL }},
        { &hf_s7commp_data_item_value,
          { "Item Value", "s7comm-plus.data.item_value", FT_NONE, BASE_NONE, NULL, 0x0,
            "Value of one item", HFILL }},

        { &hf_s7commp_data_data,
          { "Data unknown", "s7comm-plus.data.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_data_req_set,
          { "Request Set", "s7comm-plus.data.req_set", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a set of data in a request telegram", HFILL }},
        { &hf_s7commp_data_res_set,
          { "Response Set", "s7comm-plus.data.res_set", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a set of data in a response telegram", HFILL }},
        { &hf_s7commp_notification_set,
          { "Notification Data Set", "s7comm-plus.notification_dataset", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is a set of data in a notification data telegram", HFILL }},

        { &hf_s7commp_data_id_number,
          { "ID Number", "s7comm-plus.data.id_number", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            "varuint32: ID Number for function", HFILL }},
        /* Lists */
        { &hf_s7commp_valuelist,
          { "ValueList", "s7comm-plus.valuelist", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_errorvaluelist,
          { "ErrorValueList", "s7comm-plus.errorvaluelist", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_addresslist,
          { "AddressList", "s7comm-plus.addresslist", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        /* Item Address */
        { &hf_s7commp_item_count,
          { "Item Count", "s7comm-plus.item.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of items following", HFILL }},
        { &hf_s7commp_item_no_of_fields,
          { "Number of fields in complete Item-Dataset", "s7comm-plus.item.no_of_fields", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of fields in complete Item-Dataset", HFILL }},
        { &hf_s7commp_itemaddr_crc,
          { "Symbol CRC", "s7comm-plus.item.addr.symbol_crc", FT_UINT32, BASE_HEX, NULL, 0x0,
            "CRC generated out of symbolic name with (x^32+x^31+x^30+x^29+x^28+x^26+x^23+x^21+x^19+x^18+x^15+x^14+x^13+x^12+x^9+x^8+x^4+x+1)", HFILL }},
        { &hf_s7commp_itemaddr_area,
          { "Access base-area", "s7comm-plus.item.addr.area", FT_UINT32, BASE_HEX, NULL, 0x0,
            "varuint32: Base area inside Datablock with Number", HFILL }},
        { &hf_s7commp_itemaddr_area1,
          { "Accessing area", "s7comm-plus.item.addr.area1", FT_UINT16, BASE_HEX, VALS(var_item_area1_names), 0x0,
            "Always 0x8a0e for Datablock", HFILL }},
        { &hf_s7commp_itemaddr_dbnumber,
          { "DB number", "s7comm-plus.item.addr.dbnumber", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_itemaddr_area_base,
          { "Access base-area", "s7comm-plus.item.addr.area_base", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            "This is the base area for all following IDs", HFILL }},
        { &hf_s7commp_itemaddr_area_sub,
          { "Access sub-area", "s7comm-plus.item.addr.area_sub", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            "This is the sub area for all following IDs", HFILL }},
        { &hf_s7commp_itemaddr_lid_value,
          { "LID Value", "s7comm-plus.item.addr.lid_value", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: LID Value", HFILL }},
        { &hf_s7commp_itemaddr_idcount,
          { "Number of following IDs", "s7comm-plus.item.addr.idcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of following IDs", HFILL }},

        /*** Item value ***/
        { &hf_s7commp_itemval_itemnumber,
          { "Item Number", "s7comm-plus.item.val.item_number", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Item Number", HFILL }},
        { &hf_s7commp_itemval_elementid,
          { "Element Tag-Id", "s7comm-plus.item.val.elementid", FT_UINT8, BASE_HEX, VALS(itemval_elementid_names), 0x0,
            NULL, HFILL }},
        /* Datatype flags */
        { &hf_s7commp_itemval_datatype_flags,
          { "Datatype flags", "s7comm-plus.item.val.datatype_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_itemval_datatype_flags_array,
          { "Array", "s7comm-plus.item.val.datatype_flags.array", FT_BOOLEAN, 8, NULL, S7COMMP_DATATYPE_FLAG_ARRAY,
            "The data has to be interpreted as an array of values", HFILL }},
        { &hf_s7commp_itemval_datatype_flags_address_array,
          { "Addressarray", "s7comm-plus.item.val.datatype_flags.address_array", FT_BOOLEAN, 8, NULL, S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY,
            "Array of values for Item Address via CRC and LID", HFILL }},
        { &hf_s7commp_itemval_datatype_flags_sparsearray,
          { "Sparsearray", "s7comm-plus.item.val.datatype_flags.sparsearray", FT_BOOLEAN, 8, NULL, S7COMMP_DATATYPE_FLAG_SPARSEARRAY,
            "Nullterminated Array with key/value for each element", HFILL }},
        { &hf_s7commp_itemval_datatype_flags_0x80unkn,
          { "Unknown-Flag1", "s7comm-plus.item.val.datatype_flags.unknown1", FT_BOOLEAN, 8, NULL, 0x80,
            "Current unknown flag. A S7-1500 sets this flag sometimes", HFILL }},

        { &hf_s7commp_itemval_sparsearray_term,
          { "Sparsearray key terminating Null", "s7comm-plus.item.val.sparsearray_term", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_itemval_varianttypeid,
          { "Variant Type-ID", "s7comm-plus.item.val.varianttypeid", FT_UINT8, BASE_HEX, VALS(item_datatype_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_itemval_sparsearray_key,
          { "Sparsearray key", "s7comm-plus.item.val.sparsearray_key", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ", HFILL }},
        { &hf_s7commp_itemval_stringactlen,
          { "String actual length", "s7comm-plus.item.val.stringactlen", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ", HFILL }},
        { &hf_s7commp_itemval_blobrootid,
          { "Blob root ID", "s7comm-plus.item.val.blobrootid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            "If 0 then standard format. If >0 then special format similar to struct", HFILL }},
        { &hf_s7commp_itemval_blobsize,
          { "Blob size", "s7comm-plus.item.val.blobsize", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ", HFILL }},

        { &hf_s7commp_itemval_datatype,
          { "Datatype", "s7comm-plus.item.val.datatype", FT_UINT8, BASE_HEX, VALS(item_datatype_names), 0x0,
            "Type of data following", HFILL }},
        { &hf_s7commp_itemval_arraysize,
          { "Array size", "s7comm-plus.item.val.arraysize", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of values of the specified datatype following", HFILL }},
        { &hf_s7commp_itemval_value,
          { "Value", "s7comm-plus.item.val.value", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Get/Set a packed struct */
        { &hf_s7commp_packedstruct,
          { "Packed struct", "s7comm-plus.item.packedstruct", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_packedstruct_interfacetimestamp,
          { "Interface timestamp", "s7comm-plus.item.packedstruct.interfacetimestamp", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_packedstruct_transpsize,
          { "Unknown (Transport size?)", "s7comm-plus.item.packedstruct.transpsize", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_packedstruct_elementcount,
          { "Element count", "s7comm-plus.item.packedstruct.elementcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_packedstruct_data,
          { "Packed struct data", "s7comm-plus.item.packedstruct.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* List elements */
        { &hf_s7commp_listitem_terminator,
          { "Terminating Item/List", "s7comm-plus.listitem_terminator", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_errorvaluelist_terminator,
          { "Terminating ErrorValueList", "s7comm-plus.errorvaluelist_terminator", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Exploring plc */
        { &hf_s7commp_explore_req_id,
          { "Explore request ID (Root/Link-ID?)", "s7comm-plus.explore.req_id", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_explore_req_childsrec,
          { "Explore childs recursive", "s7comm-plus.explore.req_childsrecursive", FT_UINT8, BASE_DEC, VALS(no_yes_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_explore_requnknown3,
          { "Explore request unknown 3", "s7comm-plus.explore.requnknown3", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_explore_req_parents,
          { "Explore parents", "s7comm-plus.explore.req_parents", FT_UINT8, BASE_DEC, VALS(no_yes_names), 0x0,
            "Explore parents up to root", HFILL }},
        { &hf_s7commp_explore_objectcount,
          { "Number of following Objects (or object type? / unknown)", "s7comm-plus.explore.objectcount", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_explore_addresscount,
          { "Number of following Addresses (IDs)", "s7comm-plus.explore.addresscount", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_explore_structvalue,
          { "Value", "s7comm-plus.explore.structvalue", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_explore_resseqinteg,
          { "Explore Seq+IntegrId from Request", "s7comm-plus.explore.resseqinteg", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Can be calculated by adding Sequencenumber + IntegrityId from corresponding request", HFILL }},

         /* Explore result, variable (tag) description */
        { &hf_s7commp_tagdescr_offsetinfo,
          { "Offset Info", "s7comm-plus.tagdescr.offsetinfo", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_offsetinfotype,
          { "Offsetinfo Type", "s7comm-plus.tagdescr.offsetinfotype", FT_UINT8, BASE_HEX, VALS(tagdescr_offsetinfotype_names), 0x0,
            "Describes how to interpret the last VLQ values", HFILL }},
        { &hf_s7commp_tagdescr_namelength,
          { "Length of name", "s7comm-plus.tagdescr.namelength", FT_UINT8, BASE_DEC, NULL, 0x0,
            "varuint32: Tag description - Length of name", HFILL }},
        { &hf_s7commp_tagdescr_name,
          { "Name", "s7comm-plus.tagdescr.name", FT_STRING, STR_UNICODE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_unknown2,
          { "Unknown 2", "s7comm-plus.tagdescr.unknown2", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_datatype,
          { "Datatype", "s7comm-plus.tagdescr.datatype", FT_UINT8, BASE_HEX, VALS(item_datatype_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_softdatatype,
          { "SoftDataType", "s7comm-plus.tagdescr.softdatatype", FT_UINT32, BASE_DEC | BASE_EXT_STRING, &tagdescr_softdatatype_names_ext, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_tagdescr_attributeflags,
          { "Attributes", "s7comm-plus.tagdescr.attributeflags", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_hostrelevant,
          { "Hostrelevant", "s7comm-plus.tagdescr.attributeflags.hostrelevant", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_HOSTRELEVANT,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_retain,
          { "Plainmember-Retain", "s7comm-plus.tagdescr.attributeflags.retain", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_PLAINMEMBERRETAIN,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_classic,
          { "Plainmember-Classic", "s7comm-plus.tagdescr.attributeflags.classic", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_PLAINMEMBERCLASSIC,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_hmivisible,
          { "HMI-Visible", "s7comm-plus.tagdescr.attributeflags.hmivisible", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_HMIVISIBLE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_hmireadonly,
          { "HMI-Readonly", "s7comm-plus.tagdescr.attributeflags.hmireadonly", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_HMIREADONLY,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_hmicached,
          { "HMI-Cached", "s7comm-plus.tagdescr.attributeflags.hmicached", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_HMICACHED,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_hmiaccessible,
          { "HMI-Accessible", "s7comm-plus.tagdescr.attributeflags.hmiaccessible", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_HMIACCESSIBLE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_isqualifier,
          { "Is-Qualifier", "s7comm-plus.tagdescr.attributeflags.isqualifier", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_ISQUALIFIER,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_normalaccess,
          { "Normal-Access", "s7comm-plus.tagdescr.attributeflags.normalaccess", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_NORMALACCESS,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_needslegitimization,
          { "Needs-Legitimization", "s7comm-plus.tagdescr.attributeflags.needslegitimization", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_NEEDSLEGITIMIZATION,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_changeableinrun,
          { "Changeable-In-Run", "s7comm-plus.tagdescr.attributeflags.changeableinrun", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_CHANGEBLEINRUN,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_serveronly,
          { "Server-Only", "s7comm-plus.tagdescr.attributeflags.serveronly", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_SERVERONLY,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_clientreadonly,
          { "Client-Read-Only", "s7comm-plus.tagdescr.attributeflags.clientreadonly", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_CLIENTREADRONLY,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_seploadmemfa,
          { "Separate-Load-Memory-File-Allowed", "s7comm-plus.tagdescr.attributeflags.seploadmemfa", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_SEPLOADMEMFA,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_asevaluationrequired,
          { "AS-Evaluation-Required", "s7comm-plus.tagdescr.attributeflags.asevaluationrequired", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_ASEVALREQ,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_bl,
          { "BL", "s7comm-plus.tagdescr.attributeflags.bl", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_BL,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_persistent,
          { "Persistent", "s7comm-plus.tagdescr.attributeflags.persistent", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_PERSISTENT,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_core,
          { "Core", "s7comm-plus.tagdescr.attributeflags.core", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_CORE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_isout,
          { "Is-Out", "s7comm-plus.tagdescr.attributeflags.isout", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_ISOUT,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_isin,
          { "Is-In", "s7comm-plus.tagdescr.attributeflags.isin", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_ISIN,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_appwriteable,
          { "App-Writeable", "s7comm-plus.tagdescr.attributeflags.appwriteable", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_APPWRITEABLE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags_appreadable,
          { "App-Readable", "s7comm-plus.tagdescr.attributeflags.appreadable", FT_BOOLEAN, 32, NULL, S7COMMP_TAGDESCR_ATTRIBUTE_APPREADABLE,
            NULL, HFILL }},

        { &hf_s7commp_tagdescr_attributeflags2,
          { "Attributes", "s7comm-plus.tagdescr.attributeflags", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_offsetinfotype,
          { "Offsetinfotype", "s7comm-plus.tagdescr.attributeflags.offsetinfotype", FT_UINT16, BASE_DEC, VALS(tagdescr_offsetinfotype2_names), S7COMMP_TAGDESCR_ATTRIBUTE2_OFFSETINFOTYPE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_hmivisible,
          { "HMI-Visible", "s7comm-plus.tagdescr.attributeflags.hmivisible", FT_BOOLEAN, 16, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_HMIVISIBLE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_bit11,
          { "Bit11", "s7comm-plus.tagdescr.attributeflags.bit11", FT_BOOLEAN, 16, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_BIT11,
            "Bit11: hmireadonly?", HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_hmiaccessible,
          { "HMI-Accessible", "s7comm-plus.tagdescr.attributeflags.hmiaccessible", FT_BOOLEAN, 16, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_HMIACCESSIBLE,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_bit09,
          { "Bit09", "s7comm-plus.tagdescr.attributeflags.bit09", FT_BOOLEAN, 16, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_BIT09,
            "Bit09: HMI-Cached?", HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_optimizedaccess,
          { "OptimizedAccess", "s7comm-plus.tagdescr.attributeflags.optimizedaccess", FT_BOOLEAN, 16, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_OPTIMIZEDACCESS,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_section,
          { "Section", "s7comm-plus.tagdescr.attributeflags.section", FT_UINT16, BASE_DEC, VALS(tagdescr_section_names), S7COMMP_TAGDESCR_ATTRIBUTE2_SECTION,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_bit04,
          { "Bit04", "s7comm-plus.tagdescr.attributeflags.bit04", FT_BOOLEAN, 16, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_BIT04,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_attributeflags2_bitoffset,
          { "Bitoffset", "s7comm-plus.tagdescr.attributeflags.bitoffset", FT_UINT16, BASE_DEC, NULL, S7COMMP_TAGDESCR_ATTRIBUTE2_BITOFFSET,
            NULL, HFILL }},

        { &hf_s7commp_tagdescr_bitoffsetinfo,
          { "Bitoffsetinfo", "s7comm-plus.tagdescr.bitoffsetinfo", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_bitoffsetinfo_retain,
          { "Retain", "s7comm-plus.tagdescr.bitoffsetinfo.retain", FT_BOOLEAN, 8, NULL, S7COMMP_TAGDESCR_BITOFFSETINFO_RETAIN,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_bitoffsetinfo_nonoptbitoffset,
          { "Nonoptimized Bitoffset", "s7comm-plus.tagdescr.bitoffsetinfo.bitoffset.nonoptimized", FT_UINT8, BASE_DEC, NULL, S7COMMP_TAGDESCR_BITOFFSETINFO_NONOPTBITOFFSET,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_bitoffsetinfo_classic,
          { "Classic", "s7comm-plus.tagdescr.bitoffsetinfo.classic", FT_BOOLEAN, 8, NULL, S7COMMP_TAGDESCR_BITOFFSETINFO_CLASSIC,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_bitoffsetinfo_optbitoffset,
          { "Optimized Bitoffset", "s7comm-plus.tagdescr.bitoffsetinfo.bitoffset.optimized", FT_UINT8, BASE_DEC, NULL, S7COMMP_TAGDESCR_BITOFFSETINFO_OPTBITOFFSET,
            NULL, HFILL }},

        { &hf_s7commp_tagdescr_lid,
          { "LID", "s7comm-plus.tagdescr.lid", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Tag description - LID", HFILL }},
        { &hf_s7commp_tagdescr_subsymbolcrc,
          { "Subsymbol CRC", "s7comm-plus.tagdescr.subsymbolcrc", FT_UINT32, BASE_HEX, NULL, 0x0,
            "Calculated CRC from symbol name plus softdatatype-id", HFILL }},
        { &hf_s7commp_tagdescr_s7stringlength,
          { "Length of S7String", "s7comm-plus.tagdescr.s7stringlength", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Length of S7String", HFILL }},
        { &hf_s7commp_tagdescr_structrelid,
          { "Relation Id for Struct", "s7comm-plus.tagdescr.structrelid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_lenunknown,
          { "Unknown for this datatype", "s7comm-plus.tagdescr.lenunknown", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Unknown for this datatype", HFILL }},
        { &hf_s7commp_tagdescr_offsettype1,
          { "OffsetType1", "s7comm-plus.tagdescr.offsettype1", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: OffsetType1", HFILL }},
        { &hf_s7commp_tagdescr_offsettype2,
          { "OffsetType2", "s7comm-plus.tagdescr.offsettype2", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: OffsetType2", HFILL }},
        { &hf_s7commp_tagdescr_bitoffsettype1,
          { "BitOffsetType1", "s7comm-plus.tagdescr.bitoffsettype1", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: BitOffsetType1", HFILL }},
        { &hf_s7commp_tagdescr_bitoffsettype2,
          { "BitOffsetType2", "s7comm-plus.tagdescr.bitoffsettype2", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: BitOffsetType2", HFILL }},
        { &hf_s7commp_tagdescr_arraylowerbounds,
          { "Array lower bounds", "s7comm-plus.tagdescr.arraylowerbounds", FT_INT32, BASE_DEC, NULL, 0x0,
            "varint32: Array lower bounds", HFILL }},
        { &hf_s7commp_tagdescr_arrayelementcount,
          { "Array element count", "s7comm-plus.tagdescr.arrayelementcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Array element count", HFILL }},
        { &hf_s7commp_tagdescr_paddingtype1,
          { "PaddingType1", "s7comm-plus.tagdescr.paddingtype1", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: PaddingType1", HFILL }},
        { &hf_s7commp_tagdescr_paddingtype2,
          { "PaddingType2", "s7comm-plus.tagdescr.paddingtype2", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: PaddingType2", HFILL }},
        { &hf_s7commp_tagdescr_numarraydimensions,
          { "Number of array dimensions", "s7comm-plus.tagdescr.numarraydimensions", FT_UINT32, BASE_DEC, NULL, 0x0,
            "varuint32: Number of array dimensions", HFILL }},
        { &hf_s7commp_tagdescr_nonoptimized_addr,
          { "Nonoptimized address", "s7comm-plus.tagdescr.address.nonoptimized", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_optimized_addr,
          { "Optimized address", "s7comm-plus.tagdescr.address.optimized", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_nonoptimized_addr_16,
          { "Nonoptimized address", "s7comm-plus.tagdescr.address.nonoptimized", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_optimized_addr_16,
          { "Optimized address", "s7comm-plus.tagdescr.address.optimized", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_nonoptimized_struct_size,
          { "Nonoptimized structure size", "s7comm-plus.tagdescr.structsize.nonoptimized", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_optimized_struct_size,
          { "Optimized structure size", "s7comm-plus.tagdescr.structsize.optimized", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_tagdescr_accessability,
          { "Accessability", "s7comm-plus.tagdescr.accessability", FT_UINT32, BASE_DEC, VALS(tagdescr_accessability_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_tagdescr_section,
          { "Section", "s7comm-plus.tagdescr.section", FT_UINT32, BASE_DEC, VALS(tagdescr_section_names), 0x0,
            NULL, HFILL }},

        /* Fields for object traversion */
        { &hf_s7commp_element_object,
          { "Object", "s7comm-plus.object", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_element_attribute,
          { "Attribute", "s7comm-plus.attribute", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_element_relation,
          { "Relation", "s7comm-plus.relation", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_element_tagdescription,
          { "Tagdescription", "s7comm-plus.tagdescription", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_element_block,
          { "Block", "s7comm-plus.block", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_objectqualifier,
          { "ObjectQualifier", "s7comm-plus.objectqualifier", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Extended Keep alive */
        { &hf_s7commp_extkeepalive_reserved1,
          { "Reseved 1", "s7comm-plus.extkeepalive.reserved1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
         { &hf_s7commp_extkeepalive_confirmedbytes,
          { "Confirmed bytes", "s7comm-plus.extkeepalive.confirmedbytes", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Number of confirmed bytes, calculated from header length", HFILL }},
        { &hf_s7commp_extkeepalive_reserved2,
          { "Reseved 2", "s7comm-plus.extkeepalive.reserved2", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_extkeepalive_reserved3,
          { "Reseved 3", "s7comm-plus.extkeepalive.reserved3", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_extkeepalive_message,
          { "Message", "s7comm-plus.extkeepalive.message", FT_STRING, STR_ASCII, NULL, 0x0,
            NULL, HFILL }},

        /* Object */
        { &hf_s7commp_object_relid,
          { "Relation Id", "s7comm-plus.object.relid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_object_classid,
          { "Class Id", "s7comm-plus.object.classid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            "varuint32: Class Id", HFILL }},
        { &hf_s7commp_object_classflags,
          { "Class Flags", "s7comm-plus.object.classflags", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit00,
          { "User1", "s7comm-plus.object.classflags.user1", FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit01,
          { "User2", "s7comm-plus.object.classflags.user2", FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit02,
          { "User3", "s7comm-plus.object.classflags.user3", FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit03,
          { "User4", "s7comm-plus.object.classflags.user4", FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit04,
          { "NativeFixed", "s7comm-plus.object.classflags.nativefixed", FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit05,
          { "Persistent", "s7comm-plus.object.classflags.persistent", FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit06,
          { "Bit06", "s7comm-plus.object.classflags.bit06", FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit07,
          { "Bit07", "s7comm-plus.object.classflags.bit07", FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit08,
          { "TryAquireWriteLocked", "s7comm-plus.object.classflags.tryaquirewritelocked", FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit09,
          { "ChildDeleted", "s7comm-plus.object.classflags.childdeleted", FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit10,
          { "ExclusiveLocked", "s7comm-plus.object.classflags.exclusivelocked", FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit11,
          { "TreeWriteLocked", "s7comm-plus.object.classflags.treewritelocked", FT_BOOLEAN, 32, NULL, 0x00000800,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit12,
          { "Bit12", "s7comm-plus.object.classflags.bit12", FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit13,
          { "NativePlugged", "s7comm-plus.object.classflags.nativeplugged", FT_BOOLEAN, 32, NULL, 0x00002000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit14,
          { "Bit14", "s7comm-plus.object.classflags.bit14", FT_BOOLEAN, 32, NULL, 0x00004000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit15,
          { "Bit15", "s7comm-plus.object.classflags.bit15", FT_BOOLEAN, 32, NULL, 0x00008000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit16,
          { "ClientOnly", "s7comm-plus.object.classflags.clientonly", FT_BOOLEAN, 32, NULL, 0x00010000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit17,
          { "Bit17", "s7comm-plus.object.classflags.bit17", FT_BOOLEAN, 32, NULL, 0x00020000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit18,
          { "Bit18", "s7comm-plus.object.classflags.bit18", FT_BOOLEAN, 32, NULL, 0x00040000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit19,
          { "Bit19", "s7comm-plus.object.classflags.bit19", FT_BOOLEAN, 32, NULL, 0x00080000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit20,
          { "Bit20", "s7comm-plus.object.classflags.bit20", FT_BOOLEAN, 32, NULL, 0x00100000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit21,
          { "SeparateFile", "s7comm-plus.object.classflags.separatefile", FT_BOOLEAN, 32, NULL, 0x00200000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit22,
          { "Bit22", "s7comm-plus.object.classflags.bit22", FT_BOOLEAN, 32, NULL, 0x00400000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit23,
          { "Bit23", "s7comm-plus.object.classflags.bit23", FT_BOOLEAN, 32, NULL, 0x00800000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit24,
          { "Distributed", "s7comm-plus.object.classflags.bit24", FT_BOOLEAN, 32, NULL, 0x01000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit25,
          { "DistributedRoot", "s7comm-plus.object.classflags.bit25", FT_BOOLEAN, 32, NULL, 0x02000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit26,
          { "Bit26", "s7comm-plus.object.classflags.bit26", FT_BOOLEAN, 32, NULL, 0x04000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit27,
          { "Bit27", "s7comm-plus.object.classflags.bit27", FT_BOOLEAN, 32, NULL, 0x08000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit28,
          { "Bit28", "s7comm-plus.object.classflags.bit28", FT_BOOLEAN, 32, NULL, 0x10000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit29,
          { "Bit29", "s7comm-plus.object.classflags.bit29", FT_BOOLEAN, 32, NULL, 0x20000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit30,
          { "Bit30", "s7comm-plus.object.classflags.bit30", FT_BOOLEAN, 32, NULL, 0x40000000,
            NULL, HFILL }},
        { &s7commp_object_classflags_bit31,
          { "Bit31", "s7comm-plus.object.classflags.bit31", FT_BOOLEAN, 32, NULL, 0x80000000,
            NULL, HFILL }},

        { &hf_s7commp_object_attributeid,
          { "Attribute Id", "s7comm-plus.object.attributeid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            "varuint32: Attribute Id", HFILL }},
        { &hf_s7commp_object_attributeidflags,
          { "Attribute Id Flags", "s7comm-plus.object.attributeidflags", FT_UINT32, BASE_HEX, NULL, 0x0,
            "varuint32: Attribute Id Flags", HFILL }},
        { &hf_s7commp_object_relunknown1,
          { "Unknown Value 1", "s7comm-plus.object.relunknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_object_blocklength,
          { "Block length", "s7comm-plus.object.blocklength", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_object_createobjidcount,
          { "Number of following Object Ids", "s7comm-plus.object.createobjidcount", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_object_createobjid,
          { "Object Id", "s7comm-plus.object.createobjid", FT_UINT32, BASE_HEX, NULL, 0x0,
            "varuint32: Object Id", HFILL }},
        { &hf_s7commp_object_deleteobjid,
          { "Delete Object Id", "s7comm-plus.object.deleteobjid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* Setmultivar/Setvariable */
        { &hf_s7commp_setvar_unknown1,
          { "Unknown", "s7comm-plus.setvar.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_setvar_objectid,
          { "In Object Id", "s7comm-plus.setvar.objectid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_setvar_itemcount,
          { "Item count", "s7comm-plus.setvar.itemcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ: Item count", HFILL }},
        { &hf_s7commp_setvar_itemaddrcount,
          { "Item address count", "s7comm-plus.setvar.itemaddrcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ: Item address count", HFILL }},
        { &hf_s7commp_setvar_rawvaluelen,
          { "Raw value length", "s7comm-plus.setvar.rawvaluelen", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ: Raw value length", HFILL }},

        /* GetMultiVariables/GetVariable */
        { &hf_s7commp_getmultivar_unknown1,
          { "Unknown", "s7comm-plus.getmultivar.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_getmultivar_linkid,
          { "Link-Id", "s7comm-plus.setmultivar.linkid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_getmultivar_itemaddrcount,
          { "Item address count", "s7comm-plus.getmultivar.itemaddrcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ: Item address count", HFILL }},
        { &hf_s7commp_getvar_itemcount,
          { "Item count", "s7comm-plus.getvar.itemcount", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* SetVarSubstreamed, stream data */
        { &hf_s7commp_streamdata,
          { "Stream data", "s7comm-plus.streamdata", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_streamdata_frag_data_len,
          { "Stream data (fragment) Length", "s7comm-plus.streamdata.data_length", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_streamdata_frag_data,
          { "Stream data (fragment)", "s7comm-plus.streamdata.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Notification */
        { &hf_s7commp_notification_vl_retval,
          { "Return value", "s7comm-plus.notification.vl.retval", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_vl_refnumber,
          { "Item reference number", "s7comm-plus.notification.vl.refnumber", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_vl_unknown0x9c,
          { "Unknown value after value 0x9c", "s7comm-plus.notification.vl.refnumber", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_notification_subscrobjectid,
          { "Subscription Object Id", "s7comm-plus.notification.subscrobjectid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_unknown2,
          { "Unknown 2", "s7comm-plus.notification.unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_unknown3,
          { "Unknown 3", "s7comm-plus.notification.unknown3", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_unknown4,
          { "Unknown 4", "s7comm-plus.notification.unknown4", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_credittick,
          { "Notification Credit tickcount", "s7comm-plus.notification.credittick", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_seqnum_vlq,
          { "Notification sequence number (VLQ)", "s7comm-plus.notification.seqnum_vlq", FT_UINT32, BASE_DEC, NULL, 0x0,
            "VLQ: Notification sequence number", HFILL }},
        { &hf_s7commp_notification_seqnum_uint8,
          { "Notification sequence number", "s7comm-plus.notification.seqnum_ui8", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_unknown5,
          { "Unknown5", "s7comm-plus.notification.unknown5", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_s7commp_notification_p2_subscrobjectid,
          { "Part 2 - Subscription Object Id", "s7comm-plus.notification.p2.subscrobjectid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_p2_unknown1,
          { "Part 2 - Unknown 1", "s7comm-plus.notification.p2.unknown1", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_p2_unknown2,
          { "Part 2 - Unknown 2", "s7comm-plus.notification.p2.unknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_notification_unknown3b,
          { "Unknown additional 3 bytes, because 1st Object ID > 0x70000000", "s7comm-plus.notification.unknown3b", FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* SubscriptionReferenceList */
        { &hf_s7commp_subscrreflist,
          { "SubscriptionReferenceList", "s7comm-plus.subscrreflist", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_unknown1,
          { "Unknown 1", "s7comm-plus.subscrreflist.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_itemcount_unsubscr,
          { "Number of items to unsubscribe", "s7comm-plus.subscrreflist.itemcount_unsubscr", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_itemcount_subscr,
          { "Number of items to subscribe", "s7comm-plus.subscrreflist.itemcount_subscr", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_unsubscr_list,
          { "Un-Subscription List", "s7comm-plus.subscrreflist.unsubscr_list", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_subscr_list,
          { "Subscription List", "s7comm-plus.subscrreflist.subscr_list", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_item_head,
          { "Head", "s7comm-plus.subscrreflist.item.head", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_subscrreflist_item_head_unknown,
          { "Unknown", "s7comm-plus.subscrreflist.item.head_unkn", FT_UINT32, BASE_HEX, NULL, 0xffff0000,
            "left word of head", HFILL }},
        { &hf_s7commp_subscrreflist_item_head_lidcnt,
          { "Number of following IDs", "s7comm-plus.subscrreflist.item.head_lidcnt", FT_UINT32, BASE_DEC, NULL, 0xffff,
            "right word of head", HFILL }},
        { &hf_s7commp_subscrreflist_item_unknown1,
          { "Unknown 1", "s7comm-plus.subscrreflist.item.unknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* SecurityKeyEncryptedKey */
        { &hf_s7commp_securitykeyencryptedkey,
          { "Encrypted key", "s7comm-plus.securitykeyencryptedkey", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_magic,
          { "Magic", "s7comm-plus.securitykeyencryptedkey.magic", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_length,
          { "Length", "s7comm-plus.securitykeyencryptedkey.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_unknown1,
          { "Unknown 1", "s7comm-plus.securitykeyencryptedkey.unknown1", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_unknown2,
          { "Unknown 2", "s7comm-plus.securitykeyencryptedkey.unknown2", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_symmetrickeychecksum,
          { "Symmetric key checksum", "s7comm-plus.securitykeyencryptedkey.symmetrickey.checksum", FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_symmetrickeyflags,
          { "Symmetric key flags", "s7comm-plus.securitykeyencryptedkey.symmetrickey.flags", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_symmetrickeyflags_internal,
          { "Symmetric key internal flags", "s7comm-plus.securitykeyencryptedkey.symmetrickey.flags_internal", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_publickeychecksum,
          { "Public key checksum", "s7comm-plus.securitykeyencryptedkey.publickey.checksum", FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_publickeyflags,
          { "Public key flags", "s7comm-plus.securitykeyencryptedkey.publickey.flags", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_publickeyflags_internal,
          { "Public key internal flags", "s7comm-plus.securitykeyencryptedkey.publickey.flags_internal", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_encrypted_random_seed,
          { "Encrypted random seed", "s7comm-plus.securitykeyencryptedkey.encrypted_random_seed", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_encryption_init_vector,
          { "Encryption initialisation vector", "s7comm-plus.securitykeyencryptedkey.encryption_init_vector", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_securitykeyencryptedkey_encrypted_challenge,
          { "Encrypted challenge", "s7comm-plus.securitykeyencryptedkey.encrypted_challenge", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* zlib compressed blob */
        { &hf_s7commp_compressedblob,
          { "zlib compressed blob", "s7comm-plus.compressedblob", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_compressedblob_dictionary_version,
          { "Dictionary version", "s7comm-plus.compressedblob.dictionary_version", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_compressedblob_dictionary_id,
          { "Dictionary checksum (Adler-32)", "s7comm-plus.compressedblob.dictionary_id", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* MultipleStai */
        { &hf_s7commp_multiplestai,
          { "MultipleStai", "s7comm-plus.multiplestai", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_multiplestai_alid,
          { "Alid", "s7comm-plus.multiplestai.alid", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_multiplestai_alarmdomain,
          { "AlarmDomain", "s7comm-plus.multiplestai.alarmdomain", FT_UINT16, BASE_DEC, VALS(multiplestai_alarmdomains), 0x0,
            "AlarmDomain: Alarm was created by... When user, then with display class", HFILL }},
        { &hf_s7commp_multiplestai_messagetype,
          { "MessageType", "s7comm-plus.multiplestai.messagetype", FT_UINT16, BASE_DEC, VALS(multiplestai_messagetypes), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_multiplestai_alarmenabled,
          { "AlarmEnabled", "s7comm-plus.multiplestai.alarmenabled", FT_UINT8, BASE_DEC, VALS(no_yes_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_multiplestai_hmiinfo_length,
          { "HmiInfo length", "s7comm-plus.multiplestai.hmiinfo_length", FT_UINT16, BASE_DEC, NULL, 0x0,
            "HmiInfo length, constant 9", HFILL }},
        { &hf_s7commp_multiplestai_lidcount,
          { "LidCount", "s7comm-plus.multiplestai.lidcount", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_multiplestai_lid,
          { "Lids", "s7comm-plus.multiplestai.lids", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        /* HmiInfo */
        { &hf_s7commp_hmiinfo,
          { "HmiInfo", "s7comm-plus.hmiinfo", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_hmiinfo_syntaxid,
          { "SyntaxId", "s7comm-plus.hmiinfo.syntaxid", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_hmiinfo_version,
          { "Version", "s7comm-plus.hmiinfo.version", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_hmiinfo_clientalarmid,
          { "ClientAlarmId", "s7comm-plus.hmiinfo.clientalarmid", FT_UINT32, BASE_DEC, NULL, 0x0,
            "ClientAlarmId: CPU oriented unique alarm ID", HFILL }},
        { &hf_s7commp_hmiinfo_priority,
          { "Priority", "s7comm-plus.hmiinfo.priority", FT_UINT8, BASE_DEC, NULL, 0x0,
            "Priority of the alarm", HFILL }},

        /* Getlink */
        { &hf_s7commp_getlink_requnknown1,
          { "Request unknown 1", "s7comm-plus.getlink.requnknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_getlink_requnknown2,
          { "Request unknown 2", "s7comm-plus.getlink.requnknown2", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_getlink_linkidcount,
          { "Number of following Link-Ids", "s7comm-plus.getlink.linkidcount", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_getlink_linkid,
          { "Link-Id", "s7comm-plus.getlink.linkid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* BeginSequence */
        { &hf_s7commp_beginseq_transactiontype,
          { "Transaction Type", "s7comm-plus.beginseq.transactiontype", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_beginseq_valtype,
          { "Unknown / Type of value", "s7comm-plus.beginseq.valtype", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Following value: When 1 then object, when 18 then Id", HFILL }},
        { &hf_s7commp_beginseq_requnknown3,
          { "Request unknown 3", "s7comm-plus.beginseq.requnknown3", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Not always 2 bytes, sometimes only 1 byte", HFILL }},
        { &hf_s7commp_beginseq_requestid,
          { "Request Id", "s7comm-plus.beginseq.requestid", FT_UINT32, BASE_CUSTOM, CF_FUNC(s7commp_idname_fmt), 0x0,
            NULL, HFILL }},

        /* EndSequence */
        { &hf_s7commp_endseq_requnknown1,
          { "Request unknown 1", "s7comm-plus.endseq.requnknown1", FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* Invoke */
        { &hf_s7commp_invoke_subsessionid,
          { "Sub Session Id", "s7comm-plus.invoke.subsessionid", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_invoke_requnknown1,
          { "Request unknown 1", "s7comm-plus.invoke.requnknown1", FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_invoke_requnknown2,
          { "Request unknown 2", "s7comm-plus.invoke.requnknown2", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_invoke_resunknown1,
          { "Response unknown 1", "s7comm-plus.invoke.resunknown1", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        /* Integrity part for 1500 */
        { &hf_s7commp_integrity,
          { "Integrity part", "s7comm-plus.integrity", FT_NONE, BASE_NONE, NULL, 0x0,
            "Integrity part for 1500", HFILL }},
        { &hf_s7commp_integrity_id,
          { "Integrity Id", "s7comm-plus.integrity.id", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_integrity_digestlen,
          { "Digest Length", "s7comm-plus.integrity.digestlen", FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_integrity_digest,
          { "Packet Digest", "s7comm-plus.integrity.digest", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /*** Trailer fields ***/
        { &hf_s7commp_trailer,
          { "Trailer", "s7comm-plus.trailer", FT_NONE, BASE_NONE, NULL, 0x0,
            "This is the trailer part of S7 communication plus", HFILL }},
        { &hf_s7commp_trailer_protid,
          { "Protocol Id", "s7comm-plus.trailer.protid", FT_UINT8, BASE_HEX, NULL, 0x0,
            "Protocol Identification", HFILL }},
        { &hf_s7commp_trailer_protocolversion,
          { "Protocol version", "s7comm-plus.trailer.protocolversion", FT_UINT8, BASE_HEX, VALS(protocolversion_names), 0x0,
            NULL, HFILL }},
        { &hf_s7commp_trailer_datlg,
          { "Data length", "s7comm-plus.trailer.datlg", FT_UINT16, BASE_DEC, NULL, 0x0,
            "Specifies the entire length of the data block in bytes", HFILL }},

        /* Fragment fields */
        { &hf_s7commp_fragment_overlap,
          { "Fragment overlap", "s7comm-plus.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }},
        { &hf_s7commp_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap", "s7comm-plus.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},
        { &hf_s7commp_fragment_multiple_tails,
          { "Multiple tail fragments found", "s7comm-plus.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},
        { &hf_s7commp_fragment_too_long_fragment,
          { "Fragment too long", "s7comm-plus.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},
        { &hf_s7commp_fragment_error,
          { "Defragmentation error", "s7comm-plus.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }},
        { &hf_s7commp_fragment_count,
          { "Fragment count", "s7comm-plus.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_reassembled_in,
          { "Reassembled in", "s7comm-plus.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "S7COMM-PLUS fragments are reassembled in the given packet", HFILL }},
        { &hf_s7commp_reassembled_length,
          { "Reassembled S7COMM-PLUS length", "s7comm-plus.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},
        { &hf_s7commp_fragment,
          { "S7COMM-PLUS Fragment", "s7comm-plus.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
        { &hf_s7commp_fragments,
          { "S7COMM-PLUS Fragments", "s7comm-plus.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        /* Dummy header-field for conversion to wireshark 2.0. Should be removed competely later. */
        { &hf_s7commp_proto_tree_add_text_dummy,
          { "TEXT", "s7comm-plus.proto_tree_add_text_dummy", FT_STRING, BASE_NONE, NULL, 0,
             NULL, HFILL }}
    };

    static ei_register_info ei[] = {
        { &ei_s7commp_blobdecompression_nodictionary,
          { "s7comm-plus.blobdecompression.dictionary.not_found", PI_UNDECODED, PI_WARN, "Blob decompression no dictionary found", EXPFILL }},
        { &ei_s7commp_blobdecompression_xmlsubdissector_failed,
          { "s7comm-plus.blobdecompression.xmlsubdissector.failed", PI_UNDECODED, PI_WARN, "Blob decompression XML subdissector failed", EXPFILL }},
        { &ei_s7commp_blobdecompression_failed,
          { "s7comm-plus.blobdecompression.failed", PI_UNDECODED, PI_WARN, "Blob decompression failed", EXPFILL }},
        { &ei_s7commp_integrity_digestlen_error,
          { "s7comm-plus.integrity.digestlen.error", PI_PROTOCOL, PI_WARN, "Integrity digest length not 32", EXPFILL }},
        { &ei_s7commp_value_unknown_type,
          { "s7comm-plus.item.val.unknowntype_error", PI_UNDECODED, PI_WARN, "Unknown value datatype", EXPFILL }},
        { &ei_s7commp_notification_returnvalue_unknown,
          { "s7comm-plus.notification.vl.retval.unknown_error", PI_UNDECODED, PI_WARN, "Notification unknown return value", EXPFILL }},
        { &ei_s7commp_data_opcode_unknown,
          { "s7comm-plus.data.opcode.unknown_error", PI_UNDECODED, PI_WARN, "Unknown Opcode", EXPFILL }}
    };

    static gint *ett[] = {
        &ett_s7commp,
        &ett_s7commp_header,
        &ett_s7commp_data,
        &ett_s7commp_data_item,
        &ett_s7commp_data_returnvalue,
        &ett_s7commp_trailer,
        &ett_s7commp_data_req_set,
        &ett_s7commp_data_res_set,
        &ett_s7commp_notification_set,
        &ett_s7commp_itemaddr_area,
        &ett_s7commp_itemval_datatype_flags,
        &ett_s7commp_itemval_array,
        &ett_s7commp_packedstruct,
        &ett_s7commp_tagdescr_attributeflags,
        &ett_s7commp_tagdescr_bitoffsetinfo,
        &ett_s7commp_tagdescr_offsetinfo,
        &ett_s7commp_element_object,
        &ett_s7commp_element_attribute,
        &ett_s7commp_element_relation,
        &ett_s7commp_element_tagdescription,
        &ett_s7commp_element_block,
        &ett_s7commp_valuelist,
        &ett_s7commp_errorvaluelist,
        &ett_s7commp_addresslist,
        &ett_s7commp_objectqualifier,
        &ett_s7commp_integrity,
        &ett_s7commp_fragments,
        &ett_s7commp_fragment,
        &ett_s7commp_object_classflags,
        &ett_s7commp_streamdata,
        &ett_s7commp_subscrreflist,
        &ett_s7commp_subscrreflist_item_head,
        &ett_s7commp_securitykeyencryptedkey,
        &ett_s7commp_compressedblob,
        &ett_s7commp_attrib_general
    };

    module_t *s7commp_module;
    expert_module_t * expert_s7commp;

    proto_s7commp = proto_register_protocol (
        "S7 Communication Plus",            /* name */
        "S7COMM-PLUS",                      /* short name */
        "s7comm-plus"                       /* abbrev */
    );

    proto_register_field_array(proto_s7commp, hf, array_length (hf));
    proto_register_subtree_array(ett, array_length (ett));
    expert_s7commp = expert_register_protocol(proto_s7commp);
    expert_register_field_array(expert_s7commp, ei, array_length(ei));

    s7commp_module = prefs_register_protocol(proto_s7commp, NULL);

    prefs_register_bool_preference(s7commp_module, "reassemble",
                                   "Reassemble segmented S7COMM-PLUS telegrams",
                                   "Whether segmented S7COMM-PLUS telegrams should be "
                                   "reassembled.",
                                   &s7commp_reassemble);

    prefs_register_bool_preference(s7commp_module, "decompress_blobs",
                                   "Uncompress S7COMM-PLUS blobs",
                                   "Whether to uncompress S7COMM-PLUS blobs ",
                                   &s7commp_opt_decompress_blobs);

    /* Register the init routine. */
    register_init_routine(s7commp_defragment_init);
}


/*******************************************************************************************************
* Dummy proto_tree_add_text function used for conversion to Wireshark 2.0.
* As the function proto_tree_add_text() is no longer public in the libwireshark, because you should
* use appropriate header-fields.
* But for reverse-engineering, this is much easier to use.
* This should be removed competely later.
*******************************************************************************************************/
static proto_item *
proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb, gint start, gint length, const char *format, ...)
{
    proto_item *pi;
    va_list ap;
    gchar *s;

    s = (gchar *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH);
    s[0] = '\0';

    va_start(ap, format);
    g_vsnprintf(s, ITEM_LABEL_LENGTH, format, ap);
    va_end(ap);

    pi = proto_tree_add_string_format(tree, hf_s7commp_proto_tree_add_text_dummy, tvb, start, length, "DUMMY", "%s", s);
    return pi;
}

/*******************************************************************************************************
* Helper function for adding the id-name to the given proto_tree.
* If the given id is known in the id_number_names_ext list, then text+id is added,
* otherwise only the id.
*******************************************************************************************************/
static void
s7commp_proto_item_append_idname(proto_tree *tree, guint32 id_number, gchar *str_prefix)
{
    gchar *result;

    result = (gchar *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH);
    s7commp_idname_fmt(result, id_number);
    if (str_prefix) {
        proto_item_append_text(tree, "%s%s", str_prefix, result);
    } else {
        proto_item_append_text(tree, "%s", result);
    }
}
/*******************************************************************************************************
* Helper function for adding the id-name to the given pinfo column.
* If the given id is known in the id_number_names_ext list, then text+id is added,
* otherwise only the id.
*******************************************************************************************************/
static void
s7commp_pinfo_append_idname(packet_info *pinfo, guint32 id_number, gchar *str_prefix)
{
    gchar *result;

    result = (gchar *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH);
    s7commp_idname_fmt(result, id_number);
    if (str_prefix) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%s", str_prefix, result);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", result);
    }
}
/*******************************************************************************************************
 *
 * Spezial gepacktes Datenformat
 * siehe: http://en.wikipedia.org/wiki/Variable-length_quantity
 *
 * In der Datei packet-wap.c gibt es eine Funktion fuer unsigned:
 * guint tvb_get_guintvar (tvbuff_t *tvb, guint offset, guint *octetCount)
 * welche aber keine Begrenzung auf eine max-Anzahl hat (5 fuer int32).
 * Solange das Protokoll noch nicht sicher erkannt wird, ist diese Version hier sicherer.
 *
 *******************************************************************************************************/
static guint32
tvb_get_varint32(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    gint32 val = 0;
    guint8 octet;
    guint8 cont;

    for (counter = 1; counter <= 4+1; counter++) {
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        if ((counter == 1) && (octet & 0x40)) {     /* check sign */
            octet &= 0xbf;
            val = 0xffffffc0;                       /* pre-load with one complement, excluding first 6 bits */
        } else {
            val <<= 7;
        }
        cont = (octet & 0x80);
        octet &= 0x7f;
        val += octet;
        if (cont == 0) {
            break;
        }
    }
    *octet_count = counter;
    return val;
}
/*******************************************************************************************************/
static guint32
tvb_get_varuint32(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    gint32 val = 0;
    guint8 octet;
    guint8 cont;
    for (counter = 1; counter <= 4+1; counter++) {        /* grosse Werte benoetigen 5 Bytes: 4*7 bit + 4 bit */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        val <<= 7;
        cont = (octet & 0x80);
        octet &= 0x7f;
        val += octet;
        if (cont == 0) {
            break;
        }
    }
    *octet_count = counter;
    return  val;
}
/*******************************************************************************************************/
static guint64
tvb_get_varuint64(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    guint64 val = 0;
    guint8 octet;
    guint8 cont;
    for (counter = 1; counter <= 8; counter++) {        /* 8*7 bit + 8 bit = 64 bit -> Sonderfall im letzten Octett! */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        val <<= 7;
        cont = (octet & 0x80);
        octet &= 0x7f;
        val += octet;
        if (cont == 0) {
            break;
        }
    }
    *octet_count = counter;
    if (cont) {        /* 8*7 bit + 8 bit = 64 bit -> Sonderfall im letzten Octett! */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        val <<= 8;
        val += octet;
    }
    return  val;
}
/*******************************************************************************************************/
static gint64
tvb_get_varint64(tvbuff_t *tvb, guint8 *octet_count, guint32 offset)
{
    int counter;
    gint64 val = 0;
    guint8 octet;
    guint8 cont;
    for (counter = 1; counter <= 8; counter++) {  /* 8*7 bit + 8 bit = 64 bit -> Sonderfall im letzten Octett! */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        if ((counter == 1) && (octet & 0x40)) {   /* check sign */
            octet &= 0xbf;
            val = 0xffffffffffffffc0;             /* pre-load with one complement, excluding first 6 bits */
        } else {
            val <<= 7;
        }
        cont = (octet & 0x80);
        octet &= 0x7f;
        val += octet;
        if (cont == 0) {
            break;
        }
    }
    *octet_count = counter;
    if (cont) {        /* 8*7 bit + 8 bit = 64 bit -> Sonderfall im letzten Octett! */
        octet = tvb_get_guint8(tvb, offset);
        offset += 1;
        val <<= 8;
        val += octet;
    }
    return  val;
}
/*******************************************************************************************************
 *
 * Funktionen zum Hinzufuegen eines VLQ Wertes zu proto_tree.
 *
 * Die Funktionen sind in Anlehnung an die Wireshark internen Funktionen aus proto.c erstellt.
 * Die Anzahl Bytes welche der VLQ benoetigt, wird in octet_count geschrieben.
 * Die _ret_ Funktionen geben zusaetzlich in retval den eigentlichen Wert zurueck.
 *
 *******************************************************************************************************/
static proto_item *
proto_tree_add_varuint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, guint8 *octet_count)
{
    guint32 value;

    *octet_count = 0;
    value = tvb_get_varuint32(tvb, octet_count, start);
    return proto_tree_add_uint(tree, hfindex, tvb, start, *octet_count, value);
}
/*******************************************************************************************************/
static proto_item *
proto_tree_add_ret_varuint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, guint8 *octet_count, guint32 *retval)
{
    guint32 value;

    *octet_count = 0;
    value = tvb_get_varuint32(tvb, octet_count, start);
    if (retval) {
        *retval = value;
    }
    return proto_tree_add_uint(tree, hfindex, tvb, start, *octet_count, value);
}
/*******************************************************************************************************/
#if 0 // the following function causes an unused function warning
static proto_item *
proto_tree_add_varint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, guint8 *octet_count)
{
    gint32 value;

    *octet_count = 0;
    value = tvb_get_varint32(tvb, octet_count, start);
    return proto_tree_add_int(tree, hfindex, tvb, start, *octet_count, value);
}
#endif
/*******************************************************************************************************/
static proto_item *
proto_tree_add_ret_varint32(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, guint8 *octet_count, gint32 *retval)
{
    gint32 value;

    *octet_count = 0;
    value = tvb_get_varint32(tvb, octet_count, start);
    if (retval) {
        *retval = value;
    }
    return proto_tree_add_int(tree, hfindex, tvb, start, *octet_count, value);
}
/*******************************************************************************************************
 *
 * Returns a timestamp as string from a unix-timestamp 64 bit value. Needs a char array of size 34.
 * Format:
 * Jan 31, 2014 23:59:59.999.999.999
 *
 *******************************************************************************************************/
static void
s7commp_get_timestring_from_uint64(guint64 timestamp, char *str, gint max)
{
    guint16 nanosec, microsec, millisec;
    struct tm *mt;
    time_t t;

    nanosec = timestamp % 1000;
    timestamp /= 1000;
    microsec = timestamp % 1000;
    timestamp /= 1000;
    millisec = timestamp % 1000;
    timestamp /= 1000;
    t = timestamp;
    mt = gmtime(&t);
    str[0] = '\0';
    if (mt != NULL) {
        g_snprintf(str, max, "%s %2d, %d %02d:%02d:%02d.%03d.%03d.%03d", mon_names[mt->tm_mon], mt->tm_mday,
            mt->tm_year + 1900, mt->tm_hour, mt->tm_min, mt->tm_sec,
            millisec, microsec, nanosec);
    }
}
/*******************************************************************************************************
 *
 * Timespan (LT / LTIME) is interpreted as nanoseconds.
 * Use the display style from programming software:
 * LT#-106751d_23h_47m_16s_854ms_775us_808ns
 * LT#+106751d_23h_47m_16s_854ms_775us_807ns
 * Needs at least 42 chars.
 *
 *******************************************************************************************************/
static void
s7commp_get_timespan_from_int64(gint64 timespan, char *str, gint max)
{
    gchar sval[8];
    gint64 divs[] = { 86400000000000LL, 3600000000000LL, 60000000000LL, 1000000000LL, 1000000LL, 1000LL, 1LL};
    gchar *vfmt[] = { "%dd", "%02dh", "%02dm", "%02ds", "%03dms", "%03dus", "%03dns"};
    gint64 val;
    int i;

    if (timespan == 0) {
        g_strlcpy(str, "LT#000ns", max);
        return;
    }

    if (timespan < 0) {
        g_strlcpy(str, "LT#-", max);
        timespan *= -1;
    } else {
        g_strlcpy(str, "LT#", max);
    }

    for (i = 0; i < 7; i++) {
        val = timespan / divs[i];
        timespan -= val * divs[i];
        if (val > 0) {
            g_snprintf(sval, 8, vfmt[i], (gint32)val);
            g_strlcat(str, sval, max);
            if (timespan > 0) {
                g_strlcat(str, "_", max);
            }
        }
    }
}
/*******************************************************************************************************
 *
 * Decode the integrity part
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_integrity(tvbuff_t *tvb,
                         packet_info *pinfo,
                         proto_tree *tree,
                         gboolean has_integrity_id,
                         guint32 offset)
{
    guint32 offset_save;
    guint8 integrity_len = 0;
    guint8 octet_count = 0;

    proto_item *integrity_item = NULL;
    proto_tree *integrity_tree = NULL;

    offset_save = offset;
    integrity_item = proto_tree_add_item(tree, hf_s7commp_integrity, tvb, offset, -1, FALSE );
    integrity_tree = proto_item_add_subtree(integrity_item, ett_s7commp_integrity);
    /* In DeleteObject-Response, the Id is missing if the deleted id is > 0x7000000!
     * This check is done by the decoding function for deleteobject. By default there is an Id.
     *
     * The integrity_id seems to be increased by one in each telegram. The integrity_id in the corresponding
     * response is calculated by adding the sequencenumber to the integrity_id from request.
     */
    if (has_integrity_id) {
        proto_tree_add_varuint32(integrity_tree, hf_s7commp_integrity_id, tvb, offset, &octet_count);
        offset += octet_count;
    }

    integrity_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(integrity_tree, hf_s7commp_integrity_digestlen, tvb, offset, 1, integrity_len);
    offset += 1;
    /* Length should always be 32. If not, then the previous decoding was not correct.
     * To prevent malformed packet errors, check this.
     */
    if (integrity_len == 32) {
        proto_tree_add_item(integrity_tree, hf_s7commp_integrity_digest, tvb, offset, integrity_len, ENC_NA);
        offset += integrity_len;
    } else {
        expert_add_info(pinfo, integrity_tree, &ei_s7commp_integrity_digestlen_error);
        proto_tree_add_text(integrity_tree, tvb, offset-1, 1, "Error in dissector: Integrity Digest length should be 32!");
        col_append_str(pinfo->cinfo, COL_INFO, " (DISSECTOR-ERROR)"); /* add info that something went wrong */
    }
    proto_item_set_len(integrity_tree, offset - offset_save);
    return offset;
}
/*******************************************************************************************************
 *
 * Decode the integrity part with integrity id and integrity part (optional)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_integrity_wid(tvbuff_t *tvb,
                             packet_info *pinfo,
                             proto_tree *tree,
                             gboolean has_integrity_id,
                             guint8 protocolversion,
                             gint *dlength,
                             guint32 offset)
{
    guint32 offset_save = 0;
    guint8 octet_count = 0;

    if (protocolversion == S7COMMP_PROTOCOLVERSION_3) {
        /* Pakete mit neuerer Firmware haben den Wert / id am Ende, der bei anderen FW vor der Integritaet kommt.
         * Dieser ist aber nicht bei jedem Typ vorhanden. Wenn nicht, dann sind 4 Null-Bytes am Ende.
         */
        if ((*dlength > 4) && has_integrity_id) {
            proto_tree_add_varuint32(tree, hf_s7commp_integrity_id, tvb, offset, &octet_count);
            offset += octet_count;
            *dlength -= octet_count;
        }
    } else {
        if (*dlength > 4 && *dlength < 32 && has_integrity_id) {
            /* Plcsim fuer die 1500 verwendet keine Integritaet, dafuer gibt es aber am Endeblock (vor den ueblichen 4 Nullbytes)
             * eine fortlaufende Nummer.
             * Vermutlich ist das trotzdem die Id, aber der andere Teil fehlt dann. Wenn die vorige Response ebenfalls eine
             * Id hatte, dann wird die fuer den naechsten Request wieder aus der letzten Id+Seqnum berechnet, d.h. so wie auch
             * bei der Id wenn es einen kompletten Integritaetsteil gibt.
             * War dort keine vorhanden, dann wird immer um 1 erhoeht.
             * Unklar was fuer eine Funktion das haben soll.
             */
            proto_tree_add_varuint32(tree, hf_s7commp_integrity_id, tvb, offset, &octet_count);
            offset += octet_count;
            *dlength -= octet_count;
        } else if (*dlength >= 32) {
            offset_save = offset;
            offset = s7commp_decode_integrity(tvb, pinfo, tree, has_integrity_id, offset);
            *dlength -= (offset - offset_save);
        }
    }

    return offset;
}

/*******************************************************************************************************
 *
 * Decodes a return value, coded as 64 Bit VLQ. Includes an errorcode and some flags.
 * If pinfo is not NULL, then some information about the returnvalue are added to the info column.
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_returnvalue(tvbuff_t *tvb,
                           packet_info *pinfo,
                           proto_tree *tree,
                           guint32 offset,
                           gint16 *errorcode_out,
                           gboolean *errorextension_out)
{
    guint64 return_value;
    guint8 octet_count = 0;
    gint16 errorcode;
    proto_item *ret_item = NULL;

    return_value = tvb_get_varuint64(tvb, &octet_count, offset);
    errorcode = (gint16)return_value;
    ret_item = proto_tree_add_bitmask_value(tree, tvb, offset, hf_s7commp_data_returnvalue,
        ett_s7commp_data_returnvalue, s7commp_data_returnvalue_fields, return_value);
    proto_item_set_len(ret_item, octet_count);
    offset += octet_count;
    if (errorcode_out) {        /* return errorcode if needed outside */
        *errorcode_out = errorcode;
    }
    if (errorextension_out) {
        *errorextension_out = ((return_value & G_GUINT64_CONSTANT(0x4000000000000000)) > 0);
    }

    /* add info about return value to info column */
    if (pinfo) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Retval=%s", val64_to_str_const(errorcode, errorcode_names, "Unknown"));
    }

    return offset;
}

/*******************************************************************************************************
 *
 * Decoding of an ULInt value as timestamp
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_ulint_timestamp(tvbuff_t *tvb,
                                      proto_tree *tree,
                                      guint32 offset,
                                      guint8 datatype)
{
    guint64 uint64val = 0;
    guint8 octet_count = 0;
    gchar *str_val = NULL;
    proto_item *pi = NULL;

    if (datatype != S7COMMP_ITEM_DATATYPE_ULINT) {
        return offset;
    }

    str_val = (gchar *)wmem_alloc(wmem_packet_scope(), S7COMMP_ITEMVAL_STR_VAL_MAX);
    str_val[0] = '\0';

    uint64val = tvb_get_varuint64(tvb, &octet_count, offset);
    s7commp_get_timestring_from_uint64(uint64val, str_val, S7COMMP_ITEMVAL_STR_VAL_MAX);
    pi = proto_tree_add_text(tree, tvb, offset, octet_count, "Timestamp: %s", str_val);
    offset += octet_count;

    PROTO_ITEM_SET_GENERATED(pi);
    return offset;
}

/*******************************************************************************************************
 *
 * Decoding if attribute Blocklanguage (ID 2523)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_blocklanguage(tvbuff_t *tvb,
                                    proto_tree *tree,
                                    guint32 offset,
                                    guint8 datatype)
{
    guint16 blocklang;
    proto_item *pi = NULL;

    if (datatype != S7COMMP_ITEM_DATATYPE_UINT) {
        return offset;
    }

    blocklang = tvb_get_ntohs(tvb, offset);
    pi = proto_tree_add_text(tree, tvb, offset, 2, "Blocklanguage: %s", val_to_str(blocklang, attrib_blocklanguage_names, "Unknown Blocklanguage: %u"));
    offset += 2;

    PROTO_ITEM_SET_GENERATED(pi);
    return offset;
}
/*******************************************************************************************************
 *
 * Decoding if attribute ServerSessionRole (ID 299)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_serversessionrole(tvbuff_t *tvb,
                                        proto_tree *tree,
                                        guint32 offset,
                                        guint8 datatype)
{
    guint32 role;
    guint8 octet_count = 0;
    proto_item *pi = NULL;

    if (datatype != S7COMMP_ITEM_DATATYPE_UDINT) {
        return offset;
    }

    role = tvb_get_varuint32(tvb, &octet_count, offset);
    pi = proto_tree_add_text(tree, tvb, offset, octet_count, "ServerSessionRole: %s", val_to_str(role, attrib_serversessionrole, "Unknown ServerSessionRole: 0x%08x"));
    offset += octet_count;
    PROTO_ITEM_SET_GENERATED(pi);

    return offset;
}
/*******************************************************************************************************
 *
 * Decoding of attribute DAI.HmiInfo (7813)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_hmiinfo(tvbuff_t *tvb,
                              proto_tree *tree,
                              guint32 offset,
                              guint8 datatype,
                              guint32 length_of_value)
{
    proto_item *pi = NULL;
    proto_tree *subtree = NULL;

    if (datatype != S7COMMP_ITEM_DATATYPE_BLOB || length_of_value != 9) {
        return offset;
    }

    pi = proto_tree_add_item(tree, hf_s7commp_hmiinfo, tvb, offset, 9, FALSE);
    PROTO_ITEM_SET_GENERATED(pi);
    subtree = proto_item_add_subtree(pi, ett_s7commp_attrib_general);

    proto_tree_add_item(subtree, hf_s7commp_hmiinfo_syntaxid, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(subtree, hf_s7commp_hmiinfo_version, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(subtree, hf_s7commp_hmiinfo_clientalarmid, tvb, offset, 4, ENC_NA);
    offset += 4;
    proto_tree_add_item(subtree, hf_s7commp_hmiinfo_priority, tvb, offset, 1, ENC_NA);
    offset += 1;

    return offset;
}
/*******************************************************************************************************
 *
 * Decoding Of attribute MultipleSTAI.STAIs (ID 7859)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_multiplestais(tvbuff_t *tvb,
                                    proto_tree *tree,
                                    guint32 offset,
                                    guint8 datatype,
                                    guint32 length_of_value)
{
    proto_item *pi = NULL;
    proto_tree *subtree = NULL;
    int lidcount, i;
    guint16 hmiinfo_length;
    guint16 messagetype;

    if (datatype != S7COMMP_ITEM_DATATYPE_BLOB || length_of_value < 20) {
        return offset;
    }

    pi = proto_tree_add_item(tree, hf_s7commp_multiplestai, tvb, offset, length_of_value, FALSE);
    PROTO_ITEM_SET_GENERATED(pi);
    subtree = proto_item_add_subtree(pi, ett_s7commp_attrib_general);

    proto_tree_add_item(subtree, hf_s7commp_multiplestai_alid, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(subtree, hf_s7commp_multiplestai_alarmdomain, tvb, offset, 2, ENC_NA);
    offset += 2;
    messagetype = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_s7commp_multiplestai_messagetype, tvb, offset, 2, ENC_NA);
    offset += 2;
    proto_tree_add_item(subtree, hf_s7commp_multiplestai_alarmenabled, tvb, offset, 1, ENC_NA);
    offset += 1;

    hmiinfo_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(subtree, hf_s7commp_multiplestai_hmiinfo_length, tvb, offset, 2, ENC_NA);
    offset += 2;
    /* hmiinfo erkennt z.Zt. nur korrekt Alarm AP mit length = 9 */
    if (messagetype == S7COMMP_MULTIPLESTAI_MESSAGETYPE_ALARMAP && hmiinfo_length == 9) {
        offset = s7commp_decode_attrib_hmiinfo(tvb, subtree, offset, S7COMMP_ITEM_DATATYPE_BLOB, hmiinfo_length);

        lidcount = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(subtree, hf_s7commp_multiplestai_lidcount, tvb, offset, 2, ENC_NA);
        offset += 2;

        for (i = 0; i < lidcount; i++) {
            proto_tree_add_item(subtree, hf_s7commp_multiplestai_lid, tvb, offset, 4, ENC_NA);
            offset += 4;
        }
    } else {
        /* TODO */
        offset += hmiinfo_length;
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Decoding of attribute FilterOperation (1247)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_filteroperation(tvbuff_t *tvb,
                                    proto_tree *tree,
                                    guint32 offset,
                                    guint8 datatype)
{
    gint32 operation;
    guint8 octet_count = 0;
    proto_item *pi = NULL;

    if (datatype != S7COMMP_ITEM_DATATYPE_DINT) {
        return offset;
    }

    operation = tvb_get_varint32(tvb, &octet_count, offset);
    pi = proto_tree_add_text(tree, tvb, offset, octet_count, "FilterOperation: %s", val_to_str(operation, attrib_filteroperation, "Unknown operation: %d"));
    offset += octet_count;

    PROTO_ITEM_SET_GENERATED(pi);
    return offset;
}
/*******************************************************************************************************
 *
 * Decoding of attribute SecurityKeyEncryptedKey (ID 1805)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_securitykeyencryptedkey(tvbuff_t *tvb,
                                              proto_tree *tree,
                                              guint32 offset,
                                              guint8 datatype,
                                              guint32 blobsize)
{
    guint32 varsize = 0;
    proto_item *pi = NULL;
    proto_tree *subtree = NULL;
    proto_item *subpi = NULL;

    if (datatype != S7COMMP_ITEM_DATATYPE_BLOB) {
        return offset;
    }

    /* note: the values in this blob are Little-Endian! */
    if ((blobsize < 0xB4) || (tvb_get_letohl(tvb, offset) != 0xFEE1DEAD) || (tvb_get_letohl(tvb, offset+4) != blobsize)) {
        return offset;
    }

    pi = proto_tree_add_item(tree, hf_s7commp_securitykeyencryptedkey, tvb, offset, blobsize, FALSE);
    PROTO_ITEM_SET_GENERATED(pi);
    subtree = proto_item_add_subtree(pi, ett_s7commp_securitykeyencryptedkey);

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_magic, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_length, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_unknown1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_unknown2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    /* next 3 are the same as the SecurityKeySymmetricKeyID earlier in the frame */
    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_symmetrickeychecksum, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 8;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_symmetrickeyflags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_symmetrickeyflags_internal, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    /* next 3 are the same as the SecurityKeyPublicKeyID earlier in the frame */
    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_publickeychecksum, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 8;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_publickeyflags, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    subpi = proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_publickeyflags_internal, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 4;

    /* this field has variable length, I have seen 0x3C and 0x50 */
    varsize = blobsize - 0x30 - 0x48;
    proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_encrypted_random_seed, tvb, offset, varsize, ENC_NA);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += varsize;

    proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_encryption_init_vector, tvb, offset, 0x10, ENC_NA);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 0x10;

    proto_tree_add_item(subtree, hf_s7commp_securitykeyencryptedkey_encrypted_challenge, tvb, offset, 0x38, ENC_NA);
    PROTO_ITEM_SET_GENERATED(subpi);
    offset += 0x38;

    return offset;
}
/*******************************************************************************************************
 *
 * Decompress a zlib compressed blob with dictionary
 *
 *******************************************************************************************************/
static guint32
s7commp_decompress_blob(tvbuff_t *tvb,
                        packet_info *pinfo,
                        proto_tree *tree,
                        guint32 offset,
                        guint8 datatype,
                        guint32 length_of_value,
                        guint32 id_number)
{
    guint32 version;
    proto_item *pi = NULL;
    proto_tree *subtree = NULL;

#ifdef HAVE_ZLIB
    int retcode;
    z_streamp streamp;
    guint32 uncomp_length;
    const char *dict = NULL;
    guint32 dict_size = 0;
    guint8 *uncomp_blob;
    const guint8 *blobptr;
    tvbuff_t *next_tvb;
    gboolean dissected;
    guint32 length_comp_blob;
#endif

    if (datatype != S7COMMP_ITEM_DATATYPE_BLOB || length_of_value < 10) {
        return offset;
    }

    pi = proto_tree_add_item(tree, hf_s7commp_compressedblob, tvb, offset, length_of_value, FALSE);
    PROTO_ITEM_SET_GENERATED(pi);
    subtree = proto_item_add_subtree(pi, ett_s7commp_compressedblob);

    length_comp_blob = length_of_value;
    /* There are blobs which don't use a dictionary. These haven't the 4-byte version header.
     * Alternative?: Check for version <= 0x90000000 ? */
    if (id_number != 4275) {  /* ConstantsGlobal.Symbolics */
        version = tvb_get_ntohl(tvb, offset);
        pi = proto_tree_add_uint(subtree, hf_s7commp_compressedblob_dictionary_version, tvb, offset, 4, version);
        PROTO_ITEM_SET_GENERATED(pi);
        offset += 4;
        length_comp_blob -= 4;
    }

    if (s7commp_opt_decompress_blobs) {
#ifdef HAVE_ZLIB
        uncomp_length = BLOB_DECOMPRESS_BUFSIZE;
        uncomp_blob = (guint8 *)wmem_alloc(pinfo->pool, BLOB_DECOMPRESS_BUFSIZE);
        blobptr = tvb_get_ptr(tvb, offset, length_comp_blob);

        streamp = wmem_new0(wmem_packet_scope(), z_stream);
        retcode = inflateInit(streamp);
        streamp->avail_in = length_comp_blob;
#ifdef z_const
        streamp->next_in = (z_const Bytef *)blobptr;
#else
DIAG_OFF(cast-qual)
        streamp->next_in = (Bytef *)blobptr;
DIAG_ON(cast-qual)
#endif
        streamp->next_out = uncomp_blob;
        streamp->avail_out = BLOB_DECOMPRESS_BUFSIZE;

        retcode = inflate(streamp, Z_FINISH);

        if (retcode == Z_NEED_DICT) {
            pi = proto_tree_add_uint(subtree, hf_s7commp_compressedblob_dictionary_id, tvb, offset + 2, 4, streamp->adler);
            PROTO_ITEM_SET_GENERATED(pi);
            switch (streamp->adler) {
                case S7COMMP_DICTID_BodyDesc_90000001:
                    dict = s7commp_dict_BodyDesc_90000001;
                    dict_size = sizeof(s7commp_dict_BodyDesc_90000001);
                    break;
                case S7COMMP_DICTID_NWC_90000001:
                    dict = s7commp_dict_NWC_90000001;
                    dict_size = sizeof(s7commp_dict_NWC_90000001);
                    break;
                case S7COMMP_DICTID_NWC_98000001:
                    dict = s7commp_dict_NWC_98000001;
                    dict_size = sizeof(s7commp_dict_NWC_98000001);
                    break;
                case S7COMMP_DICTID_NWT_90000001:
                    dict = s7commp_dict_NWT_90000001;
                    dict_size = sizeof(s7commp_dict_NWT_90000001);
                    break;
                case S7COMMP_DICTID_NWT_98000001:
                    dict = s7commp_dict_NWT_98000001;
                    dict_size = sizeof(s7commp_dict_NWT_98000001);
                    break;
                case S7COMMP_DICTID_DebugInfo_90000001:
                    dict = s7commp_dict_DebugInfo_90000001;
                    dict_size = sizeof(s7commp_dict_DebugInfo_90000001);
                    break;
                case S7COMMP_DICTID_ExtRefData_90000001:
                    dict = s7commp_dict_ExtRefData_90000001;
                    dict_size = sizeof(s7commp_dict_ExtRefData_90000001);
                    break;
                case S7COMMP_DICTID_IntRefData_90000001:
                    dict = s7commp_dict_IntRefData_90000001;
                    dict_size = sizeof(s7commp_dict_IntRefData_90000001);
                    break;
                case S7COMMP_DICTID_IntRefData_98000001:
                    dict = s7commp_dict_IntRefData_98000001;
                    dict_size = sizeof(s7commp_dict_IntRefData_98000001);
                    break;
                case S7COMMP_DICTID_IntfDescTag_90000001:
                    dict = s7commp_dict_IntfDescTag_90000001;
                    dict_size = sizeof(s7commp_dict_IntfDescTag_90000001);
                    break;
                case S7COMMP_DICTID_IntfDesc_90000001:
                    dict = s7commp_dict_IntfDesc_90000001;
                    dict_size = sizeof(s7commp_dict_IntfDesc_90000001);
                    break;
                case S7COMMP_DICTID_DebugInfo_IntfDesc_98000001:
                    dict = s7commp_dict_DebugInfo_IntfDesc_98000001;
                    dict_size = sizeof(s7commp_dict_DebugInfo_IntfDesc_98000001);
                    break;
                case S7COMMP_DICTID_TagLineComm_90000001:
                    dict = s7commp_dict_TagLineComm_90000001;
                    dict_size = sizeof(s7commp_dict_TagLineComm_90000001);
                    break;
                case S7COMMP_DICTID_LineComm_90000001:
                    dict = s7commp_dict_LineComm_90000001;
                    dict_size = sizeof(s7commp_dict_LineComm_90000001);
                    break;
                case S7COMMP_DICTID_LineComm_98000001:
                    dict = s7commp_dict_LineComm_98000001;
                    dict_size = sizeof(s7commp_dict_LineComm_98000001);
                    break;
                case S7COMMP_DICTID_IdentES_90000001:
                    dict = s7commp_dict_IdentES_90000001;
                    dict_size = sizeof(s7commp_dict_IdentES_90000001);
                    break;
                case S7COMMP_DICTID_IdentES_90000002:
                    dict = s7commp_dict_IdentES_90000002;
                    dict_size = sizeof(s7commp_dict_IdentES_90000002);
                    break;
                case S7COMMP_DICTID_IdentES_98000001:
                    dict = s7commp_dict_IdentES_98000001;
                    dict_size = sizeof(s7commp_dict_IdentES_98000001);
                    break;
                case S7COMMP_DICTID_CompilerSettings_90000001:
                    dict = s7commp_dict_CompilerSettings_90000001;
                    dict_size = sizeof(s7commp_dict_CompilerSettings_90000001);
                    break;
                default:
                    expert_add_info_format(pinfo, subtree, &ei_s7commp_blobdecompression_nodictionary, "Unknown dictionary 0x%08lx", streamp->adler);
                    break;
            }
            if (dict) {
                retcode = inflateSetDictionary(streamp, dict, dict_size);
                if (retcode == Z_OK) {
                    retcode = inflate(streamp, Z_FINISH);
                    /* retcode is Z_OK or Z_STREAM_END */
                }
            }
        }
        while ((retcode == Z_OK) || (retcode == Z_BUF_ERROR)) {
            /* Z_OK -> made progress, but did not finish
             * Z_BUF_ERROR -> output buffer full
             */
            if (streamp->avail_out == 0) {
                /* need more memory */
                uncomp_blob = (guint8 *)wmem_realloc(pinfo->pool, uncomp_blob, uncomp_length + BLOB_DECOMPRESS_BUFSIZE);
                streamp->next_out = uncomp_blob + uncomp_length;
                streamp->avail_out = BLOB_DECOMPRESS_BUFSIZE;
                uncomp_length += BLOB_DECOMPRESS_BUFSIZE;
            } else {
                /* incomplete input, abort */
                break;
            }
            retcode = inflate(streamp, Z_FINISH);
        }
        if (retcode == Z_STREAM_END) {
            uncomp_length = uncomp_length - streamp->avail_out;

            if (uncomp_length > 0) {
                if (streamp->avail_out == 0) {
                    /* need one more byte for string null terminator */
                    uncomp_blob = (guint8 *)wmem_realloc(pinfo->pool, uncomp_blob, uncomp_length + 1);
                }

                next_tvb = tvb_new_child_real_data(tvb, uncomp_blob, uncomp_length, uncomp_length);
                add_new_data_source(pinfo, next_tvb, "Decompressed Data");

                uncomp_blob[uncomp_length] = '\0';
                /* make new tvb and call xml subdissector, as all compressed data are (so far) xml */
                if (xml_handle != NULL) {
                    dissected = call_dissector_only(xml_handle, next_tvb, pinfo, subtree, NULL);
                    if (!dissected) {
                        expert_add_info(pinfo, subtree, &ei_s7commp_blobdecompression_xmlsubdissector_failed);
                    }
                }
            }
        } else {
            expert_add_info_format(pinfo, subtree, &ei_s7commp_blobdecompression_failed, "Blob decompression failed, retcode = %d", retcode);
        }
        inflateEnd(streamp);
#endif
    }
    offset += length_comp_blob;
    return offset;
}
/*******************************************************************************************************
 *
 * Decoding of a packed struct value
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_packed_struct(tvbuff_t *tvb,
                             proto_tree *tree,
                             guint32 offset)
{
    guint32 start_offset = 0;
    guint64 uint64val = 0;
    guint32 element_count = 0;
    gchar *str_val = NULL;
    guint8 octet_count = 0;
    proto_item *value_item = NULL;
    proto_tree *value_item_tree = NULL;

    start_offset = offset;
    value_item = proto_tree_add_item(tree, hf_s7commp_packedstruct, tvb, offset, -1, FALSE);
    value_item_tree = proto_item_add_subtree(value_item, ett_s7commp_packedstruct);

    str_val = (gchar *)wmem_alloc(wmem_packet_scope(), S7COMMP_ITEMVAL_STR_VAL_MAX);
    str_val[0] = '\0';

    uint64val = tvb_get_ntoh64(tvb, offset);
    s7commp_get_timestring_from_uint64(uint64val, str_val, S7COMMP_ITEMVAL_STR_VAL_MAX);
    proto_tree_add_string_format(value_item_tree, hf_s7commp_packedstruct_interfacetimestamp, tvb, offset, 8,
        str_val, "Interface timestamp: %s", str_val);
    offset += 8;

    /* Bisher war an dieser Stelle immer eine 2, was theoretisch fuer USint stehen koennte.
     * Wenn das eine Transportgroesse ist, muesste die Elementanzahl entsprechend umgerechnet werden.
     * Solange kein solches Paket gesichtet wurde, ohne Umrechnung belassen.
     */
    proto_tree_add_item(value_item_tree, hf_s7commp_packedstruct_transpsize, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_ret_varuint32(value_item_tree, hf_s7commp_packedstruct_elementcount, tvb, offset, &octet_count, &element_count);
    offset += octet_count;

    proto_tree_add_item(value_item_tree, hf_s7commp_packedstruct_data, tvb, offset, element_count, ENC_NA);
    offset += element_count;

    proto_item_set_len(value_item_tree, offset - start_offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Extended decoding of some id-values
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_value_extended(tvbuff_t *tvb,
                              packet_info *pinfo,
                              proto_tree *tree,
                              guint32 value_start_offset,           /* offset to start of the value */
                              guint8 datatype,
                              guint8 datatype_flags,
                              guint32 sparsearray_key,
                              guint32 length_of_value,  /* length of the value in bytes */
                              guint32 id_number)
{
    guint32 offset = 0;
    switch (id_number) {
        //case 1048:  /* 1048 = SubscriptionReferenceList */
        //    offset = s7commp_decode_attrib_subscriptionreflist(tvb, tree, value_start_offset, datatype, length_of_value);
        //    break;
        case 6:     /*    6 = TypeInfoModificationTime */
        case 410:   /*  410 = VariableTypeTypeInfoReserveDataModified */
        case 529:   /*  529 = VariableTypeStructModificationTime */
        case 2453:  /* 2453 = ASObjectSimple.LastModified */
        case 2529:  /* 2529 = Block.RuntimeModified */
        case 2543:  /* 2543 = DataInterface.InterfaceModified */
        case 2581:  /* 2581 = FunctionalObject.ParameterModified */
        case 3737:  /* 3737 = ControllerArea.RuntimeModified */
        case 3745:  /* 3745 = HWConfiguration.OfflineChange */
        case 3746:  /* 3746 = PLCProgram.OfflineChange */
        case 4704:  /* 4704 = TISDescription.JobModified */
        case 7646:  /* 7646 = ContinuingTisJob.JobModified */
        case 7649:  /* 7649 = MC_DB.TOAlarmReactionModified */
        case 7650:  /* 7650 = TA_DB.TechnologicalUnitsModified */
        case 7733:  /* 7733 = DB.StructureModified */
        case 7945:  /* 7945 = EventDefinition.LastUserModified_Rid */
        case 8067:  /* 8067 = SWObject.LastUserModified_Rid */
        case 8068:  /* 8068 = TextContainer.LastUserModified_Rid */
        case 8162:  /* 8162 = TA_DB.TechnologicalConnectionsModified_Rid */
            offset = s7commp_decode_attrib_ulint_timestamp(tvb, tree, value_start_offset, datatype);
            break;
        case 299:   /*  299 = ServerSessionRole */
            offset = s7commp_decode_attrib_serversessionrole(tvb, tree, value_start_offset, datatype);
            break;
        case 1247:  /* 1247 = FilterOperation */
            offset = s7commp_decode_attrib_filteroperation(tvb, tree, value_start_offset, datatype);
            break;
        case 2523:  /* 2523 = Block.BlockLanguage */
            offset = s7commp_decode_attrib_blocklanguage(tvb, tree, value_start_offset, datatype);
            break;
        case 1805:  /* 1805 = SecurityKeyEncryptedKey */
            offset = s7commp_decode_attrib_securitykeyencryptedkey(tvb, tree, value_start_offset, datatype, length_of_value);
            break;
        case 2449:  /* ASObjectES.IdentES */
        case 2533:  /* Block.BodyDescription */
        case 2544:  /* DataInterface.InterfaceDescription */
        case 2545:  /* DataInterface.CompilerSwitches */
        case 2546:  /* DataInterface.LineComments */
        case 2583:  /* FunctionalObject.intRefData */
        case 2584:  /* FunctionalObject.NetworkComments */
        case 2585:  /* FunctionalObject.NetworkTitles */
        case 2589:  /* FunctionalObject.DebugInfo */
        case 4275:  /* ConstantsGlobal.Symbolics */
            /* Spezial-Ausnahme: Sparsearray Elemente mit einem Sparsearray-Key >= 0x80000000 sind nicht,
             * oder wenn dann anders komprimiert.
             */
            if ((datatype_flags & S7COMMP_DATATYPE_FLAG_SPARSEARRAY) && (sparsearray_key & 0x80000000)) {
                break;
            } else {
                offset = s7commp_decompress_blob(tvb, pinfo, tree, value_start_offset, datatype, length_of_value, id_number);
            }
            break;
        case 7813:  /* DAI.HmiInfo */
            offset = s7commp_decode_attrib_hmiinfo(tvb, tree, value_start_offset, datatype, length_of_value);
            break;
        case 7859:  /* MultipleSTAI.STAIs */
            offset = s7commp_decode_attrib_multiplestais(tvb, tree, value_start_offset, datatype, length_of_value);
            break;
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Decoding of a single value with datatype flags, datatype specifier and the value data
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_value(tvbuff_t *tvb,
                     packet_info *pinfo,
                     proto_tree *data_item_tree,
                     guint32 offset,
                     int* struct_level,
                     guint32 id_number)
{
    guint8 octet_count = 0;
    guint8 datatype;
    guint8 datatype_of_value;
    guint8 datatype_flags;
    gboolean is_array = FALSE;
    gboolean is_address_array = FALSE;
    gboolean is_sparsearray = FALSE;
    gboolean unknown_type_occured = FALSE;
    gboolean is_struct_addressarray = FALSE;
    guint32 array_size = 1;     /* use 1 as default, so non-arrays can be dissected in the same way as arrays */
    guint32 array_index = 0;

    proto_item *array_item = NULL;
    proto_tree *array_item_tree = NULL;
    proto_tree *current_tree = NULL;

    guint64 uint64val = 0;
    guint32 uint32val = 0;
    guint16 uint16val = 0;
    gint16 int16val = 0;
    gint32 int32val = 0;
    guint8 uint8val = 0;
    gint64 int64val = 0;
    gint8 int8val = 0;
    gchar *str_val = NULL;          /* Value of one single item */
    gchar *str_arrval = NULL;       /* Value of array values */
    guint32 sparsearray_key = 0;
    const gchar *str_arr_prefix = "Unknown";
    gchar *struct_resultstring;

    guint32 start_offset = 0;
    guint32 length_of_value = 0;
    guint32 value_start_offset = 0;

    guint32 struct_value = 0;

    str_val = (gchar *)wmem_alloc(wmem_packet_scope(), S7COMMP_ITEMVAL_STR_VAL_MAX);
    str_val[0] = '\0';
    str_arrval = (gchar *)wmem_alloc(wmem_packet_scope(), S7COMMP_ITEMVAL_STR_ARRVAL_MAX);
    str_arrval[0] = '\0';

    datatype_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(data_item_tree, tvb, offset, hf_s7commp_itemval_datatype_flags,
        ett_s7commp_itemval_datatype_flags, s7commp_itemval_datatype_flags_fields, ENC_BIG_ENDIAN);
    offset += 1;

    datatype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_datatype, tvb, offset, 1, datatype);
    offset += 1;

    is_array = (datatype_flags & S7COMMP_DATATYPE_FLAG_ARRAY) && (datatype != S7COMMP_ITEM_DATATYPE_STRUCT);
    is_address_array = (datatype_flags & S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY) && (datatype != S7COMMP_ITEM_DATATYPE_STRUCT);
    is_sparsearray = (datatype_flags & S7COMMP_DATATYPE_FLAG_SPARSEARRAY);
    is_struct_addressarray = (datatype_flags & S7COMMP_DATATYPE_FLAG_ADDRESS_ARRAY) && (datatype == S7COMMP_ITEM_DATATYPE_STRUCT);
    /* Besonderheit bei Adressarray und Datentyp Struct:
     * Hier folgt nach dem Struct-Wert (ueblicherweise eine AID) die Anzahl der folgenden
     * Array-Elemente. Die Elemente bestehen aber wieder aus einer ID mit Wert, darum
     * kann es in diesem Fall nicht wie die anderen Arrays innerhalb dieser Funktion zerlegt werden,
     * sondern es wird pro Array Element die Zerlegefunktion fuer eine ID/Value Liste aufgerufen.
     */

    datatype_of_value = datatype;
    if (is_array || is_address_array || is_sparsearray) {
        if (is_sparsearray) {
            /* Bei diesem Array-Typ gibt es keine Angabe ueber die Anzahl. Das Array ist Null-terminiert.
             * Damit die for-Schleife aber auch hierfuer verwendet werden kann, wird die Anzahl auf 999999 gesetzt,
             * und die Schleife bei erreichen der terminierenden Null explizit verlassen.
             */
            array_size = 999999;
        } else {
            proto_tree_add_ret_varuint32(data_item_tree, hf_s7commp_itemval_arraysize, tvb, offset, &octet_count, &array_size);
            offset += octet_count;
        }
        /* To display an array value, build a separate tree for the complete array.
         * Under the array tree the array values are displayed.
         */
        array_item = proto_tree_add_item(data_item_tree, hf_s7commp_itemval_value, tvb, offset, -1, FALSE);
        array_item_tree = proto_item_add_subtree(array_item, ett_s7commp_itemval_array);
        start_offset = offset;
        if (is_array) {
            str_arr_prefix = "Array";
        } else if (is_address_array) {
            str_arr_prefix = "Addressarray";
        } else if (is_sparsearray) {
            str_arr_prefix = "Sparsearray";
        }
        current_tree = array_item_tree;
    } else {
        current_tree = data_item_tree;
    }

    /* Use array loop also for non-arrays */
    for (array_index = 1; array_index <= array_size; array_index++) {
        if (is_sparsearray) {
            sparsearray_key = tvb_get_varuint32(tvb, &octet_count, offset);
            if (sparsearray_key == 0) {
                proto_tree_add_item(current_tree, hf_s7commp_itemval_sparsearray_term, tvb, offset, octet_count, FALSE);
                offset += octet_count;
                g_strlcpy(str_val, "<Empty>", S7COMMP_ITEMVAL_STR_VAL_MAX);
                break;
            } else {
                if (datatype == S7COMMP_ITEM_DATATYPE_VARIANT) {
                    proto_tree_add_uint(current_tree, hf_s7commp_itemval_varianttypeid, tvb, offset, octet_count, sparsearray_key);
                } else {
                    proto_tree_add_uint(current_tree, hf_s7commp_itemval_sparsearray_key, tvb, offset, octet_count, sparsearray_key);
                }
                offset += octet_count;
            }
        } else {
            /* Sonderbehandung Adressarray (ausschliesslich?) mit datatype VARIANT
             * TODO: Dieses ist nur eine vorlaeufige Auswertung, da zur Bestimmung des Aufbaus
             *       noch zu wenige Aufzeichnungen vorliegen. Wenn der Aufbau feststeht, sollte diese
             *       gesamte Funktion ueberarbeitet werden (Datentyp-Auswertung und Array-Verarbeitung trennen).
             * Erste Vermutung: 1. Byte datatype flags (unbestaetigt)
             *                  2. Byte Type-ID, dann weiter mit Wert anhand der Typ-ID.
             * Bei einem Sparsearray scheint der Aufbau anders zu sein.
             */
            if (datatype == S7COMMP_ITEM_DATATYPE_VARIANT) {
                proto_tree_add_bitmask(current_tree, tvb, offset, hf_s7commp_itemval_datatype_flags,
                    ett_s7commp_itemval_datatype_flags, s7commp_itemval_datatype_flags_fields, ENC_BIG_ENDIAN);
                offset += 1;
                datatype_of_value = tvb_get_guint8(tvb, offset);    /* Datentyp fuer switch-Auswertung aendern */
                proto_tree_add_uint(current_tree, hf_s7commp_itemval_varianttypeid, tvb, offset, 1, datatype_of_value);
                offset += 1;
            }
        }

        switch (datatype_of_value) {
            case S7COMMP_ITEM_DATATYPE_NULL:
                g_strlcpy(str_val, "<Null>", S7COMMP_ITEMVAL_STR_VAL_MAX);
                length_of_value = 0;
                break;
            case S7COMMP_ITEM_DATATYPE_BOOL:
                length_of_value = 1;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%s", tvb_get_guint8(tvb, offset) ? "True" : "False");
                offset += 1;
                break;
            case S7COMMP_ITEM_DATATYPE_USINT:
                length_of_value = 1;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%u", tvb_get_guint8(tvb, offset));
                offset += 1;
                break;
            case S7COMMP_ITEM_DATATYPE_UINT:
                length_of_value = 2;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%u", tvb_get_ntohs(tvb, offset));
                offset += 2;
                break;
            case S7COMMP_ITEM_DATATYPE_UDINT:
                value_start_offset = offset;
                uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%u", uint32val);
                break;
            case S7COMMP_ITEM_DATATYPE_ULINT:
                value_start_offset = offset;
                uint64val = tvb_get_varuint64(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%" G_GINT64_MODIFIER "u", uint64val);
                break;
            case S7COMMP_ITEM_DATATYPE_LINT:
                value_start_offset = offset;
                int64val = tvb_get_varint64(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%" G_GINT64_MODIFIER "d", int64val);
                break;
            case S7COMMP_ITEM_DATATYPE_SINT:
                value_start_offset = offset;
                uint8val = tvb_get_guint8(tvb, offset);
                memcpy(&int8val, &uint8val, sizeof(int8val));
                length_of_value = 1;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%d", int8val);
                offset += 1;
                break;
            case S7COMMP_ITEM_DATATYPE_INT:
                value_start_offset = offset;
                uint16val = tvb_get_ntohs(tvb, offset);
                memcpy(&int16val, &uint16val, sizeof(int16val));
                length_of_value = 2;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%d", int16val);
                offset += 2;
                break;
            case S7COMMP_ITEM_DATATYPE_DINT:
                value_start_offset = offset;
                int32val = tvb_get_varint32(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%d", int32val);
                break;
            case S7COMMP_ITEM_DATATYPE_BYTE:
                length_of_value = 1;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "0x%02x", tvb_get_guint8(tvb, offset));
                offset += 1;
                break;
            case S7COMMP_ITEM_DATATYPE_WORD:
                length_of_value = 2;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "0x%04x", tvb_get_ntohs(tvb, offset));
                offset += 2;
                break;
            case S7COMMP_ITEM_DATATYPE_STRUCT:
                if (struct_level) *struct_level += 1; /* entering a new structure level */
                length_of_value = 4;
                value_start_offset = offset;
                struct_value = tvb_get_ntohl(tvb, offset);
                struct_resultstring = (gchar *)wmem_alloc(wmem_packet_scope(), ITEM_LABEL_LENGTH);
                s7commp_idname_fmt(struct_resultstring, struct_value);
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%u (%s)", struct_value, struct_resultstring);
                offset += 4;
                break;
            case S7COMMP_ITEM_DATATYPE_DWORD:
                length_of_value = 4;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "0x%08x", tvb_get_ntohl(tvb, offset));
                offset += 4;
                break;
            case S7COMMP_ITEM_DATATYPE_LWORD:
                length_of_value = 8;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "0x%016" G_GINT64_MODIFIER "x", tvb_get_ntoh64(tvb, offset));
                offset += 8;
                break;
            case S7COMMP_ITEM_DATATYPE_REAL:
                length_of_value = 4;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%f", tvb_get_ntohieee_float(tvb, offset));
                offset += 4;
                break;
            case S7COMMP_ITEM_DATATYPE_LREAL:
                length_of_value = 8;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%f", tvb_get_ntohieee_double(tvb, offset));
                offset += 8;
                break;
            case S7COMMP_ITEM_DATATYPE_TIMESTAMP:
                length_of_value = 8;
                value_start_offset = offset;
                uint64val = tvb_get_ntoh64(tvb, offset);
                s7commp_get_timestring_from_uint64(uint64val, str_val, S7COMMP_ITEMVAL_STR_VAL_MAX);
                offset += 8;
                break;
            case S7COMMP_ITEM_DATATYPE_TIMESPAN:
                value_start_offset = offset;
                int64val = tvb_get_varint64(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                s7commp_get_timespan_from_int64(int64val, str_val, S7COMMP_ITEMVAL_STR_VAL_MAX);
                break;
            case S7COMMP_ITEM_DATATYPE_RID:
                length_of_value = 4;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "0x%08x", tvb_get_ntohl(tvb, offset));
                offset += 4;
                break;
            case S7COMMP_ITEM_DATATYPE_AID:
                value_start_offset = offset;
                uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%u", uint32val);
                break;
            case S7COMMP_ITEM_DATATYPE_WSTRING:
                proto_tree_add_ret_varuint32(current_tree, hf_s7commp_itemval_stringactlen, tvb, offset, &octet_count, &length_of_value);
                offset += octet_count;
                value_start_offset = offset;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%s",
                       tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length_of_value, ENC_UTF_8|ENC_NA));
                offset += length_of_value;
                break;
            case S7COMMP_ITEM_DATATYPE_VARIANT:
                value_start_offset = offset;
                uint32val = tvb_get_varuint32(tvb, &octet_count, offset);
                offset += octet_count;
                length_of_value = octet_count;
                g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "%u", uint32val);
                break;
            case S7COMMP_ITEM_DATATYPE_BLOB:
                proto_tree_add_ret_varuint32(current_tree, hf_s7commp_itemval_blobrootid, tvb, offset, &octet_count, &uint32val);
                offset += octet_count;
                /* Wenn Wert > 0 dann Spezialformat, welches im Prinzip bis auf die 9 eingeschobenen Bytes
                 * identisch zum Aufbau einer Struct ist. Verwendung z.B. mit ID 1848.
                 */
                if (uint32val > 0) {
                    g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "<Blob special for ID: %u>", uint32val);
                    proto_tree_add_text(current_tree, tvb, offset, 9, "Blob special unknown 9 bytes (always zero?)");
                    offset += 9;
                    value_start_offset = offset;
                    /* Sub-Elemente rekursiv abarbeiten. Bisher sind hier immer nur zwei Standard-Blobs enthalten. */
                    offset = s7commp_decode_id_value_list(tvb, pinfo, current_tree, offset, TRUE);
                    length_of_value = 0;
                } else {
                    proto_tree_add_ret_varuint32(current_tree, hf_s7commp_itemval_blobsize, tvb, offset, &octet_count, &length_of_value);
                    offset += octet_count;
                    value_start_offset = offset;
                    if (length_of_value > 0) {
                        g_snprintf(str_val, S7COMMP_ITEMVAL_STR_VAL_MAX, "0x%s", tvb_bytes_to_str(wmem_packet_scope(), tvb, offset, length_of_value));
                    } else {
                        g_strlcpy(str_val, "<Empty>", S7COMMP_ITEMVAL_STR_VAL_MAX);
                    }
                    offset += length_of_value;
                }
                break;
            default:
                unknown_type_occured = TRUE;
                expert_add_info(pinfo, current_tree, &ei_s7commp_value_unknown_type);
                g_strlcpy(str_val, "Unknown Type occured. Could not interpret value!", S7COMMP_ITEMVAL_STR_VAL_MAX);
                break;
        } /* switch */

        if (unknown_type_occured) {
            break;
        }

        if (is_array || is_address_array || is_sparsearray) {
            /* Leere Werte mit <Empty> kennzeichnen */
            if (strlen(str_val) == 0) {
                g_strlcpy(str_val, "<Empty>", S7COMMP_ITEMVAL_STR_VAL_MAX);
            }
            /* Build a string of all array values. Maximum number of 10 values */
            if (array_index < S7COMMP_ITEMVAL_ARR_MAX_DISPLAY) {
                if (array_index > 1 && array_size > 1) {
                    g_strlcat(str_arrval, ", ", S7COMMP_ITEMVAL_STR_ARRVAL_MAX);
                }
                g_strlcat(str_arrval, str_val, S7COMMP_ITEMVAL_STR_ARRVAL_MAX);
            } else if (array_index == S7COMMP_ITEMVAL_ARR_MAX_DISPLAY) {
                /* truncate */
                g_strlcat(str_arrval, "...", S7COMMP_ITEMVAL_STR_ARRVAL_MAX);
            }
            if (is_sparsearray) {
                proto_tree_add_text(array_item_tree, tvb, offset - length_of_value, length_of_value, "Value: %s", str_val);
                if (sparsearray_key == 0) {
                    break;
                }
            } else {
                proto_tree_add_text(array_item_tree, tvb, offset - length_of_value, length_of_value, "Value[%u]: %s", array_index, str_val);
            }
        }
        /* Erweitertes Decodieren der Daten ausgewaehlter IDs */
        s7commp_decode_value_extended(tvb, pinfo, current_tree, value_start_offset, datatype, datatype_flags, sparsearray_key, length_of_value, id_number);
    } /* for */

    if (strlen(str_arrval) == 0) {
        g_strlcpy(str_arrval, "<Empty>", S7COMMP_ITEMVAL_STR_ARRVAL_MAX);
    }
    if (is_array || is_address_array) {
        proto_item_append_text(array_item_tree, " %s[%u] = %s", str_arr_prefix, array_size, str_arrval);
        proto_item_set_len(array_item_tree, offset - start_offset);
        proto_item_append_text(data_item_tree, " (%s) %s[%u] = %s", val_to_str(datatype, item_datatype_names, "Unknown datatype: 0x%02x"), str_arr_prefix, array_size, str_arrval);
    } else if (is_sparsearray) {
        proto_item_append_text(array_item_tree, " %s = %s", str_arr_prefix, str_arrval);
        proto_item_set_len(array_item_tree, offset - start_offset);
        proto_item_append_text(data_item_tree, " (%s) %s = %s", val_to_str(datatype, item_datatype_names, "Unknown datatype: 0x%02x"), str_arr_prefix, str_arrval);
    } else if (is_struct_addressarray) {
        proto_tree_add_text(data_item_tree, tvb, offset - length_of_value, length_of_value, "Value: %s", str_val);
        proto_tree_add_ret_varuint32(data_item_tree, hf_s7commp_itemval_arraysize, tvb, offset, &octet_count, &array_size);
        offset += octet_count;
        proto_item_append_text(data_item_tree, " (Addressarray %s) = %s", val_to_str(datatype, item_datatype_names, "Unknown datatype: 0x%02x"), str_val);
        /* Das Handling der Array-Elemente erfolgt hier */
        for (array_index = 1; array_index <= array_size; array_index++) {
            start_offset = offset;
            array_item = proto_tree_add_item(data_item_tree, hf_s7commp_itemval_value, tvb, offset, -1, FALSE);
            array_item_tree = proto_item_add_subtree(array_item, ett_s7commp_itemval_array);
            proto_item_append_text(array_item_tree, " [%u]", array_index);

            offset = s7commp_decode_id_value_list(tvb, pinfo, array_item_tree, offset, TRUE);

            proto_item_set_len(array_item_tree, offset - start_offset);
        }
        if (struct_level) {
            *struct_level = -1;       /* Zur Signalisierung benutzen, dass anschliessend keine Item-ID sondern eine Element-ID folgen muss. */
        }
    } else { /* not an array or address array */
        if (length_of_value > 0) {
            proto_tree_add_text(data_item_tree, tvb, offset - length_of_value, length_of_value, "Value: %s", str_val);
        }
        proto_item_append_text(data_item_tree, " (%s) = %s", val_to_str(datatype, item_datatype_names, "Unknown datatype: 0x%02x"), str_val);
    }
    /* Sonderbehandlung bei Datentyp struct bestimmten IDs:
     * Es werden die struct-Elemente nicht einzeln sondern gepackt uebertragen (z.B. DTL-Struct).
     * Der ID-Bereich in dem dieses moeglich ist, ist nur vermutet (Type Info).
     * Die Auswertung an dieser Stelle funktioniert nur, solange hier nicht auch Arrays erlaubt sind.
     */
    if (datatype == S7COMMP_ITEM_DATATYPE_STRUCT &&
        ((struct_value > 0x90000000 && struct_value < 0x9fffffff) ||
         (struct_value > 0x02000000 && struct_value < 0x02ffffff)) ) {
        offset = s7commp_decode_packed_struct(tvb, current_tree, offset);
        if (struct_level) *struct_level -= 1; /* in diesem Fall keine neue Strukturebene, da auch keine terminierende Null */
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a list of item-id and a value recursive sub-structs.
 * Builds a tree which represents the data structure.
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_id_value_list(tvbuff_t *tvb,
                             packet_info *pinfo,
                             proto_tree *tree,
                             guint32 offset,
                             gboolean recursive)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint32 id_number;
    guint32 start_offset;
    guint8 octet_count = 0;
    int struct_level;

    do {
        id_number = tvb_get_varuint32(tvb, &octet_count, offset);
        if (id_number == 0) {
            proto_tree_add_item(tree, hf_s7commp_listitem_terminator, tvb, offset, octet_count, FALSE);
            offset += octet_count;
            return offset;
        } else {
            start_offset = offset;
            data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
            proto_tree_add_uint(data_item_tree, hf_s7commp_data_id_number, tvb, offset, octet_count, id_number);
            s7commp_proto_item_append_idname(data_item_tree, id_number, ": ID=");
            offset += octet_count;
            struct_level = 0;
            offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, id_number);
            /* Extended decoding */
            switch (id_number) {
                case 1048:  /* 1048 = SubscriptionReferenceList. An dieser Position weil Array of int */
                    s7commp_decode_attrib_subscriptionreflist(tvb, tree, start_offset + octet_count);
                    break;
            }

            if (struct_level > 0) { /* A new struct was entered, use recursive struct traversal */
                offset = s7commp_decode_id_value_list(tvb, pinfo, data_item_tree, offset, TRUE);
            }
            proto_item_set_len(data_item_tree, offset - start_offset);
            if (struct_level < 0) {
                return offset;
            }
        }
    } while (recursive);
    return offset;
}
/*******************************************************************************************************
 *
 * Calls s7commp_decode_id_value_list an inserts data into a ValueList subtree
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_id_value_list_in_new_tree(tvbuff_t *tvb,
                                         packet_info *pinfo,
                                         proto_tree *tree,
                                         guint32 offset,
                                         gboolean recursive)
{
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint32 list_start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_s7commp_valuelist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
    offset = s7commp_decode_id_value_list(tvb, pinfo, list_item_tree, offset, recursive);
    proto_item_set_len(list_item_tree, offset - list_start_offset);
    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a list of item-number and value. Subvalues (struct members) are decoded as IDs.
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_itemnumber_value_list(tvbuff_t *tvb,
                                     packet_info *pinfo,
                                     proto_tree *tree,
                                     guint32 offset,
                                     gboolean recursive)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint32 itemnumber;
    guint32 start_offset;
    guint8 octet_count = 0;
    int struct_level;

    do {
        itemnumber = tvb_get_varuint32(tvb, &octet_count, offset);
        if (itemnumber == 0) {
            proto_tree_add_item(tree, hf_s7commp_listitem_terminator, tvb, offset, octet_count, FALSE);
            offset += octet_count;
            break;
        } else {
            start_offset = offset;
            data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
            proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_itemnumber, tvb, offset, octet_count, itemnumber);
            proto_item_append_text(data_item_tree, " [%u]:", itemnumber);
            offset += octet_count;
            struct_level = 0;
            offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, 0);
            if (struct_level > 0) {
                offset = s7commp_decode_id_value_list(tvb, pinfo, data_item_tree, offset, TRUE);
            }
            proto_item_set_len(data_item_tree, offset - start_offset);
        }
    } while (recursive);
    return offset;
}
/*******************************************************************************************************
 *
 * Calls s7commp_decode_itemnumber_value_list and inserts data into a ValueList subtree
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_itemnumber_value_list_in_new_tree(tvbuff_t *tvb,
                                                 packet_info *pinfo,
                                                 proto_tree *tree,
                                                 guint32 offset,
                                                 gboolean recursive)
{
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint32 list_start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_s7commp_valuelist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
    offset = s7commp_decode_itemnumber_value_list(tvb, pinfo, list_item_tree, offset, recursive);
    proto_item_set_len(list_item_tree, offset - list_start_offset);
    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a list of error values, until terminating null and lowest struct level
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_itemnumber_errorvalue_list(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset)
{
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;

    guint32 item_number;
    guint8 octet_count = 0;
    gint16 errorcode = 0;
    gboolean errorextension = FALSE;

    guint32 start_offset = offset;
    guint32 list_start_offset = offset;

    list_item = proto_tree_add_item(tree, hf_s7commp_errorvaluelist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_errorvaluelist);

    do {
        item_number = tvb_get_varuint32(tvb, &octet_count, offset);
        if (item_number == 0) {
            proto_tree_add_item(list_item_tree, hf_s7commp_errorvaluelist_terminator, tvb, offset, octet_count, FALSE);
            offset += octet_count;
        } else {
            start_offset = offset;
            data_item = proto_tree_add_item(list_item_tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
            proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_itemnumber, tvb, offset, octet_count, item_number);
            offset += octet_count;
            offset = s7commp_decode_returnvalue(tvb, NULL, data_item_tree, offset, &errorcode, &errorextension);
            proto_item_append_text(data_item_tree, " [%u]: Error code: %s (%d)", item_number, val64_to_str_const(errorcode, errorcode_names, "Unknown"), errorcode);
            proto_item_set_len(data_item_tree, offset - start_offset);
        }
    } while (item_number != 0);
    proto_item_set_len(list_item_tree, offset - list_start_offset);
    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a tag description (old S7-1200 FW2)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_tagdescription(tvbuff_t *tvb,
                              proto_tree *tree,
                              guint32 offset)
{
    guint32 length_of_value;
    guint32 vlq_value;
    gint32 svlq_value;
    guint8 octet_count = 0;
    guint8 datatype;
    guint8 offsetinfotype;
    proto_item *offsetinfo_item = NULL;
    proto_tree *offsetinfo_tree = NULL;
    guint32 start_offset;
    gint32 number_of_array_dimensions;
    gint32 array_dimension;
    const guint8 *str_name;
    const guint8 *str_type;
    gint32 mdarray_lowerbounds[6];
    gint32 mdarray_elementcount[6];

    offsetinfotype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_tagdescr_offsetinfotype, tvb, offset, 1, offsetinfotype);
    offset += 1;

    proto_tree_add_ret_varuint32(tree, hf_s7commp_tagdescr_namelength, tvb, offset, &octet_count, &length_of_value);
    offset += octet_count;

    proto_tree_add_item_ret_string(tree, hf_s7commp_tagdescr_name, tvb, offset, length_of_value, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &str_name);
    proto_item_append_text(tree, ": Name=%s", str_name);
    offset += length_of_value;

    proto_tree_add_item(tree, hf_s7commp_tagdescr_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    datatype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_tagdescr_datatype, tvb, offset, 1, datatype);
    offset += 1;

    proto_tree_add_ret_varuint32(tree, hf_s7commp_tagdescr_softdatatype, tvb, offset, &octet_count, &vlq_value);
    if ((str_type = try_val_to_str_ext(vlq_value, &tagdescr_softdatatype_names_ext))) {
        proto_item_append_text(tree, " Type=%s", str_type);
    } else {
        proto_item_append_text(tree, " Type=Unknown softdatatype 0x%04x", vlq_value);
    }
    offset += octet_count;

    proto_tree_add_bitmask(tree, tvb, offset, hf_s7commp_tagdescr_attributeflags,
        ett_s7commp_tagdescr_attributeflags, s7commp_tagdescr_attributeflags_fields, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_varuint32(tree, hf_s7commp_tagdescr_lid, tvb, offset, &octet_count);
    offset += octet_count;

    /* Dieser Wert hat je nach Datentyp eine unterschiedliche Funktion.
     * Ist das Element eine Struktur, so kann mit einer folgenden Abfrage eines Sub-Elements im Datenbaustein anhand der ID
     * die Beziehung zu dem uebergeordneten Element hergestellt werden.
     */
    length_of_value = tvb_get_varuint32(tvb, &octet_count, offset);
    if (datatype == S7COMMP_ITEM_DATATYPE_S7STRING) {
        proto_tree_add_uint(tree, hf_s7commp_tagdescr_s7stringlength, tvb, offset, octet_count, length_of_value);
    } else if (datatype == S7COMMP_ITEM_DATATYPE_STRUCT) {
        proto_tree_add_uint(tree, hf_s7commp_tagdescr_structrelid, tvb, offset, octet_count, length_of_value);
    } else {
        proto_tree_add_uint(tree, hf_s7commp_tagdescr_lenunknown, tvb, offset, octet_count, length_of_value);
    }
    offset += octet_count;

    offsetinfo_item = proto_tree_add_item(tree, hf_s7commp_tagdescr_offsetinfo, tvb, offset, -1, FALSE);
    offsetinfo_tree = proto_item_add_subtree(offsetinfo_item, ett_s7commp_tagdescr_offsetinfo);
    start_offset = offset;

    if (offsetinfotype & 0x04 || offsetinfotype & 0x08) {
        proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_accessability, tvb, offset, &octet_count);
        offset += octet_count;
        proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_section, tvb, offset, &octet_count);
        offset += octet_count;
    }
    proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_offsettype1, tvb, offset, &octet_count);
    offset += octet_count;
    proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_offsettype2, tvb, offset, &octet_count);
    offset += octet_count;

    switch (offsetinfotype & 0x03) {
        case 0x00:
            /* nothing extra here */
            break;
        case 0x01:
            proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_bitoffsettype1, tvb, offset, &octet_count);
            offset += octet_count;
            proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_bitoffsettype2, tvb, offset, &octet_count);
            offset += octet_count;
            break;
        case 0x02:
            proto_tree_add_ret_varint32(offsetinfo_tree, hf_s7commp_tagdescr_arraylowerbounds, tvb, offset, &octet_count, &svlq_value);
            offset += octet_count;
            proto_tree_add_ret_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_arrayelementcount, tvb, offset, &octet_count, &vlq_value);
            offset += octet_count;
            proto_item_append_text(tree, "-Array[%d..%d]", svlq_value, svlq_value + (gint32)(vlq_value - 1));
            proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_paddingtype1, tvb, offset, &octet_count);
            offset += octet_count;
            proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_paddingtype2, tvb, offset, &octet_count);
            offset += octet_count;
            break;
        case 0x03:
            proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_paddingtype1, tvb, offset, &octet_count);
            offset += octet_count;
            proto_tree_add_varuint32(offsetinfo_tree, hf_s7commp_tagdescr_paddingtype2, tvb, offset, &octet_count);
            offset += octet_count;
            number_of_array_dimensions = (gint32)tvb_get_varuint32(tvb, &octet_count, offset);
            proto_tree_add_uint(offsetinfo_tree, hf_s7commp_tagdescr_numarraydimensions, tvb, offset, octet_count, number_of_array_dimensions);
            offset += octet_count;
            /* Multidimensional Array max. 6 dimensions */
            for (array_dimension = 0; array_dimension < number_of_array_dimensions; array_dimension++) {
                svlq_value = tvb_get_varint32(tvb, &octet_count, offset);
                proto_tree_add_int_format(offsetinfo_tree, hf_s7commp_tagdescr_arraylowerbounds, tvb, offset, octet_count, svlq_value,
                    "Array lower bounds [Dimension %u]: %d", array_dimension+1, svlq_value);
                offset += octet_count;
                vlq_value = tvb_get_varuint32(tvb, &octet_count, offset);
                proto_tree_add_uint_format(offsetinfo_tree, hf_s7commp_tagdescr_arrayelementcount, tvb, offset, octet_count, svlq_value,
                    "Array element count [Dimension %u]: %u", array_dimension+1, vlq_value);
                offset += octet_count;
                if (array_dimension < 6) {
                    mdarray_lowerbounds[array_dimension] = svlq_value;
                    mdarray_elementcount[array_dimension] = (gint32)vlq_value;
                }
            }
            /* Displaystyle [a..b, c..d, e..f], using order which is used in variable declaration */
            if (number_of_array_dimensions > 6) {
                number_of_array_dimensions = 6; /* limit to max 6 dims  */
            }
            proto_item_append_text(tree, "-Array[");
            for (array_dimension = (number_of_array_dimensions - 1); array_dimension >= 0; array_dimension--) {
                proto_item_append_text(tree, "%d..%d%s", mdarray_lowerbounds[array_dimension],
                    mdarray_lowerbounds[array_dimension] + (mdarray_elementcount[array_dimension] - 1),
                    (array_dimension > 0) ? ", " : "]");
            }
            break;
    }
    /* Passt nicht ins Schema oben, unbekannt wozu die weiteren zwei Werte dienen */
    if (offsetinfotype == 0x08) {
        vlq_value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(offsetinfo_tree, tvb, offset, octet_count, "Unknown SFB Instance Offset 1: %u", vlq_value);
        offset += octet_count;
        vlq_value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(offsetinfo_tree, tvb, offset, octet_count, "Unknown SFB Instance Offset 2: %u", vlq_value);
        offset += octet_count;
    }
    proto_item_set_len(offsetinfo_tree, offset - start_offset);
    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a variable type list (0xab)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_vartypelist(tvbuff_t *tvb,
                           proto_tree *tree,
                           guint32 offset)
{
    guint32 tag_start_offset;
    guint32 max_offset;
    guint32 softdatatype;
    proto_item *item;
    proto_tree *tag_tree;
    int i = 1;
    const guint8 *str_type;
    guint16 block_len;
    guint16 attributeflags2;
    gint32 array_lowerbounds, array_elementcount;
    gint32 mdarray_lowerbounds[6];
    gint32 mdarray_elementcount[6];
    int mdarray_actdimensions;
    int d;
    guint8 offsetinfotype;

    /* Hier koennen mehrere Datenbloecke vorhanden sein (gleiches bei varnamelist).
     * Ist die Laenge == 0, dann folgt kein weiterer Datenblock mehr.
     * Nur der erste Datenblock besitzt zusaetzlich noch eine 4-Byte ID (oder Flags?).
     *
     * Die Bytereihenfolge ist in diesem Block Little-Endian!!
     * Auf so eine Idee muss man erstmal kommen, ob da noch die S7 classic Abteilung am Werk war...
     */
    block_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_object_blocklength, tvb, offset, 2, block_len);
    offset += 2;
    max_offset = offset + block_len;

    proto_tree_add_text(tree, tvb, offset, 4, "Unknown in first Block (LittleEndian): 0x%08x / %u", tvb_get_letohl(tvb, offset), tvb_get_letohl(tvb, offset));
    offset += 4;

    while (block_len > 0) {
        do {
            tag_start_offset = offset;
            item = proto_tree_add_item(tree, hf_s7commp_element_tagdescription, tvb, offset, -1, FALSE);
            tag_tree = proto_item_add_subtree(item, ett_s7commp_element_tagdescription);

            proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_lid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            /* Die CRC hier wird rein aus dem Symbol hier, plus softdatatype-id (1=Bool, 5=Int, ...) uebermittelt.
             * Fuer den Zugriff auf eine Variable in einem DB reicht diese alleine nicht aus,
             * sondern es muss die Pruefsumme ueber den gesamten Symbolpfad gebildet werden:
             * DBname.structname.variablenname
             * Als Trennzeichen "." ist hierbei 0x09 einzusetzen und dann ein zweites Mal darueber die
             * Pruefsumme zu bilden.
             */
            proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_subsymbolcrc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            softdatatype = tvb_get_guint8(tvb, offset); /* hier nur 1 Byte */
            proto_tree_add_uint(tag_tree, hf_s7commp_tagdescr_softdatatype, tvb, offset, 1, softdatatype);
            offset += 1;

            if ((str_type = try_val_to_str_ext(softdatatype, &tagdescr_softdatatype_names_ext))) {
                proto_item_append_text(tag_tree, "[%d]: Type=%s", i, str_type);
            } else {
                proto_item_append_text(tag_tree, "[%d]: Unknown softdatatype 0x%04x", i, softdatatype);
            }

            /* Werte dieser 2 Bytes:
             * Bei M/I/C/T:                           0x8a40 = 1000 1010 0100 0000
             * Bei M/I/C/T wenn "nicht sichtbar":     0x8240 = 1000 0010 0100 0000
             * Bei M/I/C/T wenn "nicht erreichbar":   0x8040 = 1000 0000 0100 0000
             * Bei Variablen in einem optimierten DB: 0x8ac0 = 1000 1010 1100 0000
             * Bei Struct in einem optimierten DB:    0xcac0 = 1100 1010 1100 0000
             * Bei Variablen in einem NICHT opt. DB:  0x8a40 = 1000 1010 0100 0000
             * Bei String/WStr in einem NICHT opt. DB:0x9a40 = 1001 1010 0100 0000
             * Structmember                           0x1a80 = 0001 1010 1000 0000
             */
            attributeflags2 = tvb_get_ntohs(tvb, offset);
            proto_tree_add_bitmask(tag_tree, tvb, offset, hf_s7commp_tagdescr_attributeflags2,
                ett_s7commp_tagdescr_attributeflags, s7commp_tagdescr_attributeflags2_fields, ENC_BIG_ENDIAN);
            offsetinfotype = ((attributeflags2 & S7COMMP_TAGDESCR_ATTRIBUTE2_OFFSETINFOTYPE) >> 12);
            offset += 2;

            /* Bei nicht-optimierten immer 0x08?
             * Sinnvoll auswerten laesst sich der Wert nur bei im IQM-Bereich.
             * Bitoffset pro Nibble:
             * Bit .0 = 0x08
             * Bit .1 = 0x19
             * Bit .2 = 0x2a
             * Bit .3 = 0x3b
             * Bit .4 = 0x4c
             * Wenn kein Bool-Typ, dann 0x00
             */
            proto_tree_add_bitmask(tag_tree, tvb, offset, hf_s7commp_tagdescr_bitoffsetinfo,
                ett_s7commp_tagdescr_bitoffsetinfo, s7commp_tagdescr_bitoffsetinfo_fields, ENC_BIG_ENDIAN);
            offset += 1;

            /* "legacy" offset */
            switch (offsetinfotype) {
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STD:
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_nonoptimized_addr_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_optimized_addr_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STD:
                    /* fields swapped in contrast to previous case! */
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_optimized_addr_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_nonoptimized_addr_16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRING:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRING:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAY1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAY1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAYMDIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAYMDIM:
                    /* first value used as string length */
                    if (softdatatype == S7COMMP_SOFTDATATYPE_STRING ||
                        softdatatype == S7COMMP_SOFTDATATYPE_WSTRING) {
                        proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_s7stringlength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    } else {
                        proto_tree_add_text(tag_tree, tvb, offset, 2, "General Offsetinfo 1: %u (unused?)", tvb_get_letohs(tvb, offset));
                    }
                    offset += 2;
                    proto_tree_add_text(tag_tree, tvb, offset, 2, "General Offsetinfo 2: %u (unused?)", tvb_get_letohs(tvb, offset));
                    offset += 2;
                    break;
                /*************************************************************************/
                default:
                    proto_tree_add_text(tag_tree, tvb, offset, 2, "General Offsetinfo 1: %u (unused?)", tvb_get_letohs(tvb, offset));
                    offset += 2;
                    proto_tree_add_text(tag_tree, tvb, offset, 2, "General Offsetinfo 2: %u (unused?)", tvb_get_letohs(tvb, offset));
                    offset += 2;
                    break;
            }

            /* "new" offset */
            switch (offsetinfotype) {
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STD:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STD:
                    /* nothing special here */
                    break;
                /*************************************************************************/
                default:
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_optimized_addr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_nonoptimized_addr, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    break;
            }

            /* array dimensions */
            switch (offsetinfotype) {
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAY1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAY1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT1DIM:
                    array_lowerbounds = (gint32)tvb_get_letohl(tvb, offset);
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_arraylowerbounds, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    array_elementcount = (gint32)tvb_get_letohl(tvb, offset);
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_arrayelementcount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    proto_item_append_text(tag_tree, "-Array[%d..%d]", array_lowerbounds, array_lowerbounds + (array_elementcount - 1));
                    break;
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_ARRAYMDIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_ARRAYMDIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTMDIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCTMDIM:
                    array_lowerbounds = (gint32)tvb_get_letohl(tvb, offset);
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_arraylowerbounds, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    array_elementcount = (gint32)tvb_get_letohl(tvb, offset);
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_arrayelementcount, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    /* Multidimensional Array max. 6 dimensions */
                    for (d = 0; d < 6; d++) {
                        mdarray_lowerbounds[d] = (gint32)tvb_get_letohl(tvb, offset);
                        proto_tree_add_text(tag_tree, tvb, offset, 4, "MdimArray Info DIM %d, Array lower bounds: %d", d + 1, mdarray_lowerbounds[d]);
                        offset += 4;
                    }
                    mdarray_actdimensions = 0;
                    for (d = 0; d < 6; d++) {
                        mdarray_elementcount[d] = (gint32)tvb_get_letohl(tvb, offset);
                        if (mdarray_elementcount[d] > 0) {
                            mdarray_actdimensions++;
                        }
                        proto_tree_add_text(tag_tree, tvb, offset, 4, "MdimArray Info DIM %d, Array element count: %d", d + 1, mdarray_elementcount[d]);
                        offset += 4;
                    }
                    /* Displaystyle [a..b, c..d, e..f] */
                    proto_item_append_text(tag_tree, "-Array[");
                    for (d = (mdarray_actdimensions - 1); d >= 0; d--) {
                        if (mdarray_elementcount[d] > 0) {
                            proto_item_append_text(tag_tree, "%d..%d", mdarray_lowerbounds[d], mdarray_lowerbounds[d] + (mdarray_elementcount[d] - 1));
                            if (d > 0) {
                                proto_item_append_text(tag_tree, ", ");
                            }
                        }
                    }
                    proto_item_append_text(tag_tree, "]");
                    break;
            }

            /* struct info, alarms */
            switch (offsetinfotype) {
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT1DIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTMDIM:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCTMDIM:
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_nonoptimized_struct_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_optimized_struct_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    /* no break; here */
                    /* Falls through */
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCT:
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_STRUCTELEM_STRUCT:
                    proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_structrelid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "Struct Info 4: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "Struct Info 5: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "Struct Info 6: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "Struct Info 7: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    break;
                /*************************************************************************/
                case S7COMMP_TAGDESCR_OFFSETINFOTYPE2_PROGRAMALARM:
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Relation-Id: 0x%08x", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Info 4: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Info 5: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Info 6: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Info 7: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Info 8: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    proto_tree_add_text(tag_tree, tvb, offset, 4, "ProgramAlarm Info 9: %u", tvb_get_letohl(tvb, offset));
                    offset += 4;
                    break;
            }
            proto_item_set_len(tag_tree, offset - tag_start_offset);
            i++;
        } while (offset < max_offset);
        block_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_s7commp_object_blocklength, tvb, offset, 2, block_len);
        offset += 2;
        max_offset = offset + block_len;
    }; /* while blocklen > 0 */

    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a variable name list (0xac)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_varnamelist(tvbuff_t *tvb,
                           proto_tree *tree,
                           guint32 offset)
{
    guint8 length_of_value;
    guint32 max_offset;
    proto_item *item;
    proto_tree *tag_tree;
    const guint8 *str_name;
    int i = 1;
    guint16 block_len;

    block_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_object_blocklength, tvb, offset, 2, block_len);
    offset += 2;
    max_offset = offset + block_len;

    while (block_len > 0) {
        do {
            /* Laenge eines Namens max. 128 Zeichen */
            length_of_value = tvb_get_guint8(tvb, offset);
            item = proto_tree_add_item(tree, hf_s7commp_element_tagdescription, tvb, offset, (1 + length_of_value + 1), FALSE);
            tag_tree = proto_item_add_subtree(item, ett_s7commp_element_tagdescription);
            proto_tree_add_uint(tag_tree, hf_s7commp_tagdescr_namelength, tvb, offset, 1, length_of_value);
            offset += 1;
            proto_tree_add_item_ret_string(tag_tree, hf_s7commp_tagdescr_name, tvb, offset, length_of_value, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &str_name);
            proto_item_append_text(tag_tree, "[%d]: Name=%s", i, str_name);
            offset += length_of_value;
            /* String-terminierende Null? Bei Laengenangabe eigentlich ueberfluessig */
            proto_tree_add_item(tag_tree, hf_s7commp_tagdescr_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            i++;
        } while (offset < max_offset);
        block_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(tree, hf_s7commp_object_blocklength, tvb, offset, 2, block_len);
        offset += 2;
        max_offset = offset + block_len;
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a list of following fields per set: Syntax-ID, ID, datatype-flags, datatype, value
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_object(tvbuff_t *tvb,
                      packet_info *pinfo,
                      proto_tree *tree,
                      guint32 offset,
                      gboolean append_class)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    proto_item *pi = NULL;
    guint32 start_offset;
    guint32 uint32_value;
    guint32 uint32_value_clsid;
    guint8 octet_count = 0;
    guint8 element_id;
    gboolean terminate = FALSE;

    do {
        start_offset = offset;
        element_id = tvb_get_guint8(tvb, offset);
        switch (element_id) {
            case S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT:              /* 0xa1 */
                data_item = proto_tree_add_item(tree, hf_s7commp_element_object, tvb, offset, -1, FALSE);
                data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_element_object);
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                uint32_value = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(data_item_tree, hf_s7commp_object_relid, tvb, offset, 4, uint32_value);
                offset += 4;
                proto_tree_add_ret_varuint32(data_item_tree, hf_s7commp_object_classid, tvb, offset, &octet_count, &uint32_value_clsid);
                if ((pinfo != NULL) && append_class) {
                    s7commp_pinfo_append_idname(pinfo, uint32_value_clsid, NULL);
                    s7commp_pinfo_append_idname(pinfo, uint32_value, " / ");
                }
                s7commp_proto_item_append_idname(data_item_tree, uint32_value_clsid, ": ClsId=");
                s7commp_proto_item_append_idname(data_item_tree, uint32_value, ", RelId=");
                offset += octet_count;
                uint32_value = tvb_get_varuint32(tvb, &octet_count, offset);
                pi = proto_tree_add_bitmask_value(data_item_tree, tvb, offset, hf_s7commp_object_classflags,
                    ett_s7commp_object_classflags, s7commp_object_classflags_fields, uint32_value);
                proto_item_set_len(pi, octet_count);
                offset += octet_count;
                proto_tree_add_ret_varuint32(data_item_tree, hf_s7commp_object_attributeid, tvb, offset, &octet_count, &uint32_value);
                offset += octet_count;
                if (uint32_value != 0) {
                    proto_tree_add_varuint32(data_item_tree, hf_s7commp_object_attributeidflags, tvb, offset, &octet_count);
                    offset += octet_count;
                }
                offset = s7commp_decode_object(tvb, pinfo, data_item_tree, offset, append_class);
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_TERMOBJECT:               /* 0xa2 */
                proto_tree_add_uint(tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                terminate = TRUE;
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_RELATION:                 /* 0xa4 */
                data_item = proto_tree_add_item(tree, hf_s7commp_element_relation, tvb, offset, -1, FALSE);
                data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_element_relation);
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                proto_tree_add_varuint32(data_item_tree, hf_s7commp_object_relid, tvb, offset, &octet_count);
                offset += octet_count;
                proto_tree_add_item(data_item_tree, hf_s7commp_object_relunknown1, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_STARTTAGDESC:             /* 0xa7 */
                data_item = proto_tree_add_item(tree, hf_s7commp_element_tagdescription, tvb, offset, -1, FALSE);
                data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_element_tagdescription);
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                offset = s7commp_decode_tagdescription(tvb, data_item_tree, offset);
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_TERMTAGDESC:              /* 0xa8 */
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_VARNAMELIST:                /* 0xac */
                data_item = proto_tree_add_item(tree, hf_s7commp_element_block, tvb, offset, -1, FALSE);
                data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_element_block);
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                proto_item_append_text(data_item_tree, ": VarnameList");
                offset = s7commp_decode_varnamelist(tvb, data_item_tree, offset);
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_VARTYPELIST:                /* 0xab */
                data_item = proto_tree_add_item(tree, hf_s7commp_element_block, tvb, offset, -1, FALSE);
                data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_element_block);
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                proto_item_append_text(data_item_tree, ": VartypeList");
                offset = s7commp_decode_vartypelist(tvb, data_item_tree, offset);
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            case S7COMMP_ITEMVAL_ELEMENTID_ATTRIBUTE:                /* 0xa3 */
                data_item = proto_tree_add_item(tree, hf_s7commp_element_attribute, tvb, offset, -1, FALSE);
                data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_element_attribute);
                proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_elementid, tvb, offset, 1, element_id);
                offset += 1;
                offset = s7commp_decode_id_value_list(tvb, pinfo, data_item_tree, offset, FALSE);
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            default:
                terminate = TRUE;
        }
    } while (terminate == FALSE);

    return offset;
}
/*******************************************************************************************************
 *
 * Request CreateObject
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_createobject(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset,
                                    guint8 protocolversion)
{
    int struct_level = 1;
    guint32 start_offset;
    guint32 id_number;
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint8 next_byte;
    guint8 octet_count = 0;
    guint32 value = 0;

    start_offset = offset;
    data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
    id_number = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(data_item_tree, hf_s7commp_data_id_number, tvb, offset, 4, id_number);
    s7commp_proto_item_append_idname(data_item_tree, id_number, ": ID=");
    s7commp_pinfo_append_idname(pinfo, id_number, NULL);
    offset += 4;
    offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, id_number);
    proto_item_set_len(data_item_tree, offset - start_offset);
    /* es folgen noch 4 Null-Bytes */
    proto_tree_add_text(tree, tvb, offset, 4, "Unknown value 1: 0x%08x", tvb_get_ntohl(tvb, offset));
    offset += 4;

    /* Es gibt z.Zt. keine bekannte Moeglichkeit anhand der vorigen Werte festzustellen, ob hier noch ein eingeschobener Wert (VLQ) folgt.
     * Dieser zusaetzliche Wert ist so wie es aussieht nur bei einer 1500 vorhanden.
     * Darum wird geprueft, ob der naechste Wert nicht ein Objekt-Anfang darstellt.
     * Das eingeschobene Byte ist aber definitiv nur bei Data-Telegrammen vorhanden.
     */
    next_byte = tvb_get_guint8(tvb, offset);
    if (((protocolversion == S7COMMP_PROTOCOLVERSION_2) || (protocolversion == S7COMMP_PROTOCOLVERSION_3)) && next_byte != S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT) {
        value = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_text(tree, tvb, offset, octet_count, "Unknown VLQ-Value in Data-CreateObject: %u", value);
        offset += octet_count;
    }
    return s7commp_decode_object(tvb, pinfo, tree, offset, TRUE);
}
/*******************************************************************************************************
 *
 * Response CreateObject
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_createobject(tvbuff_t *tvb,
                                     packet_info *pinfo,
                                     proto_tree *tree,
                                     guint32 offset,
                                     guint8 protocolversion)
{
    guint8 object_id_count = 0;
    guint8 octet_count = 0;
    guint32 object_id = 0;
    int i;
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    object_id_count = tvb_get_guint8(tvb, offset);
    /* TODO: hier die gleiche ID wie beim Request, d.h. aus der Liste? */
    proto_tree_add_uint(tree, hf_s7commp_object_createobjidcount, tvb, offset, 1, object_id_count);
    offset += 1;
    for (i = 0; i < object_id_count; i++) {
        object_id = tvb_get_varuint32(tvb, &octet_count, offset);
        proto_tree_add_uint_format(tree, hf_s7commp_object_createobjid, tvb, offset, octet_count, object_id,
                    "Object Id [%i]: 0x%08x", i+1, object_id);
        offset += octet_count;
        /* add result object ids to info column, usually it's only one single id */
        if (i == 0) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " ObjId=0x%08x", object_id);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, ",0x%08x", object_id);
        }
    }
    /* Ein Daten-Objekt gibt es nur beim Connect.
     * Das Vorhandensein an errorextension feststellen scheitert.
     */
    if (protocolversion == S7COMMP_PROTOCOLVERSION_1) {
        offset = s7commp_decode_object(tvb, pinfo, tree, offset, FALSE);
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Request DeleteObject
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_deleteobject(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    guint32 object_id;
    object_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_object_deleteobjid, tvb, offset, 4, object_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " ObjId=0x%08x", object_id);
    offset += 4;

    return offset;
}
/*******************************************************************************************************
 *
 * Response DeleteObject
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_deleteobject(tvbuff_t *tvb,
                                     packet_info *pinfo,
                                     proto_tree *tree,
                                     guint32 offset,
                                     gboolean *has_integrity_id)
{
    guint32 object_id;
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    object_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_object_deleteobjid, tvb, offset, 4, object_id);
    offset += 4;
    col_append_fstr(pinfo->cinfo, COL_INFO, " ObjId=0x%08x", object_id);

    if (errorextension) {
        offset = s7commp_decode_object(tvb, pinfo, tree, offset, FALSE);
    }
    /* If the id is < 0x7000000 there is no integrity-id in integrity dataset at the end (only for 1500) */
    if (object_id > 0x70000000) {
        *has_integrity_id = TRUE;
    } else {
        *has_integrity_id = FALSE;
    }

    return offset;
}

/*******************************************************************************************************
 *
 * Decodes part 1 of an item address
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_address_part1(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 *number_of_fields,
                                  guint32 *id_value,
                                  guint32 offset)
{
    guint8 octet_count = 0;
    const guint8 *str_id_name;
    guint32 value;
    proto_item *area_item = NULL;
    proto_item *area_item_tree = NULL;
    guint16 var_area1 = 0;
    guint16 db_number = 0;

    /**************************************************************
     * 2. Feld
     * Das zweite Feld ist eine ID aus der ID-Namensliste, welche so etwas wie die "Base-Area" angibt auf den
     * sich die weiteren IDs beziehen.
     * Fuer dem Merkerbereich ist dort auch eine mit der Funktion uebereinstimmende ID vorhanden (82).
     * Fuer Datenbausteine gibt es keine explizite ID, weil sich diese aus einem fixen und einem variablen Teil
     * zusammensetzt.
     *   0x8a0e nnnn, mit nnnn = Nummer des Datenbausteins.
     * Demnach entspricht eine id > 0x8a0e0000=2316173312 (DB0) und id < 0x8a0effff=2316238847 (DB65535) einem DB-Zugriff.
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);

    if ((value >= 0x8a0e0000) && (value <= 0x8a0effff)) {
        area_item = proto_tree_add_uint(tree, hf_s7commp_itemaddr_area, tvb, offset, octet_count, value);
        area_item_tree = proto_item_add_subtree(area_item, ett_s7commp_itemaddr_area);
        var_area1 = (value >> 16);
        db_number = (value & 0xffff);
        proto_tree_add_uint(area_item_tree, hf_s7commp_itemaddr_area1, tvb, offset, octet_count, var_area1);

        proto_tree_add_uint(area_item_tree, hf_s7commp_itemaddr_dbnumber, tvb, offset, octet_count, db_number);
        proto_item_append_text(area_item_tree, " (Datablock, DB-Number: %u)", db_number);
        proto_item_append_text(tree, " DB%u", db_number);
    } else {
        proto_tree_add_uint(tree, hf_s7commp_itemaddr_area_base, tvb, offset, octet_count, value);
        if ((str_id_name = try_val_to_str_ext(value, &id_number_names_ext))) {
            proto_item_append_text(tree, " %s", str_id_name);
        } else {
            proto_item_append_text(tree, " (%u)", value);
        }
    }
    offset += octet_count;

    *number_of_fields += 1;
    *id_value = value;

    return offset;
}
/*******************************************************************************************************
 *
 * Decodes fields 4 and 5 of an item address
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_address_part2(tvbuff_t *tvb,
                                  proto_tree *tree,
                                  guint32 *number_of_fields,
                                  guint32 id_value,
                                  guint32 crc,
                                  guint32 lid_nest_depth,
                                  guint32 offset)
{
    guint32 value = 0;
    guint32 lid_cnt = 0;
    guint32 first_lid = 0;
    guint8 octet_count = 0;
    const guint8 *str_id_name;
    gboolean is_datablock_access = FALSE;
    gboolean is_iqmct_access = FALSE;
    gboolean is_classicblob_access = FALSE;

    /**************************************************************
     * 4. Feld
     * Eine ID aus der ID-Namensliste. Hiermit wird angezeigt, welcher Typ von Wert gelesen werden soll.
     * Bei Merkern: 3736 = ControllerArea.ValueActual
     * Bei DBs: 2550 = DB.ValueActual
     * Vermutlich lassen sich damit auch Startwerte im DB lesen (ueber 2548).
     * Es lassen sich auch diverse andere Objekte der SPS lesen.
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);
    proto_tree_add_uint(tree, hf_s7commp_itemaddr_area_sub, tvb, offset, octet_count, value);
    if ((str_id_name = try_val_to_str_ext(value, &id_number_names_ext))) {
        proto_item_append_text(tree, ", %s", str_id_name);
    } else {
        proto_item_append_text(tree, ", (%u)", value);
    }
    offset += octet_count;

    *number_of_fields += 1;

    /**************************************************************
     * 5. bis n. Feld
     * LID pro Nest-Level
     */
    is_datablock_access = ((id_value >= 0x8a0e0000) && (id_value <= 0x8a0effff));     /* Datenbaustein mit Nummer */
    is_iqmct_access = ((id_value >= 80) && (id_value <= 84));                         /* 80=I, 81=Q, 82=M, 83=C, 84=T */
    is_classicblob_access = (crc == 0) && (is_datablock_access || is_iqmct_access);

    if (lid_nest_depth > 1) {
        if (is_classicblob_access) {
            lid_cnt = 2;
            /* 1. LID: Zugriffsart */
            first_lid = tvb_get_varuint32(tvb, &octet_count, offset);
            proto_tree_add_text(tree, tvb, offset, octet_count, "LID-access Aid: %s (%u)", val_to_str(first_lid, lid_access_aid_names, "%u"), first_lid);
            proto_item_append_text(tree, ", %s (%u)", val_to_str(first_lid, lid_access_aid_names, "%u"), first_lid);
            offset += octet_count;
            lid_cnt += 1;
            *number_of_fields += 1;
            /* Wenn Zugriffsart == 3 (ClassicBlob), dann wird mit Absolutadressen gearbeitet */
            if (first_lid == 3) {
                /* 2. Startadresse */
                value = tvb_get_varuint32(tvb, &octet_count, offset);
                proto_tree_add_text(tree, tvb, offset, octet_count, "Blob startoffset: %u", value);
                proto_item_append_text(tree, ", Offs=%u", value);
                offset += octet_count;
                lid_cnt += 1;
                *number_of_fields += 1;
                /* 3. Anzahl an Bytes */
                value = tvb_get_varuint32(tvb, &octet_count, offset);
                proto_tree_add_text(tree, tvb, offset, octet_count, "Blob bytecount: %u", value);
                proto_item_append_text(tree, ", Cnt=%u", value);
                offset += octet_count;
                lid_cnt += 1;
                *number_of_fields += 1;
                /* Wenn jetzt noch ein Feld folgt, dann ist es ein Bitoffset */
                if (lid_nest_depth >= lid_cnt) {
                    value = tvb_get_varuint32(tvb, &octet_count, offset);
                    proto_tree_add_text(tree, tvb, offset, octet_count, "Blob bitoffset: %u", value);
                    proto_item_append_text(tree, ", Bitoffs=%u", value);
                    offset += octet_count;
                    lid_cnt += 1;
                    *number_of_fields += 1;
                }
            }
            /* TODO: Wenn jetzt noch LIDs folgen, erstmal als weitere IDs anzeigen */
            if (lid_nest_depth > lid_cnt) {
                proto_item_append_text(tree, ", LID=");
            }
            for (lid_cnt = lid_cnt; lid_cnt <= lid_nest_depth; lid_cnt++) {
                value = tvb_get_varuint32(tvb, &octet_count, offset);
                proto_tree_add_uint(tree, hf_s7commp_itemaddr_lid_value, tvb, offset, octet_count, value);
                if (lid_cnt == lid_nest_depth) {
                    proto_item_append_text(tree, "%u", value);
                } else {
                    proto_item_append_text(tree, "%u.", value);
                }
                offset += octet_count;
                *number_of_fields += 1;
            }
        } else {
            /* Standard fuer symbolischen Zugriff mit crc und LIDs */
            proto_item_append_text(tree, ", LID=");
            for (lid_cnt = 2; lid_cnt <= lid_nest_depth; lid_cnt++) {
                value = tvb_get_varuint32(tvb, &octet_count, offset);
                proto_tree_add_uint(tree, hf_s7commp_itemaddr_lid_value, tvb, offset, octet_count, value);
                if (lid_cnt == lid_nest_depth) {
                    proto_item_append_text(tree, "%u", value);
                } else {
                    proto_item_append_text(tree, "%u.", value);
                }
                offset += octet_count;
                *number_of_fields += 1;
            }
        }
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a plc address
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_address(tvbuff_t *tvb,
                            proto_tree *tree,
                            guint32 *number_of_fields,
                            guint32 item_nr,
                            guint32 offset)
{
    proto_item *adr_item = NULL;
    proto_tree *adr_item_tree = NULL;
    guint8 octet_count = 0;
    guint32 id_value = 0;
    guint32 crc = 0;
    guint32 lid_nest_depth = 0;
    guint32 start_offset = offset;

    *number_of_fields = 0;

    adr_item = proto_tree_add_item(tree, hf_s7commp_data_item_address, tvb, offset, -1, FALSE);
    adr_item_tree = proto_item_add_subtree(adr_item, ett_s7commp_data_item);
    proto_item_append_text(adr_item_tree, " [%u]:", item_nr);

    /**************************************************************
     * 1. Feld
     * CRC als varuint
     *
     * Es gibt mindestens zwei Interpretationsarten:
     * 1) Symbolischer Zugriff vom HMI ueber CRC und LID
     * 2) Zugriff auf Objekte ueber AID/RID
     *
     * Vom Aufbau her sind beide Adressen identisch nur die Interpretation ist eine andere. Die Unterscheidung
     * erfolgt anhand des ersten Feldes (crc). Ist dieses Null, dann ist es eine Object ID Interpretation.
     * Ohne crc scheint es sich bei den LIDs um Adressen zu handeln, wenn der DB ein nicht-optimierter DB ist, oder
     * der Speicherbereich IQMCT ist.
     * Zumindest bei I/Q/M und nicht opt. DBs passt das mit den Adressen ueberein, bei T/C wird die Nummer mal zwei genommen.
     * Optimierte DBs werden nach aktueller Erkenntnis immer mit crc gelesen.
     * Beispiel: M122.7: 3.122.1.7
     *                   3 = ClassicBlob, 122 = offset, 1 = Typ BOOL??? nur dann folgt eine Bitadresse, 7=bitoffset
     *                   Antwort ist dann mit Datentyp BOOL
     * Beispiel: DB1.intVar2 (nicht opt. an DB1.DBW2): 3.2.2
     *                   3 = ClassicBlob, 2 = offset, 2 = Typ Blob?, bzw. Laenge 2 Bytes?
     *                   Antwort ist mit Datentyp Blob von Groesse 2
     * Beispiel: DB1.dateAndTimeVar_48_0 = 3.48.8
     *                   3 = ClassicBlob, 48 = offset, 8 = length
     */
    proto_tree_add_ret_varuint32(adr_item_tree, hf_s7commp_itemaddr_crc, tvb, offset, &octet_count, &crc);
    offset += octet_count;

    *number_of_fields += 1;

    /**************************************************************
     * ID aus der Namensliste
     */
    offset = s7commp_decode_item_address_part1(tvb, adr_item_tree, number_of_fields, &id_value, offset);

    proto_item_append_text(adr_item_tree, ", SYM-CRC=%x", crc);
    /**************************************************************
     * 3. Feld
     * LID Nesting Depth
     *
     * 0x01: Merker                 Folgende LIDs: 1
     * 0x02: DB.VAR                 Folgende LIDs: 1
     * 0x03: DB.STRUCT.VAR          Folgende LIDs: 2
     * 0x03: DB.ARRAY[INDEX]        Folgende LIDs: 2
     * 0x04: DB.STRUCT.STRUCT.VAR   Folgende LIDs: 3
     * -> Die Werte gelten nur wenn mit crc != 0 gelesen wird!
     */
    proto_tree_add_ret_varuint32(adr_item_tree, hf_s7commp_itemaddr_idcount, tvb, offset, &octet_count, &lid_nest_depth);
    offset += octet_count;
    *number_of_fields += 1;

    /**************************************************************
     * Felder 4 und 5 und weitere LIDs
     */
    offset = s7commp_decode_item_address_part2(tvb, adr_item_tree, number_of_fields, id_value, crc, lid_nest_depth, offset);

    proto_item_set_len(adr_item_tree, offset - start_offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Decodes a plc address in subscription array.
 *
 * Abgeleitet von s7commp_decode_item_address().
 * Unterschiede:
 * - "Symbol-CRC" und "Access base-area" tauschen die Reihenfolge
 * - Kein "Number of following IDs" als Einzelwert, sondern in den 16 Bits eines 32 Bit Werts codiert.
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_item_address_sub(tvbuff_t *tvb,
                                proto_tree *tree,
                                guint32 *number_of_fields,
                                guint32 item_nr,
                                guint32 offset)
{
    proto_item *adr_item = NULL;
    proto_tree *adr_item_tree = NULL;

    guint8 octet_count = 0;
    guint32 value = 0;
    guint32 id_value = 0;
    guint32 crc = 0;
    guint32 lid_nest_depth = 0;
    guint32 start_offset = offset;
    proto_item *ret_item = NULL;

    adr_item = proto_tree_add_item(tree, hf_s7commp_data_item_address, tvb, offset, -1, FALSE);
    adr_item_tree = proto_item_add_subtree(adr_item, ett_s7commp_data_item);
    proto_item_append_text(adr_item_tree, " [%u]:", item_nr);

    /* z.B. 0x80040003
     * Wofuer die linken 2 Bytes stehen ist nicht bekannt.
     * In den rechten 2 Bytes steht die Anzahl der LIDs.
     */
    value = tvb_get_varuint32(tvb, &octet_count, offset);
    lid_nest_depth = value & 0xffff;
    ret_item = proto_tree_add_bitmask_value(adr_item_tree, tvb, offset, hf_s7commp_subscrreflist_item_head,
        ett_s7commp_subscrreflist_item_head, s7commp_subscrreflist_item_head_fields, value);
    proto_item_set_len(ret_item, octet_count);
    offset += octet_count;
    *number_of_fields += 1;

    proto_tree_add_varuint32(adr_item_tree, hf_s7commp_notification_vl_refnumber, tvb, offset, &octet_count);
    offset += octet_count;
    *number_of_fields += 1;

    proto_tree_add_varuint32(adr_item_tree, hf_s7commp_subscrreflist_item_unknown1, tvb, offset, &octet_count);
    offset += octet_count;
    *number_of_fields += 1;

    /**************************************************************
     * ID aus der Namensliste
     */
    offset = s7commp_decode_item_address_part1(tvb, adr_item_tree, number_of_fields, &id_value, offset);

    /**************************************************************
     * CRC als varuint
     */
    proto_tree_add_ret_varuint32(adr_item_tree, hf_s7commp_itemaddr_crc, tvb, offset, &octet_count, &crc);
    proto_item_append_text(adr_item_tree, ", SYM-CRC=%x", crc);
    offset += octet_count;
    *number_of_fields += 1;

    /**************************************************************
     * Felder 4 und 5 und weitere LIDs
     */
    offset = s7commp_decode_item_address_part2(tvb, adr_item_tree, number_of_fields, id_value, crc, lid_nest_depth, offset);

    proto_item_set_len(adr_item_tree, offset - start_offset);

    return offset;
}


/*******************************************************************************************************
 *
 * Request SetMultiVariables
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_setmultivar(tvbuff_t *tvb,
                                   packet_info *pinfo,
                                   proto_tree *tree,
                                   gint16 dlength _U_,
                                   guint32 offset)
{
    guint32 item_count = 0;
    guint32 number_of_fields_in_complete_set = 0;
    guint32 i = 0;
    guint32 number_of_fields = 0;
    guint32 value;
    guint8 octet_count = 0;
    guint32 item_address_count;
    guint32 id_number;
    guint32 id_number_offset;
    guint32 offset_save;
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint32 list_start_offset;

    /* Wenn die ersten 4 Bytes 0x00, dann ist es ein 'normaler' Schreib-Befehl.
     * Es kann sein, dass hier die Session-ID steht, dann ist der Aufbau anders.
     */
    value = tvb_get_ntohl(tvb, offset);
    offset += 4;

    if (value == 0) {
        proto_tree_add_uint(tree, hf_s7commp_setvar_unknown1, tvb, offset-4, 4, value);
        proto_tree_add_ret_varuint32(tree, hf_s7commp_item_count, tvb, offset, &octet_count, &item_count);
        offset += octet_count;

        proto_tree_add_ret_varuint32(tree, hf_s7commp_item_no_of_fields, tvb, offset, &octet_count, &number_of_fields_in_complete_set);
        offset += octet_count;
        /* Es lassen sich mehrere Variablen mit einem write schreiben.
         * Danach folgen erst die Adressen und dann die Werte.
         */
        list_start_offset = offset;
        list_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_addresslist);
        for (i = 1; i <= item_count; i++) {
            offset = s7commp_decode_item_address(tvb, list_item_tree, &number_of_fields, i, offset);
            number_of_fields_in_complete_set -= number_of_fields;
        }
        proto_item_set_len(list_item_tree, offset - list_start_offset);

        list_start_offset = offset;
        list_item = proto_tree_add_item(tree, hf_s7commp_valuelist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
        for (i = 1; i <= item_count; i++) {
            offset = s7commp_decode_itemnumber_value_list(tvb, pinfo, list_item_tree, offset, FALSE);
        }
        proto_item_set_len(list_item_tree, offset - list_start_offset);
    } else {
        proto_tree_add_uint(tree, hf_s7commp_setvar_objectid, tvb, offset-4, 4, value);
        col_append_fstr(pinfo->cinfo, COL_INFO, " ObjId=0x%08x", value);
        proto_tree_add_ret_varuint32(tree, hf_s7commp_setvar_itemcount, tvb, offset, &octet_count, &item_count);
        offset += octet_count;
        proto_tree_add_ret_varuint32(tree, hf_s7commp_setvar_itemaddrcount, tvb, offset, &octet_count, &item_address_count);
        offset += octet_count;

        list_start_offset = offset;
        list_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_addresslist);
        id_number_offset = offset;  /* Startaddresse der 1. ID */
        for (i = 1; i <= item_address_count; i++) {
            proto_tree_add_varuint32(list_item_tree, hf_s7commp_data_id_number, tvb, offset, &octet_count);
            offset += octet_count;
        }
        proto_item_set_len(list_item_tree, offset - list_start_offset);

        list_start_offset = offset;
        list_item = proto_tree_add_item(tree, hf_s7commp_valuelist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
        for (i = 1; i <= item_count; i++) {
            /* Nochmal zugehoerige ID auslesen um die ID zum Datensatz zu bekommen. */
            id_number = tvb_get_varuint32(tvb, &octet_count, id_number_offset);
            id_number_offset += octet_count;
            offset_save = offset;

            offset = s7commp_decode_itemnumber_value_list(tvb, pinfo, list_item_tree, offset, FALSE);

            /* ID 1048 = SubscriptionReferenceList gesondert decodieren */
            if (id_number == 1048) {
                tvb_get_varuint32(tvb, &octet_count, offset); /* Laenge des Item-number elements */
                s7commp_decode_attrib_subscriptionreflist(tvb, list_item_tree, offset_save + octet_count);
            }
        }
        proto_item_set_len(list_item_tree, offset - list_start_offset);
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Request GetMultiVariables
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_getmultivar(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    guint32 item_count = 0;
    guint32 number_of_fields_in_complete_set = 0;
    guint32 i = 0;
    guint32 number_of_fields = 0;
    guint32 value;
    guint8 octet_count = 0;
    guint32 item_address_count;
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint32 list_start_offset;

    /* Zum Variablen-Lesen muessen die ersten 4 Bytes 0 sein. Andernfalls ist es eine Link-Id.
     */
    value = tvb_get_ntohl(tvb, offset);
    if (value == 0) {
        proto_tree_add_uint(tree, hf_s7commp_getmultivar_unknown1, tvb, offset, 4, value);
    } else {
        proto_tree_add_uint(tree, hf_s7commp_getmultivar_linkid, tvb, offset, 4, value);
    }
    offset += 4;
    proto_tree_add_ret_varuint32(tree, hf_s7commp_item_count, tvb, offset, &octet_count, &item_count);
    offset += octet_count;
    if (value == 0x0) {
        proto_tree_add_ret_varuint32(tree, hf_s7commp_item_no_of_fields, tvb, offset, &octet_count, &number_of_fields_in_complete_set);
        offset += octet_count;
        list_start_offset = offset;
        list_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_addresslist);
        for (i = 1; i <= item_count; i++) {
            offset = s7commp_decode_item_address(tvb, list_item_tree, &number_of_fields, i, offset);
            number_of_fields_in_complete_set -= number_of_fields;
        }
        proto_item_set_len(list_item_tree, offset - list_start_offset);
    } else {
        proto_tree_add_ret_varuint32(tree, hf_s7commp_getmultivar_itemaddrcount, tvb, offset, &octet_count, &item_address_count);
        offset += octet_count;
        list_start_offset = offset;
        list_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_addresslist);
        for (i = 1; i <= item_address_count; i++) {
            proto_tree_add_varuint32(list_item_tree, hf_s7commp_data_id_number, tvb, offset, &octet_count);
            offset += octet_count;
        }
        proto_item_set_len(list_item_tree, offset - list_start_offset);
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Response GetMultiVariables
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_getmultivar(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    offset = s7commp_decode_itemnumber_value_list_in_new_tree(tvb, pinfo, tree, offset, TRUE);
    offset = s7commp_decode_itemnumber_errorvalue_list(tvb, tree, offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Response SetMultiVariables
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_setmultivar(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;
    /* Der Unterschied zum Read-Response ist, dass man hier sofort im Fehlerbereich ist wenn das erste Byte != 0.
     * Ein erfolgreiches Schreiben einzelner Werte scheint nicht extra bestaetigt zu werden.
     */

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    offset = s7commp_decode_itemnumber_errorvalue_list(tvb, tree, offset);
    return offset;
}
/*******************************************************************************************************
 *
 * Notification Value List
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_notification_value_list(tvbuff_t *tvb,
                                       packet_info *pinfo,
                                       proto_tree *tree,
                                       guint32 offset,
                                       gboolean recursive)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint32 item_number;
    guint32 start_offset;
    guint8 octet_count;
    guint8 item_return_value;
    int struct_level;
    int n_access_errors = 0;
    /* Return value: Ist der Wert ungleich 0, dann folgt ein Datensatz mit dem bekannten
     * Aufbau aus den anderen Telegrammen.
     * Liegt ein Adressfehler vor, so werden hier auch Fehlerwerte uebertragen. Dann ist Datatype=NULL
     * Folgende Rueckgabewerte wurden gesichtet:
     *  0x03 -> Fehler bei einer Adresse (S7-1500 - Plcsim)
     *  0x13 -> Fehler bei einer Adresse (S7-1200) und 1500-Plcsim
     *  0x81 -> Standard Objekt beginnend mit 0xa1 (nur bei Protokoll-Version v1?)
     *  0x83 -> Standard value Aufbau, dann notification value-list (nur bei Protokoll-Version v1?)
     *  0x92 -> Erfolg (S7-1200)
     *  0x9b -> Bei 1500 und 1200 gesehen. Es folgt eine ID oder Nummer, dann flag, typ, wert.
     *  0x9c -> Bei Beobachtung mit einer Variablentabelle (S7-1200), Aufbau scheint dann anders zu sein
     *  => Bit 15 = true bei Erfolg?
     * Danach koennen noch weitere Daten folgen, deren Aufbau bisher nicht bekannt ist.
     */
    do {
        struct_level = 0;
        item_return_value = tvb_get_guint8(tvb, offset);
        if (item_return_value == 0) {
            proto_tree_add_item(tree, hf_s7commp_listitem_terminator, tvb, offset, 1, FALSE);
            offset += 1;
            if (n_access_errors > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " <Access errors: %d>", n_access_errors);
            }
            return offset;
        } else {
            start_offset = offset;
            data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
            proto_tree_add_uint(data_item_tree, hf_s7commp_notification_vl_retval, tvb, offset, 1, item_return_value);
            offset += 1;
            if (item_return_value == 0x92) {
                /* Item reference number. Is sent to plc on the subscription-telegram for the addresses. */
                item_number = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(data_item_tree, hf_s7commp_notification_vl_refnumber, tvb, offset, 4, item_number);
                offset += 4;
                proto_item_append_text(data_item_tree, " [%u]:", item_number);
                offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, 0);
            } else if (item_return_value == 0x9b) {
                proto_tree_add_ret_varuint32(data_item_tree, hf_s7commp_data_id_number, tvb, offset, &octet_count, &item_number);
                offset += octet_count;
                proto_item_append_text(data_item_tree, " [%u]:", item_number);
                offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, 0);
            } else if (item_return_value == 0x9c) {
                item_number = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(data_item_tree, hf_s7commp_notification_vl_unknown0x9c, tvb, offset, 4, item_number);
                proto_item_append_text(data_item_tree, " Returncode 0x9c, Value: 0x%08x", item_number);
                offset += 4;
            } else if (item_return_value == 0x13 || item_return_value == 0x03) {
                item_number = tvb_get_ntohl(tvb, offset);
                proto_tree_add_uint(data_item_tree, hf_s7commp_notification_vl_refnumber, tvb, offset, 4, item_number);
                proto_item_append_text(data_item_tree, " [%u]: Access error", item_number);
                offset += 4;
                n_access_errors++;
            } else if (item_return_value == 0x81) {     /* Vermutlich nur in Protokoll Version v1*/
                offset = s7commp_decode_object(tvb, pinfo, data_item_tree, offset, FALSE);
            } else if (item_return_value == 0x83) {     /* Vermutlich nur in Protokoll Version v1*/
                offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, 0);
            } else {
                expert_add_info_format(pinfo, data_item_tree, &ei_s7commp_notification_returnvalue_unknown, "Notification unknown return value: 0x%02x", item_return_value);
                proto_item_set_len(data_item_tree, offset - start_offset);
                break;
            }
            if (struct_level > 0) {
                offset = s7commp_decode_notification_value_list(tvb, pinfo, data_item_tree, offset, TRUE);
            }
            proto_item_set_len(data_item_tree, offset - start_offset);
        }
    } while (recursive);

    return offset;
}
/*******************************************************************************************************
 *
 * Notification
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_notification(tvbuff_t *tvb,
                            packet_info *pinfo,
                            proto_tree *tree,
                            guint32 offset)
{
    guint16 unknown2;
    guint32 subscr_object_id, subscr_object_id2;
    guint8 credit_tick;
    guint32 seqnum;
    guint8 item_return_value;
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint8 octet_count = 0;
    gboolean add_data_info_column = FALSE;
    guint32 list_start_offset;

    /* 4 Bytes Subscription Object Id */
    subscr_object_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_notification_subscrobjectid, tvb, offset, 4, subscr_object_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " ObjId=0x%08x", subscr_object_id);
    offset += 4;

    /* 6/7: Unbekannt */
    unknown2 = tvb_get_ntohs(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_notification_unknown2, tvb, offset, 2, unknown2);
    offset += 2;

    proto_tree_add_item(tree, hf_s7commp_notification_unknown3, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (unknown2 == 0x0400) {
        /* Bei V13 und einer 1200 werden hiermit Daten vom HMI zyklisch
         * bei AEnderung uebermittelt. Daten sind nur enthalten wenn sich etwas aendert.
         * Sonst gibt es ein verkuerztes (Status?)-Telegramm.
         */
        proto_tree_add_item(tree, hf_s7commp_notification_unknown4, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Es gibt zwei Nummern:
         * 1) Nummerierung fuer Creditlimit: Wird bei Aufbau der notification-session ein Wert angegeben, so erfolgt die UEbertragung
         *                                  bis zur in modifiy-session angegebenen Limit.
         * 2) Sequenznummer: Wurde beim Session-Aufbau -1 angegeben, so ist die Zahl bei 1) Null, und es folgt hier eine aufsteigende Nummer.
         *
         * Bei der Sequenznummer scheint es einen Unterschied zwischen 1200 und 1500 zu geben.
         * Bei der 1200 ist diese immer nur 1 Byte, bei der 1500 ist es ein VLQ!
         * Es scheint abhaengig von der ersten ID zu sein. Ist diese groesser 0x7000000 dann ist es ein VLQ.
         * Es scheint generell so, dass eine 1200 IDs beginnend mit 0x1.. und eine 1500 mit 0x7.. verwendet.
         * Eine 1200 mit FW4 verwendet ebenfall > 0x700000. An der Protokollversion kann es nicht festgemacht werden.
         */
        credit_tick = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_s7commp_notification_credittick, tvb, offset, 1, credit_tick);
        offset += 1;
        if (subscr_object_id > 0x70000000) {
            proto_tree_add_ret_varuint32(tree, hf_s7commp_notification_seqnum_vlq, tvb, offset, &octet_count, &seqnum);
            offset += octet_count;
        } else {
            seqnum = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(tree, hf_s7commp_notification_seqnum_uint8, tvb, offset, 1, seqnum);
            offset += 1;
        }
        col_append_fstr(pinfo->cinfo, COL_INFO, " Ctick=%u NSeq=%u", credit_tick, seqnum);

        item_return_value = tvb_get_guint8(tvb, offset);
        /* Woran zu erkennen ist, dass hier ein eingeschobener Wert folgt ist noch nicht bekannt.
         * Wenn vorhanden, wird dieser Wert (gelegentlich) jedes Telegramm erhoeht, sodass auch normal "gueltige"
         * retval Werte einer Variable moeglich sind.
         * Ist es ein retval der Variable, dann folgt ueblicherweise min. ein 0xff da die Referenznummern von
         * 0xffffffff abwaerts gezaehlt werden.
         * Hier besteht auf jeden Fall noch Analysebedarf.
         */
        if ((subscr_object_id > 0x70000000) && (item_return_value != 0x00 && (tvb_get_guint8(tvb, offset + 1) != 0xff))) {
            proto_tree_add_uint(tree, hf_s7commp_notification_unknown5, tvb, offset, 1, item_return_value);
            offset += 1;
        }

        list_item = proto_tree_add_item(tree, hf_s7commp_valuelist, tvb, offset, -1, FALSE);
        list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
        list_start_offset = offset;
        offset = s7commp_decode_notification_value_list(tvb, pinfo, list_item_tree, offset, TRUE);
        proto_item_set_len(list_item_tree, offset - list_start_offset);
        if (offset - list_start_offset > 1) {
            add_data_info_column = TRUE;
        }

        /* Noch ein spezial Datensatz, mit ein paar unbekannten Werten davor und einer Standard Objekt-Datenstruktur. */
        if (tvb_get_guint8(tvb, offset) != 0) {
            subscr_object_id2 = tvb_get_ntohl(tvb, offset);
            if (subscr_object_id2 != 0) {
                proto_tree_add_uint(tree, hf_s7commp_notification_p2_subscrobjectid, tvb, offset, 4, subscr_object_id2);
                offset += 4;
                proto_tree_add_item(tree, hf_s7commp_notification_p2_unknown1, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tree, hf_s7commp_notification_p2_unknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                if (tvb_get_guint8(tvb, offset) == S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT) {
                    offset =  s7commp_decode_object(tvb, pinfo, tree, offset, TRUE);
                }
            }
        }
        /* Nur wenn die id > 0x70000000 dann folgen noch 3 Bytes, die bisher immer null waren.
         * Das ist hier weiterhin notwendig, da ansonsten ein ggf. vorhandener Integritaetsteil nicht erkannt wuerde.
         */
        if (subscr_object_id > 0x70000000) {
            /* Unknown additional 3 bytes, because 1st Object ID > 0x70000000 */
            proto_tree_add_item(tree, hf_s7commp_notification_unknown3b, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
        }
        if (add_data_info_column) {
            col_append_str(pinfo->cinfo, COL_INFO, " <Contains values>");
        }
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Notification, used only in Protocol Version 1
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_notification_v1(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *tree,
                               guint32 offset)
{
    guint32 subscr_object_id;
    guint32 list_start_offset;

    /* 4 Bytes Subscription Object Id -> scheint hier nicht der Fall zu sein? */
    subscr_object_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_notification_subscrobjectid, tvb, offset, 4, subscr_object_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, " ObjId=0x%08x", subscr_object_id);
    offset += 4;

    proto_tree_add_text(tree, tvb, offset, 4, "Notification v1, Unknown 2: 0x%08x", tvb_get_ntohl(tvb, offset));
    offset += 4;
    /* Alle folgenden Werte sind nur vorhanden, wenn hier keine 4 Null-Bytes folgen.
     * Der Wert an dieser Stelle ist meistens um 2 oder 3 hoeher als die obige Object Id.
     */
    if (tvb_get_ntohl(tvb, offset) != 0) {
        proto_tree_add_text(tree, tvb, offset, 4, "Notification v1, Unknown 3: 0x%08x", tvb_get_ntohl(tvb, offset));
        offset += 4;
        proto_tree_add_text(tree, tvb, offset, 2, "Notification v1, Unknown 4: 0x%04x", tvb_get_ntohs(tvb, offset));
        offset += 2;
        list_start_offset = offset;
        offset = s7commp_decode_notification_value_list(tvb, pinfo, tree, offset, TRUE);
        if (offset - list_start_offset > 1) {
            col_append_str(pinfo->cinfo, COL_INFO, " <Contains values>");
        }
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Extended decoding of attribute with id SubscriptionReferenceList
 *
 * Der komplette "Item-Value" Zweig wurde vorher schon mit der Standard-Funktion zerlegt
 * und auch im Baum angezeigt.
 * Diese Funktion dekodiert die Werte weiter in die Adressen, weil diese fuer eine Analyse
 * welche Werte abbonniert werden interessanter sind.
 * Wenn Datentyp und flags nicht zum Standard passen, wird abgebrochen.
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_attrib_subscriptionreflist(tvbuff_t *tvb,
                                          proto_tree *tree,
                                          guint32 offset)
{
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    proto_item *sub_list_item = NULL;
    proto_tree *sub_list_item_tree = NULL;

    guint8 octet_count = 0;
    guint32 item_count_unsubscr = 0;
    guint32 item_count_subscr = 0;
    guint32 i;
    guint32 array_index = 1;
    guint32 list_start_offset;
    guint32 sub_list_start_offset;

    /* Datatype flags: 0x20 fuer Adressarray sein
     * Datatype: sollte 0x04 fuer UDInt sein
     */
    if ((tvb_get_guint8(tvb, offset) != 0x20) || (tvb_get_guint8(tvb, offset+1) != S7COMMP_ITEM_DATATYPE_UDINT)) {
        return offset;
    }
    offset += 2;

    /* Array size: wird nicht weiter benoetigt, muss fuer die Berechnung des offsets aber nochmal ausgelesen werden */
    tvb_get_varuint32(tvb, &octet_count, offset);
    offset += octet_count;

    list_start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_s7commp_subscrreflist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_subscrreflist);

    /* Header mit insgesamt 3 Werten
     * 1. Wert:
     * Bei Request Create Object: 0x80010000
     * Bei Request SetMultiVariables: 0x00020000, 0x00030000, 0x00040000, 0x00050000, 0x00060000
     *   Bearbeitet die Liste?
     */
    proto_tree_add_varuint32(list_item_tree, hf_s7commp_subscrreflist_unknown1, tvb, offset, &octet_count);
    offset += octet_count;
    array_index += 1;

    proto_tree_add_ret_varuint32(list_item_tree, hf_s7commp_subscrreflist_itemcount_unsubscr, tvb, offset, &octet_count, &item_count_unsubscr);
    offset += octet_count;
    array_index += 1;

    proto_tree_add_ret_varuint32(list_item_tree, hf_s7commp_subscrreflist_itemcount_subscr, tvb, offset, &octet_count, &item_count_subscr);
    proto_item_append_text(list_item_tree, ": %u %s, %u %s", item_count_subscr, (item_count_subscr > 1) ? "Subscriptions" : "Subscription",
        item_count_unsubscr, (item_count_unsubscr > 1) ? "Un-Subscriptions" : "Un-Subscription");
    offset += octet_count;
    array_index += 1;

    if (item_count_unsubscr > 0) {
        sub_list_start_offset = offset;
        sub_list_item = proto_tree_add_item(list_item_tree, hf_s7commp_subscrreflist_unsubscr_list, tvb, offset, -1, FALSE);
        sub_list_item_tree = proto_item_add_subtree(sub_list_item, ett_s7commp_subscrreflist);
        for (i = 1; i <= item_count_unsubscr; i++) {
            proto_tree_add_varuint32(sub_list_item_tree, hf_s7commp_notification_vl_refnumber, tvb, offset, &octet_count);
            offset += octet_count;
        }
        proto_item_set_len(sub_list_item_tree, offset - sub_list_start_offset);
    }

    if (item_count_subscr > 0) {
        sub_list_start_offset = offset;
        sub_list_item = proto_tree_add_item(list_item_tree, hf_s7commp_subscrreflist_subscr_list, tvb, offset, -1, FALSE);
        sub_list_item_tree = proto_item_add_subtree(sub_list_item, ett_s7commp_subscrreflist);
        for (i = 1; i <= item_count_subscr; i++) {
            offset = s7commp_decode_item_address_sub(tvb, sub_list_item_tree, &array_index, i, offset);
        }
        proto_item_set_len(sub_list_item_tree, offset - sub_list_start_offset);
    }

    proto_item_set_len(list_item_tree, offset - list_start_offset);
    /* Kennzeichnen dass diese Liste vorher schon verarbeitet wurde */
    PROTO_ITEM_SET_GENERATED(list_item_tree);
    return offset;
}
/*******************************************************************************************************
 *
 * Request SetVariable
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_setvariable(tvbuff_t *tvb,
                                   packet_info *pinfo,
                                   proto_tree *tree,
                                   guint32 offset)
{
    guint32 object_id;
    guint8 octet_count = 0;
    guint32 item_address_count = 0;
    guint32 i;
    int struct_level = 0;
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint32 list_start_offset;

    object_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_setvar_objectid, tvb, offset, 4, object_id);
    s7commp_pinfo_append_idname(pinfo, object_id, " ObjId=");
    offset += 4;

    proto_tree_add_ret_varuint32(tree, hf_s7commp_setvar_itemaddrcount, tvb, offset, &octet_count, &item_address_count);
    offset += octet_count;

    list_start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_addresslist);
    /* Wenn count == 1 dann folgt nur eine ID. Wenn z.B. count == 4, dann folgen 2 IDs, eine Null
     * und dann eine Laengenangabe die mit der Roh-Laenge im folgenden Value-Teil identisch ist.
     * Warum diese Redundanz ist nicht klar. Vermutetes Schema was zumindest bei den bisherigen
     * Aufzeichnungen funktioniert:
     * Wenn innerhalb Schleife ein Nullwert auftritt, dann folgt danach noch eine Laenge.
     */
    for (i = 1; i <= item_address_count; i++) {
        proto_tree_add_ret_varuint32(list_item_tree, hf_s7commp_data_id_number, tvb, offset, &octet_count, &object_id);
        offset += octet_count;
        if (object_id == 0) {
            proto_tree_add_varuint32(list_item_tree, hf_s7commp_setvar_rawvaluelen, tvb, offset, &octet_count);
            offset += octet_count;
            i += 1;
        }
    }
    proto_item_set_len(list_item_tree, offset - list_start_offset);

    list_start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_s7commp_valuelist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
    offset = s7commp_decode_value(tvb, pinfo, list_item_tree, offset, &struct_level, 0);
    proto_item_set_len(list_item_tree, offset - list_start_offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Response SetVariable
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_setvariable(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    return s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
}
/*******************************************************************************************************
 *
 * Request GetVariable
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_getvariable(tvbuff_t *tvb,
                                   packet_info *pinfo,
                                   proto_tree *tree,
                                   guint32 offset)
{
    guint32 relid;
    guint32 id_number;
    guint8 octet_count;
    guint32 item_count;
    guint32 i;
    proto_item *list_item = NULL;
    proto_tree *list_item_tree = NULL;
    guint32 list_start_offset;

    relid = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_object_relid, tvb, offset, 4, relid);
    s7commp_pinfo_append_idname(pinfo, relid, NULL);
    offset += 4;
    /* Ob es wirklich moeglich ist hier auch mehrere Variablen zu lesen ist
     * nicht bekannt, denn dazu gibt es eigentlich eine eigene Funktion.
     */
    proto_tree_add_ret_varuint32(tree, hf_s7commp_getvar_itemcount, tvb, offset, &octet_count, &item_count);
    offset += octet_count;
    list_start_offset = offset;
    list_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
    list_item_tree = proto_item_add_subtree(list_item, ett_s7commp_valuelist);
    for (i = 1; i <= item_count; i++) {
        proto_tree_add_ret_varuint32(list_item_tree, hf_s7commp_data_id_number, tvb, offset, &octet_count, &id_number);
        s7commp_pinfo_append_idname(pinfo, id_number, NULL);
        offset += octet_count;
    }
    proto_item_set_len(list_item_tree, offset - list_start_offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Response GetVariable
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_getvariable(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint32 start_offset;
    int struct_level = 0;
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
    start_offset = offset;
    offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, 0);
    proto_item_set_len(data_item_tree, offset - start_offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Request GetVarSubStreamed
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_getvarsubstr(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    guint32 id_number;
    guint32 start_offset;
    int struct_level = 0;

    do {
        id_number = tvb_get_ntohl(tvb, offset);
        if (id_number == 0) {
            struct_level--;
            proto_tree_add_text(tree, tvb, offset, 1, "Terminating Struct (Lvl:%d <- Lvl:%d)", struct_level, struct_level+1);
            offset += 4;
        } else {
            start_offset = offset;
            data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
            proto_tree_add_uint(data_item_tree, hf_s7commp_data_id_number, tvb, offset, 4, id_number);
            proto_item_append_text(data_item_tree, " [%u]:", id_number);
            offset += 4;
            offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, id_number);
            proto_item_set_len(data_item_tree, offset - start_offset);
        }
    } while (struct_level > 0);

    return offset;
}
/*******************************************************************************************************
 *
 * Response GetVarSubStreamed
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_getvarsubstr(tvbuff_t *tvb,
                                     packet_info *pinfo,
                                     proto_tree *tree,
                                     guint32 offset)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    int struct_level = 0;
    guint32 start_offset;
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    proto_tree_add_text(tree, tvb, offset, 1, "Response unknown 1: 0x%02x", tvb_get_guint8(tvb, offset));
    offset += 1;
    data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
    start_offset = offset;
    /* This function should be possible to handle a Null-Value */
    offset = s7commp_decode_value(tvb, pinfo, data_item_tree, offset, &struct_level, 0);
    /* when a struct was entered, then id, flag, type are following until terminating null */
    if (struct_level > 0) {
        offset = s7commp_decode_id_value_list(tvb, pinfo, data_item_tree, offset, TRUE);
    }
    proto_item_set_len(data_item_tree, offset - start_offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Request SetVarSubStreamed
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_setvarsubstr(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    /* Gleicher Aufbau wie Request GetVarSubstreamed */
    offset = s7commp_decode_request_getvarsubstr(tvb, pinfo, tree, offset);

    return offset;
}
/*******************************************************************************************************
 *
 * Response SetVarSubStreamed
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_setvarsubstr(tvbuff_t *tvb,
                                     packet_info *pinfo,
                                     proto_tree *tree,
                                     guint32 offset)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);

    return offset;
}
/*******************************************************************************************************
 *
 * Request SetVarSubStreamed, Stream data
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_setvarsubstr_stream(tvbuff_t *tvb,
                                           packet_info *pinfo,
                                           proto_tree *tree,
                                           gint *dlength,
                                           guint32 offset)
{
    guint32 offset_save;
    int struct_level = 0;
    proto_item *streamdata_item = NULL;
    proto_tree *streamdata_tree = NULL;

    streamdata_item = proto_tree_add_item(tree, hf_s7commp_streamdata, tvb, offset, -1, FALSE );
    streamdata_tree = proto_item_add_subtree(streamdata_item, ett_s7commp_streamdata);

    offset_save = offset;
    proto_tree_add_text(streamdata_tree, tvb, offset, 2, "Request SetVarSubStreamed unknown 2 Bytes: 0x%04x", tvb_get_ntohs(tvb, offset));
    offset += 2;
    offset = s7commp_decode_value(tvb, pinfo, streamdata_tree, offset, &struct_level, 0);
    *dlength -= (offset - offset_save);
    proto_item_set_len(streamdata_tree, offset - offset_save);

    return offset;
}
/*******************************************************************************************************
 *
 * Request SetVarSubStreamed, Stream data (fragment)
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_setvarsubstr_stream_frag(tvbuff_t *tvb,
                                                packet_info *pinfo,
                                                proto_tree *tree,
                                                guint8 protocolversion,
                                                gint *dlength,
                                                guint32 offset,
                                                gboolean has_trailer)
{
    guint32 offset_save;
    proto_item *streamdata_item = NULL;
    proto_tree *streamdata_tree = NULL;
    guint8 octet_count = 0;
    guint32 streamlen;

    streamdata_item = proto_tree_add_item(tree, hf_s7commp_streamdata, tvb, offset, -1, FALSE );
    streamdata_tree = proto_item_add_subtree(streamdata_item, ett_s7commp_streamdata);

    offset_save = offset;

    proto_tree_add_ret_varuint32(streamdata_tree, hf_s7commp_streamdata_frag_data_len, tvb, offset, &octet_count, &streamlen);
    offset += octet_count;

    if (streamlen > 0) {
        proto_tree_add_item(streamdata_tree, hf_s7commp_streamdata_frag_data, tvb, offset, streamlen, FALSE);
        offset += streamlen;
    }
    *dlength -= (offset - offset_save);
    proto_item_set_len(streamdata_tree, offset - offset_save);

    if (has_trailer) {
        offset = s7commp_decode_integrity_wid(tvb, pinfo, tree, TRUE, protocolversion, dlength, offset);
        if (*dlength > 0) {
            proto_tree_add_item(tree, hf_s7commp_data_data, tvb, offset, *dlength, ENC_NA);
            offset += *dlength;
        }
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Request GetLink
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_getlink(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *tree,
                               guint32 offset)
{
    guint8 octet_count = 0;
    guint32 item_number = 0;

    /* Ein Datensatz wurde bisher nur mit 12 Bytes Laenge gesichtet. Minus 4 Null-Bytes am Ende bleiben 8 Bytes
     * - 4 Bytes fix
     * - 1 VLQ
     * - 2 Nullbytes?
     */
    proto_tree_add_item(tree, hf_s7commp_getlink_requnknown1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_ret_varuint32(tree, hf_s7commp_data_id_number, tvb, offset, &octet_count, &item_number);
    s7commp_pinfo_append_idname(pinfo, item_number, NULL);
    offset += octet_count;

    proto_tree_add_item(tree, hf_s7commp_getlink_requnknown2, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}
/*******************************************************************************************************
 *
 * Response GetLink
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_getlink(tvbuff_t *tvb,
                                packet_info *pinfo,
                                proto_tree *tree,
                                guint32 offset)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;
    guint8 number_of_items;
    guint32 linkid;
    int i;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);

    number_of_items = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_getlink_linkidcount, tvb, offset, 1, number_of_items);
    offset += 1;

    for (i = 1; i <= number_of_items; i++) {
        /* Es scheint eine Link-Id zu sein, die im folgenden verwendet werden kann (z.B. Vartab als Start-Id fuer getmultivar */
        linkid = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint_format(tree, hf_s7commp_getlink_linkid, tvb, offset, 4, linkid,
            "Link-Id [%d]: 0x%08x", i, linkid);
        offset += 4;
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Request BeginSequence
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_beginsequence(tvbuff_t *tvb,
                                     packet_info *pinfo,
                                     proto_tree *tree,
                                     gint16 dlength _U_,
                                     guint32 offset,
                                     guint8 protocolversion)
{
    guint8 type;
    guint16 valtype;
    guint32 id;

    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_beginseq_transactiontype, tvb, offset, 1, type);
    offset += 1;
    if (protocolversion != S7COMMP_PROTOCOLVERSION_1) {
        valtype = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_s7commp_beginseq_valtype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* Ob ein Objekt oder anderer weiterer Wert folgt, scheint abhaengig vom 2./3. Byte zu sein.
         * Wenn 1 dann Objekt, wenn 18 dann ID. Andere Werte als 1 und 18 bisher noch nicht gesichtet.
         */
        if (valtype == 1) {
            /* Die 1200 mit V2 laesst hier gelegentlich 1 Byte aus. Die Antwort zeigt aber keine
             * Fehlermeldung, d.h. dies scheint toleriert zu werden.
             */
            if (tvb_get_guint8(tvb, offset + 1) == S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT) {
                proto_tree_add_item(tree, hf_s7commp_beginseq_requnknown3, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            } else {
                proto_tree_add_item(tree, hf_s7commp_beginseq_requnknown3, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            offset = s7commp_decode_object(tvb, pinfo, tree, offset, TRUE);
        } else {
            id = tvb_get_ntohl(tvb, offset);
            s7commp_pinfo_append_idname(pinfo, id, " Id=");
            proto_tree_add_item(tree, hf_s7commp_beginseq_requestid, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
        }
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Response BeginSequence
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_beginsequence(tvbuff_t *tvb,
                                      packet_info *pinfo,
                                      proto_tree *tree,
                                      guint32 offset,
                                      guint8 protocolversion)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    if (protocolversion != S7COMMP_PROTOCOLVERSION_1) {
        proto_tree_add_item(tree, hf_s7commp_beginseq_valtype, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(tree, hf_s7commp_beginseq_requestid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Request EndSequence
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_endsequence(tvbuff_t *tvb,
                                   proto_tree *tree,
                                   guint32 offset)
{
    proto_tree_add_item(tree, hf_s7commp_endseq_requnknown1, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}
/*******************************************************************************************************
 *
 * Response EndSequence
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_endsequence(tvbuff_t *tvb,
                                    packet_info *pinfo,
                                    proto_tree *tree,
                                    guint32 offset)
{
    guint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    return offset;
}
/*******************************************************************************************************
 *
 * Request Invoke
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_invoke(tvbuff_t *tvb,
                              packet_info *pinfo,
                              proto_tree *tree,
                              guint32 offset)
{
    proto_tree_add_item(tree, hf_s7commp_invoke_subsessionid, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_s7commp_invoke_requnknown1, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    offset = s7commp_decode_itemnumber_value_list_in_new_tree(tvb, pinfo, tree, offset, TRUE);
    proto_tree_add_item(tree, hf_s7commp_invoke_requnknown2, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}
/*******************************************************************************************************
 *
 * Response Invoke
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_invoke(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *tree,
                               guint32 offset)
{
    guint16 errorcode;
    gboolean errorextension;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);
    /* Ein Panel TPxy mit V14 schiebt hier bei der Antwort noch ein Null-Byte ein.
     * Solange es anschliessend keine leere ValueList gibt, funktioniert das auch. */
    if (tvb_get_guint8(tvb, offset) == 0) {
        proto_tree_add_item(tree, hf_s7commp_invoke_resunknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }
    offset = s7commp_decode_itemnumber_value_list_in_new_tree(tvb, pinfo, tree, offset, TRUE);
    proto_tree_add_item(tree, hf_s7commp_invoke_resunknown1, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    return offset;
}
/*******************************************************************************************************
 *
 * Exploring the data structure of a plc, request
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_request_explore(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *tree,
                               guint32 offset)
{
    int number_of_objects = 0;
    int number_of_ids = 0;
    int i;
    guint32 start_offset;
    guint32 id_number = 0;
    guint32 uint32value;
    guint8 octet_count = 0;
    guint8 datatype;
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;

    id_number = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_s7commp_data_id_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    s7commp_proto_item_append_idname(tree, id_number, ": Area: ");
    s7commp_pinfo_append_idname(pinfo, id_number, " Area=");
    offset += 4;

    /* 4 oder 5 weitere Bytes unbekannter Funktion
     * wenn die ersten beiden Bytes zu Begin Null sind, dann werden Objekte gelesen.
     */
    proto_tree_add_ret_varuint32(tree, hf_s7commp_explore_req_id, tvb, offset, &octet_count, &uint32value);
    if (uint32value > 0) {
        s7commp_proto_item_append_idname(tree, uint32value, " / ");
        s7commp_pinfo_append_idname(pinfo, uint32value, " / ");
    }
    offset += octet_count;
    proto_tree_add_item(tree, hf_s7commp_explore_req_childsrec, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7commp_explore_requnknown3, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_s7commp_explore_req_parents, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    do {
        number_of_objects = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_s7commp_explore_objectcount, tvb, offset, 1, number_of_objects);
        offset += 1;
        number_of_ids = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(tree, hf_s7commp_explore_addresscount, tvb, offset, 1, number_of_ids);
        offset += 1;

        if (number_of_objects > 0) {
            start_offset = offset;
            data_item = proto_tree_add_item(tree, hf_s7commp_data_item_value, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data_item);
            proto_item_append_text(data_item_tree, " (Objects with (type, value))");
            datatype = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(data_item_tree, hf_s7commp_itemval_datatype, tvb, offset, 1, datatype);
            offset += 1;
            if (datatype == S7COMMP_ITEM_DATATYPE_STRUCT) {
                proto_tree_add_item(data_item_tree, hf_s7commp_explore_structvalue, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                offset = s7commp_decode_id_value_list(tvb, pinfo, data_item_tree, offset, TRUE);
            }
            proto_item_set_len(data_item_tree, offset - start_offset);
        }

        if (number_of_ids > 0) {
            start_offset = offset;
            data_item = proto_tree_add_item(tree, hf_s7commp_addresslist, tvb, offset, -1, FALSE);
            data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_addresslist);
            proto_item_append_text(data_item_tree, " (ID Numbers)");
            for (i = 0; i < number_of_ids; i++) {
                proto_tree_add_varuint32(data_item_tree, hf_s7commp_data_id_number, tvb, offset, &octet_count);
                offset += octet_count;
            }
            proto_item_set_len(data_item_tree, offset - start_offset);
        }
    } while (number_of_objects > 0);
    return offset;
}
/*******************************************************************************************************
 *
 * Exploring the data structure of a plc, response
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_explore(tvbuff_t *tvb,
                                packet_info *pinfo,
                                proto_tree *tree,
                                guint32 offset,
                                guint8 protocolversion)
{
    guint32 id_number;
    gint16 errorcode = 0;
    gboolean errorextension = FALSE;
    guint8 octet_count = 0;
    guint8 nextb;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);

    id_number = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(tree, hf_s7commp_data_id_number, tvb, offset, 4, id_number);
    s7commp_pinfo_append_idname(pinfo, id_number, NULL);
    offset += 4;

    /* Der folgende Wert berechnet sich so wie es aussieht aus (SequenceNumber + IntegrityId) des
     * zugehoerigen Requests. Darum ist das Feld bei der alten 1200 ohne Integritaetsteil auch nicht
     * vorhanden. Ist in der Response keine Integritaets-ID, dann war es das auch nicht beim Request.
     * Was dadurch geprueft werden kann/soll ist unklar.
     * Leider gibt es bei der alten 1200 bei einem einzelnen Paket keine Moeglichkeit, BEVOR das ganze Paket
     * verarbeitet wurde, festzustellen, ob es diese Integritaets-Id gibt oder nicht. Protokollversion
     * V3 besitzt so wie es aussieht IMMER eine, V1 NIE, bei V2 nur bei der 1500.
     * Die hier realisierte Pruefung funktioniert nur, falls nicht zufaellig der Wert von resseqinteg mit 0xa1 beginnt!
     */
    nextb = tvb_get_guint8(tvb, offset);
    if ( (protocolversion == S7COMMP_PROTOCOLVERSION_3) ||
        ((protocolversion == S7COMMP_PROTOCOLVERSION_2) &&
         (nextb != S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT) && (nextb != 0)) ) {
        proto_tree_add_varuint32(tree, hf_s7commp_explore_resseqinteg, tvb, offset, &octet_count);
        offset += octet_count;
    }
    /* Dann nur die Liste durchgehen, wenn auch ein Objekt folgt. Sonst wuerde ein Null-Byte
     * zur Terminierung der Liste eingefuegt werden.
     */
    if (tvb_get_guint8(tvb, offset) == S7COMMP_ITEMVAL_ELEMENTID_STARTOBJECT) {
        offset = s7commp_decode_object(tvb, pinfo, tree, offset, FALSE);
    }
    return offset;
}
/*******************************************************************************************************
 *
 * General error message, response
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_response_error(tvbuff_t *tvb,
                              packet_info *pinfo,
                              proto_tree *tree,
                              guint32 offset)
{
    gint16 errorcode = 0;
    gboolean errorextension = FALSE;

    offset = s7commp_decode_returnvalue(tvb, pinfo, tree, offset, &errorcode, &errorextension);

    // this opcode has no data after the error code

    return offset;
}
/*******************************************************************************************************
 *
 * Decode the object qualifier
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_objectqualifier(tvbuff_t *tvb,
                               packet_info *pinfo,
                               proto_tree *tree,
                               gint16 dlength,
                               guint32 offset)
{
    guint32 offset_save;
    guint32 offsetmax;
    guint16 id = 0;
    proto_item *objectqualifier_item = NULL;
    proto_tree *objectqualifier_tree = NULL;

    offset_save = offset;
    offsetmax = offset + dlength-2;

    while (offset < offsetmax) {
        id = tvb_get_ntohs(tvb, offset);
        if (id == 0x4e8) {
            /* alles dazwischen mit Dummy-Bytes auffuellen */
            if ((offset+2 - offset_save) > 0) {
                proto_tree_add_item(tree, hf_s7commp_data_data, tvb, offset_save, offset - offset_save, ENC_NA);
            }
            dlength = dlength - (offset - offset_save);
            offset_save = offset;
            objectqualifier_item = proto_tree_add_item(tree, hf_s7commp_objectqualifier, tvb, offset, -1, FALSE );
            objectqualifier_tree = proto_item_add_subtree(objectqualifier_item, ett_s7commp_objectqualifier);
            proto_tree_add_uint(objectqualifier_tree, hf_s7commp_data_id_number, tvb, offset, 2, id);
            offset += 2;
            offset = s7commp_decode_id_value_list_in_new_tree(tvb, pinfo, objectqualifier_tree, offset, TRUE);
            proto_item_set_len(objectqualifier_tree, offset - offset_save);
            break;
        }
        offset += 1;
    }
    if (id != 0x4e8) {
        offset = offset_save; /* Offset zuruecksetzen wenn nicht gefunden */
    }
    return offset;
}
/*******************************************************************************************************
 *
 * Extended Keep Alive telegrams
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_extkeepalive(tvbuff_t *tvb,
                            packet_info *pinfo,
                            proto_tree *tree,
                            gint dlength,
                            guint32 offset)
{
    proto_item *data_item = NULL;
    proto_tree *data_item_tree = NULL;
    gint str_len;
    const guint8 *str_name;
    guint32 confirmed_bytes;

    /* Evtl. ist das hier eine Art erweiteres Keep Alive. Das habe ich erst mit V14 das erste mal gesehen.
     * Die Telegramme werden dabei von der SPS oder einem Siemens Panel verschickt.
     * Es gibt eine Version mit 16 Bytes und eine mit 22 Bytes.
     * Bei der 22 Byte Version folgt noch ein String wie "LOGOUT", dieses aber nur
     * nach einem DeleteObject.
     */
    data_item = proto_tree_add_item(tree, hf_s7commp_data, tvb, offset, dlength, FALSE);
    data_item_tree = proto_item_add_subtree(data_item, ett_s7commp_data);

    /* 4 Bytes immer Null (bisher zumindest) */
    proto_tree_add_item(data_item_tree, hf_s7commp_extkeepalive_reserved1, tvb, offset, 4, FALSE);
    offset += 4;
    /* Es folgt die Anzahl der Bytes die seit dem letzten Keep Alive oder seit Start empfangen wurden.
     * Es werden dazu die Laengenangaben aus dem Header verwendet und aufsummiert.
     */
    confirmed_bytes = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint(data_item_tree, hf_s7commp_extkeepalive_confirmedbytes, tvb, offset, 4, confirmed_bytes);
    offset += 4;
    /* Insgesamt 2*4 Bytes die bisher immer Null waren */
    proto_tree_add_item(data_item_tree, hf_s7commp_extkeepalive_reserved2, tvb, offset, 4, FALSE);
    offset += 4;
    proto_tree_add_item(data_item_tree, hf_s7commp_extkeepalive_reserved3, tvb, offset, 4, FALSE);
    offset += 4;

    col_append_fstr(pinfo->cinfo, COL_INFO, " ConfirmedBytes=%u", confirmed_bytes);

    str_len = dlength - 16;
    if (str_len > 0) {
        proto_tree_add_item_ret_string(data_item_tree, hf_s7commp_extkeepalive_message, tvb, offset, str_len, ENC_ASCII|ENC_NA, wmem_packet_scope(), &str_name);
        col_append_fstr(pinfo->cinfo, COL_INFO, " Message=%s", str_name);
        offset += str_len;
    }

    return offset;
}
/*******************************************************************************************************
 *
 * Decodes the data part
 *
 *******************************************************************************************************/
static guint32
s7commp_decode_data(tvbuff_t *tvb,
                    packet_info *pinfo,
                    proto_tree *tree,
                    gint dlength,
                    guint32 offset,
                    guint8 protocolversion)
{
    proto_item *item = NULL;
    proto_tree *item_tree = NULL;

    guint16 seqnum = 0;
    guint16 functioncode = 0;
    guint8 opcode = 0;
    guint32 offset_save = 0;
    gboolean has_integrity_id = TRUE;
    gboolean has_objectqualifier = FALSE;
    const guint8 *str_opcode;

    opcode = tvb_get_guint8(tvb, offset);
    /* 1: Opcode */
    str_opcode = try_val_to_str(opcode, opcode_names);
    /* If opcode is unknown, stop decoding and show data as undecoded */
    if (str_opcode) {
        proto_item_append_text(tree, ": %s", val_to_str(opcode, opcode_names, "Unknown Opcode: 0x%02x"));
        proto_tree_add_uint(tree, hf_s7commp_data_opcode, tvb, offset, 1, opcode);
        offset += 1;
        dlength -= 1;

        /* Bei Protokollversion 1 gibt es nur bei der 1500 und Deleteobject eine ID, und auch da nicht immer! */
        if (protocolversion == S7COMMP_PROTOCOLVERSION_1) {
            has_integrity_id = FALSE;
        }

        if (opcode == S7COMMP_OPCODE_NOTIFICATION) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", val_to_str(opcode, opcode_names, "Unknown Opcode: 0x%02x"));
            item = proto_tree_add_item(tree, hf_s7commp_notification_set, tvb, offset, -1, FALSE);
            item_tree = proto_item_add_subtree(item, ett_s7commp_notification_set);
            offset_save = offset;
            if (protocolversion == S7COMMP_PROTOCOLVERSION_1) {
                offset = s7commp_decode_notification_v1(tvb, pinfo, item_tree, offset);
            } else {
                offset = s7commp_decode_notification(tvb, pinfo, item_tree, offset);
            }
            proto_item_set_len(item_tree, offset - offset_save);
            dlength = dlength - (offset - offset_save);
        } else {
            proto_tree_add_item(tree, hf_s7commp_data_reserved1, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            dlength -= 2;

            /* 4/5: Functioncode */
            functioncode = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(tree, hf_s7commp_data_function, tvb, offset, 2, functioncode);
            offset += 2;
            dlength -= 2;

            proto_tree_add_item(tree, hf_s7commp_data_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            dlength -= 2;

            /* 8/9: Sequence number */
            seqnum = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(tree, hf_s7commp_data_seqnum, tvb, offset, 2, seqnum);
            offset += 2;
            dlength -= 2;

            /* add some infos to info column */
            col_append_fstr(pinfo->cinfo, COL_INFO, " Seq=%u [%s %s]",
                seqnum,
                val_to_str(opcode, opcode_names_short, "Unknown Opcode: 0x%02x"),
                val_to_str(functioncode, data_functioncode_names, "?"));
            proto_item_append_text(tree, " %s", val_to_str(functioncode, data_functioncode_names, "?"));

            if (opcode == S7COMMP_OPCODE_REQ) {
                proto_tree_add_item(tree, hf_s7commp_data_sessionid, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                dlength -= 4;

                proto_tree_add_item(tree, hf_s7commp_data_unknown1, tvb, offset, 1, FALSE);
                offset += 1;
                dlength -= 1;

                item = proto_tree_add_item(tree, hf_s7commp_data_req_set, tvb, offset, -1, FALSE);
                item_tree = proto_item_add_subtree(item, ett_s7commp_data_req_set);
                offset_save = offset;

                switch (functioncode) {
                    case S7COMMP_FUNCTIONCODE_GETMULTIVAR:
                        offset = s7commp_decode_request_getmultivar(tvb, item_tree, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETMULTIVAR:
                        offset = s7commp_decode_request_setmultivar(tvb, pinfo, item_tree, dlength, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETVARIABLE:
                        offset = s7commp_decode_request_setvariable(tvb, pinfo, item_tree, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_GETVARIABLE:
                        offset = s7commp_decode_request_getvariable(tvb, pinfo, item_tree, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_CREATEOBJECT:
                        offset = s7commp_decode_request_createobject(tvb, pinfo, item_tree, offset, protocolversion);
                        break;
                    case S7COMMP_FUNCTIONCODE_DELETEOBJECT:
                        offset = s7commp_decode_request_deleteobject(tvb, pinfo, item_tree, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_GETVARSUBSTR:
                        offset = s7commp_decode_request_getvarsubstr(tvb, pinfo, item_tree, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETVARSUBSTR:
                        offset = s7commp_decode_request_setvarsubstr(tvb, pinfo, item_tree, offset);
                        has_objectqualifier = TRUE;
                        break;
                    case S7COMMP_FUNCTIONCODE_EXPLORE:
                        offset = s7commp_decode_request_explore(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_GETLINK:
                        offset = s7commp_decode_request_getlink(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_BEGINSEQUENCE:
                        offset = s7commp_decode_request_beginsequence(tvb, pinfo, item_tree, dlength, offset, protocolversion);
                        break;
                    case S7COMMP_FUNCTIONCODE_ENDSEQUENCE:
                        offset = s7commp_decode_request_endsequence(tvb, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_INVOKE:
                        offset = s7commp_decode_request_invoke(tvb, pinfo, item_tree, offset);
                        break;
                }
                proto_item_set_len(item_tree, offset - offset_save);
                dlength = dlength - (offset - offset_save);
            } else if ((opcode == S7COMMP_OPCODE_RES) || (opcode == S7COMMP_OPCODE_RES2)) {
                proto_tree_add_item(tree, hf_s7commp_data_unknown1, tvb, offset, 1, FALSE);
                offset += 1;
                dlength -= 1;

                item = proto_tree_add_item(tree, hf_s7commp_data_res_set, tvb, offset, -1, FALSE);
                item_tree = proto_item_add_subtree(item, ett_s7commp_data_res_set);
                offset_save = offset;

                switch (functioncode) {
                    case S7COMMP_FUNCTIONCODE_GETMULTIVAR:
                        offset = s7commp_decode_response_getmultivar(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_SETMULTIVAR:
                        offset = s7commp_decode_response_setmultivar(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_SETVARIABLE:
                        offset = s7commp_decode_response_setvariable(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_GETVARIABLE:
                        offset = s7commp_decode_response_getvariable(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_CREATEOBJECT:
                        offset = s7commp_decode_response_createobject(tvb, pinfo, item_tree, offset, protocolversion);
                        break;
                    case S7COMMP_FUNCTIONCODE_DELETEOBJECT:
                        offset = s7commp_decode_response_deleteobject(tvb, pinfo, item_tree, offset, &has_integrity_id);
                        break;
                    case S7COMMP_FUNCTIONCODE_GETVARSUBSTR:
                        offset = s7commp_decode_response_getvarsubstr(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_SETVARSUBSTR:
                        offset = s7commp_decode_response_setvarsubstr(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_EXPLORE:
                        offset = s7commp_decode_response_explore(tvb, pinfo, item_tree, offset, protocolversion);
                        break;
                    case S7COMMP_FUNCTIONCODE_GETLINK:
                        offset = s7commp_decode_response_getlink(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_BEGINSEQUENCE:
                        offset = s7commp_decode_response_beginsequence(tvb, pinfo, item_tree, offset, protocolversion);
                        break;
                    case S7COMMP_FUNCTIONCODE_ENDSEQUENCE:
                        offset = s7commp_decode_response_endsequence(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_INVOKE:
                        offset = s7commp_decode_response_invoke(tvb, pinfo, item_tree, offset);
                        break;
                    case S7COMMP_FUNCTIONCODE_ERROR:
                         offset = s7commp_decode_response_error(tvb, pinfo, item_tree, offset);
                         break;
                }
                proto_item_set_len(item_tree, offset - offset_save);
                dlength = dlength - (offset - offset_save);
            }
        }
        /* Nach Object Qualifier trailer suchen.
         * Der Objectqualifier hat die ID 1256 = 0x04e8. Dieses Objekt hat 3 Member mit jeweils einer ID.
         * Solange wir noch nicht immer direkt auf dieser ID landen, danach suchen.
         */
        if (has_objectqualifier && dlength > 10) {
            offset_save = offset;
            offset = s7commp_decode_objectqualifier(tvb, pinfo, tree, dlength, offset);
            dlength = dlength - (offset - offset_save);
        }

        /* Additional Data */
        if (opcode == S7COMMP_OPCODE_REQ) {
            if (functioncode == S7COMMP_FUNCTIONCODE_GETVARSUBSTR) {
                proto_tree_add_text(tree, tvb, offset, 2, "Request GetVarSubStreamed unknown 2 Bytes: 0x%04x", tvb_get_ntohs(tvb, offset));
                offset += 2;
                dlength -= 2;
            } else if (functioncode == S7COMMP_FUNCTIONCODE_SETVARSUBSTR) {
                offset = s7commp_decode_request_setvarsubstr_stream(tvb, pinfo, tree, &dlength, offset);
            } else if (functioncode == S7COMMP_FUNCTIONCODE_SETVARIABLE) {
                proto_tree_add_text(tree, tvb, offset, 1, "Request SetVariable unknown Byte: 0x%02x", tvb_get_guint8(tvb, offset));
                offset += 1;
                dlength -= 1;
            }
        }
        offset = s7commp_decode_integrity_wid(tvb, pinfo, tree, has_integrity_id, protocolversion, &dlength, offset);
    } else {
        /* unknown opcode */
        expert_add_info_format(pinfo, tree, &ei_s7commp_data_opcode_unknown, "Unknown Opcode: 0x%02x", opcode);
        proto_item_append_text(tree, ": Unknown Opcode: 0x%02x", opcode);
        col_append_fstr(pinfo->cinfo, COL_INFO, " Unknown Opcode: 0x%02x", opcode);
    }
    /* Show remaining undecoded data as raw bytes */
    if (dlength > 0) {
        proto_tree_add_item(tree, hf_s7commp_data_data, tvb, offset, dlength, ENC_NA);
        offset += dlength;
    }
    return offset;
}
/*******************************************************************************************************
 *******************************************************************************************************
 *
 * S7-Protocol plus (main tree)
 *
 *******************************************************************************************************
 *******************************************************************************************************/
static gboolean
dissect_s7commp(tvbuff_t *tvb,
                packet_info *pinfo,
                proto_tree *tree,
                void *data _U_)
{
    proto_item *s7commp_item = NULL;
    proto_item *s7commp_sub_item = NULL;
    proto_tree *s7commp_tree = NULL;

    proto_tree *s7commp_header_tree = NULL;
    proto_tree *s7commp_data_tree = NULL;
    proto_tree *s7commp_trailer_tree = NULL;

    guint32 offset = 0;
    guint32 offset_save = 0;

    guint8 protocolversion = 0;
    gint dlength = 0;
    guint8 keepaliveseqnum = 0;

    gboolean has_trailer = FALSE;
    gboolean save_fragmented;
    guint32 frag_id;
    frame_state_t *packet_state = NULL;
    conversation_t *conversation;
    conv_state_t *conversation_state = NULL;
    gboolean first_fragment = FALSE;
    gboolean inner_fragment = FALSE;
    gboolean last_fragment = FALSE;
    gboolean reasm_standard = FALSE;
    tvbuff_t* next_tvb = NULL;

    guint8 reasm_opcode = 0;
    guint16 reasm_function = 0;

    guint packetlength;

    packetlength = tvb_reported_length(tvb);    /* Payload length reported from tpkt/cotp dissector. */
    /*----------------- Heuristic Checks - Begin */
    /* 1) check for minimum length */
    if (packetlength < S7COMMP_MIN_TELEGRAM_LENGTH) {
        return 0;
    }
    /* 2) first byte must be 0x72 */
    if (tvb_get_guint8(tvb, 0) != S7COMM_PLUS_PROT_ID) {
        return 0;
    }
    /*----------------- Heuristic Checks - End */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_S7COMM_PLUS);
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", "");

    protocolversion = tvb_get_guint8(tvb, 1);                       /* Get the type byte */

    /* display some infos in info-column of wireshark */
    if (pinfo->srcport == 102) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%u Ver:[%s]", UTF8_RIGHTWARDS_ARROW, pinfo->destport, val_to_str(protocolversion, protocolversion_names, "0x%02x"));
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s%u Ver:[%s]", UTF8_LEFTWARDS_ARROW, pinfo->srcport, val_to_str(protocolversion, protocolversion_names, "0x%02x"));
    }
    s7commp_item = proto_tree_add_item(tree, proto_s7commp, tvb, 0, -1, FALSE);
    s7commp_tree = proto_item_add_subtree(s7commp_item, ett_s7commp);

    /******************************************************
     * Header
     ******************************************************/
    s7commp_sub_item = proto_tree_add_item(s7commp_tree, hf_s7commp_header, tvb, offset, S7COMMP_HEADER_LEN, FALSE );
    s7commp_header_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_header);
    proto_item_append_text(s7commp_header_tree, ": Protocol version=%s", val_to_str(protocolversion, protocolversion_names, "0x%02x"));
    proto_tree_add_item(s7commp_header_tree, hf_s7commp_header_protid, tvb, offset, 1, FALSE);
    offset += 1;
    proto_tree_add_uint(s7commp_header_tree, hf_s7commp_header_protocolversion, tvb, offset, 1, protocolversion);
    offset += 1;

    /* Typ FF Pakete scheinen eine Art Keep-Alive Telegramme zu sein, welche nur 4 Bytes lang sind.
     * 1. Protocol-id, 2.PDU Typ und dann 3. eine Art Sequenz-Nummer, und das 4. Byte bisher immer 0.
     */
    if (protocolversion == S7COMMP_PROTOCOLVERSION_255) {
        keepaliveseqnum = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(s7commp_header_tree, hf_s7commp_header_keepaliveseqnum, tvb, offset, 1, keepaliveseqnum);
        col_append_fstr(pinfo->cinfo, COL_INFO, " KeepAliveSeq=%d", keepaliveseqnum);
        offset += 1;
        /* dann noch ein Byte, noch nicht klar wozu */
        proto_tree_add_text(s7commp_header_tree, tvb, offset, 1, "Reserved? : 0x%02x", tvb_get_guint8(tvb, offset));
        offset += 1;
    } else if (protocolversion == S7COMMP_PROTOCOLVERSION_254) {
        dlength = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(s7commp_header_tree, hf_s7commp_header_datlg, tvb, offset, 2, dlength);
        offset += 2;
        offset = s7commp_decode_extkeepalive(tvb, pinfo, s7commp_tree, dlength, offset);
    } else {
        /* 3/4: Data length */
        dlength = tvb_get_ntohs(tvb, offset);
        proto_tree_add_uint(s7commp_header_tree, hf_s7commp_header_datlg, tvb, offset, 2, dlength);
        offset += 2;

        /* Paket hat einen Trailer, wenn nach der angegebenen Datenlaenge noch 4 Bytes uebrig bleiben */
        has_trailer = ((signed) packetlength) > (dlength + 4);

        /* Bei einer 1500 mit Firmware Version >= V1.5 wurde der Integritaetsteil vom Ende des Datenteils an den Anfang verschoben.
         * Bei fragmentierten Paketen hatte bisher nur das letzte Fragment einen Integritaetsteil.
         * Bei FW >= V1.5 hat nun auch bei fragmentierten Paketen jedes Fragment einen Integritaetsteil. Der Integritaetsteil
         * zaehlt aber von der Laengenangabe im Kopf zum Datenteil. Bei fragmentierten Paketen muss daher bei dieser Version
         * der Integritaetsteil ausserhalb der eigentlichen Funktion zum Zerlegen des Datenteils platziert werden, da ansonsten
         * dieser beim Reassemblieren innerhalb der Datenteile liegen wuerde.
         * Leider wird damit der Zweig nicht unter dem Datenteil, sondern als eigener separater Zweig eingefuegt.
         */
        if (protocolversion == S7COMMP_PROTOCOLVERSION_3) {
            offset_save = offset;
            offset = s7commp_decode_integrity(tvb, pinfo, s7commp_tree, FALSE, offset);
            dlength -= (offset - offset_save);
        }

        /************************************************** START REASSEMBLING *************************************************************************/
        if (s7commp_reassemble) {
            /*
             * Fragmentation check:
             * Da es keine Kennzeichnungen ueber die Fragmentierung gibt, muss es in einer Zustandsmaschine abgefragt werden
             *
             * Istzustand   Transition                                      Aktion                                Neuer Zustand
             * state == 0:  Paket hat einen Trailer, keine Fragmentierung   dissect_data                          state = 0
             * state == 0:  Paket hat keinen Trailer, Start Fragmentierung  push data                             state = 1
             * state == 1:  Paket hat keinen Trailer, weiterhin Fragment    push data                             state = 1
             * state == 1:  Paket hat einen trailer, Ende Fragmente         push data, pop, dissect_data          state = 0
             *
             * Die einzige Zugehoerigkeit die es gibt, ist die TCP Portnummer. Es muessen dabei BEIDE uebereinstimmen.
             *
             * Dabei muss zusaetzlich beachtet werden, dass womoeglich ein capture inmitten einer solchen Serie gestartet wurde.
             * Das kann aber nicht zuverlaessig abgefangen werden, wenn zufaellig in den ersten Bytes des Datenteils gueltige Daten stehen.
             *
             */

            /* Zustandsdiagramm:
                             NEIN                Konversation    JA
             has_trailer ---------------------mit vorigem Frame-------- Inneres Fragment
                  ?                              vorhanden?
                  |                                  |
                  | JA                               | NEIN
                  |                                  |
               Konversation     NEIN        Neue Konversation anlegen
            mit vorigem Frame--------+               |
                vorhanden?           |          Erstes Fragment
                  |                  |
                  | JA        Nicht fragmentiert
                  |
              Letztes Fragment
            */

            if (!pinfo->fd->flags.visited) {        /* first pass */
                /* Vorabcheck: opcode und function herausfinden
                 * Da z.B. SetVarSubstreamed einen anderen Mechanismus verwendet!
                 */
                reasm_opcode = tvb_get_guint8(tvb, offset);
                reasm_function = tvb_get_ntohs(tvb, offset + 3);

                #ifdef DEBUG_REASSEMBLING
                printf("Reassembling pass 1: Frame=%3d HasTrailer=%d", pinfo->fd->num, has_trailer);
                #endif
                /* Conversation:
                 * find_conversation() ist dazu gedacht eine Konversation in beiden Richtungen zu finden.
                 * D.h. es wurde z.B. Port 2000->102 wie auch 102->2000 gefunden. Das ist an dieser Stelle jedoch
                 * nicht gewuenscht, und kann auch durch den Parameter option nicht verhindert werden.
                 * Aus dem Grund wird aus Quell- und Zielport eine eindeutige Portnummer generiert.
                 * Destport/srcport sind vom Typ guint32, erlaubte Portnummern sind jedoch nur 0..65535.
                 */
                conversation = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->src,
                                                 (const endpoint_type) pinfo->ptype, pinfo->destport + (pinfo->srcport * 65536),
                                                 0, NO_PORT_B);
                if (conversation == NULL) {
                    conversation = conversation_new(pinfo->fd->num, &pinfo->dst, &pinfo->src,
                                                    (const endpoint_type) pinfo->ptype, pinfo->destport + (pinfo->srcport * 65536),
                                                    0, NO_PORT2);
                    #ifdef DEBUG_REASSEMBLING
                    printf(" NewConv" );
                    #endif
                }
                conversation_state = (conv_state_t *)conversation_get_proto_data(conversation, proto_s7commp);
                if (conversation_state == NULL) {
                    conversation_state = wmem_new(wmem_file_scope(), conv_state_t);
                    conversation_state->state = CONV_STATE_NEW;
                    conversation_state->start_frame = 0;
                    conversation_state->start_opcode = 0;
                    conversation_state->start_function = 0;
                    conversation_add_proto_data(conversation, proto_s7commp, conversation_state);
                    #ifdef DEBUG_REASSEMBLING
                    printf(" NewConvState" );
                    #endif
                }
                #ifdef DEBUG_REASSEMBLING
                printf(" ConvState->state=%d", conversation_state->state);
                #endif

                if (has_trailer) {
                    if (conversation_state->state == CONV_STATE_NEW) {
                        #ifdef DEBUG_REASSEMBLING
                        printf(" no_fragment=1");
                        #endif
                    } else {
                        last_fragment = TRUE;
                        /* ruecksetzen */
                        #ifdef DEBUG_REASSEMBLING
                        col_append_fstr(pinfo->cinfo, COL_INFO, " (DEBUG: A state=%d)", conversation_state->state);
                        printf(" last_fragment=1, delete_proto_data");
                        #endif
                        conversation_state->state = CONV_STATE_NOFRAG;
                        conversation_delete_proto_data(conversation, proto_s7commp);
                    }
                } else {
                    if (conversation_state->state == CONV_STATE_NEW) {
                        first_fragment = TRUE;
                        conversation_state->state = CONV_STATE_FIRST;
                        conversation_state->start_frame = pinfo->fd->num;
                        conversation_state->start_opcode = reasm_opcode;
                        conversation_state->start_function = reasm_function;
                        #ifdef DEBUG_REASSEMBLING
                        printf(" first_fragment=1, set state=%d, start_frame=%d", conversation_state->state, conversation_state->start_frame);
                        #endif
                    } else {
                        inner_fragment = TRUE;
                        conversation_state->state = CONV_STATE_INNER;
                    }
                }
                #ifdef DEBUG_REASSEMBLING
                printf(" => Conv->state=%d", conversation_state->state);
                printf(" => Conv->start_frame=%3d", conversation_state->start_frame);
                printf("\n");
                #endif
            }

            save_fragmented = pinfo->fragmented;
            packet_state = (frame_state_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_s7commp, (guint32)tvb_raw_offset(tvb));
            if (!packet_state) {
                /* First S7COMMP in frame*/
                packet_state = wmem_new(wmem_file_scope(), frame_state_t);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_s7commp, (guint32)tvb_raw_offset(tvb), packet_state);
                packet_state->first_fragment = first_fragment;
                packet_state->inner_fragment = inner_fragment;
                packet_state->last_fragment = last_fragment;
                packet_state->start_frame = conversation_state->start_frame;
                packet_state->start_opcode = conversation_state->start_opcode;
                packet_state->start_function = conversation_state->start_function;
                #ifdef DEBUG_REASSEMBLING
                col_append_str(pinfo->cinfo, COL_INFO, " (DEBUG-REASM: INIT-packet_state)");
                #endif
            } else {
                first_fragment = packet_state->first_fragment;
                inner_fragment = packet_state->inner_fragment;
                last_fragment = packet_state->last_fragment;
            }

            if (packet_state->start_opcode == S7COMMP_OPCODE_REQ &&
                packet_state->start_function == S7COMMP_FUNCTIONCODE_SETVARSUBSTR) {
                reasm_standard = FALSE;
            } else {
                reasm_standard = TRUE;
            }

            if (reasm_standard && (first_fragment || inner_fragment || last_fragment)) {
                tvbuff_t* new_tvb = NULL;
                fragment_head *fd_head;
                guint32 frag_data_len;
                /* guint32 frag_number; */
                gboolean more_frags;
                #ifdef DEBUG_REASSEMBLING
                col_append_fstr(pinfo->cinfo, COL_INFO, " (DEBUG-REASM: F=%d I=%d L=%d N=%u)", first_fragment, inner_fragment, last_fragment, packet_state->start_frame);
                #endif

                frag_id       = packet_state->start_frame;
                frag_data_len = tvb_reported_length_remaining(tvb, offset);     /* Dieses ist der reine Data-Teil, da offset hinter dem Header steht */
                /* frag_number   = pinfo->fd->num; */
                more_frags    = !last_fragment;

                pinfo->fragmented = TRUE;
                /*
                 * fragment_add_seq_next() geht davon aus, dass die Pakete in der richtigen Reihenfolge reinkommen.
                 * Bei fragment_add_seq_check() muss eine Sequenznummer angegeben werden, die gibt es aber nicht im Protokoll.
                 */
                fd_head = fragment_add_seq_next(&s7commp_reassembly_table,
                                                 tvb, offset, pinfo,
                                                 frag_id,               /* ID for fragments belonging together */
                                                 NULL,                  /* void *data */
                                                 frag_data_len,         /* fragment length - to the end */
                                                 more_frags);           /* More fragments? */

                new_tvb = process_reassembled_data(tvb, offset, pinfo,
                                                   "Reassembled S7COMM-PLUS", fd_head, &s7commp_frag_items,
                                                   NULL, s7commp_tree);

                if (new_tvb) { /* take it all */
                    next_tvb = new_tvb;
                    offset = 0;
                } else { /* make a new subset */
                    next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, -1);
                    offset = 0;
                }
            } else {    /* nicht fragmentiert, oder nicht im Standardverfahren */
                next_tvb = tvb;
            }
            pinfo->fragmented = save_fragmented;
        } else {
            /* Reassembling disabled */
            next_tvb = tvb;
        }
        /******************************************************* END REASSEMBLING *******************************************************************/

        /******************************************************
         * Data
         ******************************************************/
        /* Besondere Behandlung von SetVarSubstreamed, da hier ein voellig anderer!!! Fragmentierungsmechanismus
         * verwendet wird. Im Ersten Paket gibt es als Datenteil einen Blob der auch abgeschlossen wird.
         * Danach besitzt jedes Paket nochmal einen eigenen Laengenheader im Datenteil.
         */
        if (packet_state &&
            packet_state->start_opcode == S7COMMP_OPCODE_REQ &&
            packet_state->start_function == S7COMMP_FUNCTIONCODE_SETVARSUBSTR) {

            s7commp_sub_item = proto_tree_add_item(s7commp_tree, hf_s7commp_data, next_tvb, offset, dlength, FALSE);
            s7commp_data_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_data);

            if (first_fragment) {
                /* Das erste Paket kann im Standardverfahren behandelt werden */
                offset = s7commp_decode_data(next_tvb, pinfo, s7commp_data_tree, dlength, offset, protocolversion);
            } else {
                offset = s7commp_decode_request_setvarsubstr_stream_frag(next_tvb, pinfo, s7commp_data_tree, protocolversion, &dlength, offset, has_trailer);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (Req SetVarSubStreamed fragment. Start in Frame %u)", packet_state->start_frame);
                proto_item_append_text(s7commp_data_tree, ": Request SetVarSubStreamed fragment. Start in Frame %u", packet_state->start_frame);
            }
        } else {
            if (last_fragment) {
                /* when reassembled, instead of using the dlength from header, use the length of the
                 * complete reassembled packet, minus the header length.
                 */
                dlength = tvb_reported_length_remaining(next_tvb, offset) - S7COMMP_HEADER_LEN;
            }
            /* insert data tree */
            s7commp_sub_item = proto_tree_add_item(s7commp_tree, hf_s7commp_data, next_tvb, offset, dlength, FALSE);
            /* insert sub-items in data tree */
            s7commp_data_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_data);
            /* main dissect data function */
            if (first_fragment || inner_fragment) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " (S7COMM-PLUS %s fragment)", first_fragment ? "first" : "inner" );
                proto_tree_add_item(s7commp_data_tree, hf_s7commp_data_data, next_tvb, offset, dlength, ENC_NA);
                offset += dlength;
            } else {
                if (last_fragment) {
                    col_append_str(pinfo->cinfo, COL_INFO, " (S7COMM-PLUS reassembled)");
                }
                offset = s7commp_decode_data(next_tvb, pinfo, s7commp_data_tree, dlength, offset, protocolversion);
            }
        }
        /******************************************************
         * Trailer
         ******************************************************/
        if (has_trailer) {
            s7commp_sub_item = proto_tree_add_item(s7commp_tree, hf_s7commp_trailer, next_tvb, offset, S7COMMP_TRAILER_LEN, FALSE);
            s7commp_trailer_tree = proto_item_add_subtree(s7commp_sub_item, ett_s7commp_trailer);
            proto_tree_add_item(s7commp_trailer_tree, hf_s7commp_trailer_protid, next_tvb, offset, 1, FALSE);
            offset += 1;
            proto_tree_add_item(s7commp_trailer_tree, hf_s7commp_trailer_protocolversion, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(s7commp_trailer_tree, ": Protocol version=%s", val_to_str(tvb_get_guint8(next_tvb, offset), protocolversion_names, "0x%02x"));
            offset += 1;
            proto_tree_add_item(s7commp_trailer_tree, hf_s7commp_trailer_datlg, next_tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
    }
    col_set_fence(pinfo->cinfo, COL_INFO);
    return TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
