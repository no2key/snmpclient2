package snmpclient

import (
	"bytes"
	"encoding/hex"
	"strconv"
)

var NotImplented = newError(SNMP_CODE_FAILED, nil, "NotImplented")

const (
	MAX_COMMUNITY_LEN     = 128
	SNMP_ENGINE_ID_LEN    = 32
	SNMP_CONTEXT_NAME_LEN = 32
	SNMP_AUTH_KEY_LEN     = 40
	SNMP_PRIV_KEY_LEN     = 32
	SNMP_ADM_STR32_LEN    = 32
)

type V2CPDU struct {
	version          SnmpVersion
	op               SnmpType
	requestId        int
	community        string
	variableBindings VariableBindings
	maxMsgSize       uint

	max_repetitions int
	non_repeaters   int
	error_status    int32
}

func (pdu *V2CPDU) Init(params map[string]string) SnmpError {
	pdu.maxMsgSize = *maxPDUSize
	if v, ok := params["snmp.max_msg_size"]; ok {
		if num, e := strconv.ParseUint(v, 10, 0); nil == e {
			pdu.maxMsgSize = uint(num)
		}
	}

	if v, ok := params["snmp.max_repetitions"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.max_repetitions = int(num)
		}
	}

	if v, ok := params["snmp.non_repeaters"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.non_repeaters = int(num)
		}
	}

	community, ok := params["snmp.community"]
	if ok && "" != community {
		pdu.community = community
		return nil
	}
	return Error(SNMP_CODE_FAILED, "community is empty.")
}

func (pdu *V2CPDU) GetRequestID() int {
	return pdu.requestId
}

func (pdu *V2CPDU) SetRequestID(id int) {
	pdu.requestId = id
}

func (pdu *V2CPDU) GetVersion() SnmpVersion {
	return pdu.version
}

func (pdu *V2CPDU) SetVersion(v SnmpVersion) {
	pdu.version = v
}

func (pdu *V2CPDU) SetType(t SnmpType) {
	pdu.op = t
}

func (pdu *V2CPDU) GetType() SnmpType {
	return pdu.op
}

func (pdu *V2CPDU) SetMaxMsgSize(size uint) {
	pdu.maxMsgSize = size
}

func (pdu *V2CPDU) GetMaxMsgSize() uint {
	return pdu.maxMsgSize
}

func (pdu *V2CPDU) GetErrorStatus() int32 {
	return pdu.error_status
}

func (pdu *V2CPDU) SetErrorStatus(error_status int32) {
	pdu.error_status = error_status
}

func (pdu *V2CPDU) GetVariableBindings() *VariableBindings {
	return &pdu.variableBindings
}

func (pdu *V2CPDU) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(pdu.op.String())
	buffer.WriteString(" variableBindings")
	buffer.WriteString(pdu.variableBindings.String())
	buffer.WriteString(" with community = '")
	buffer.WriteString(pdu.community)
	buffer.WriteString("' and requestId='")
	buffer.WriteString(strconv.Itoa(pdu.GetRequestID()))
	buffer.WriteString("' and version='")
	buffer.WriteString(pdu.version.String())
	buffer.WriteString("' and error_status='")
	buffer.WriteString(strconv.Itoa(int(pdu.error_status)))
	if SNMP_PDU_GETBULK == pdu.op {
		buffer.WriteString("' and max_repetitions='")
		buffer.WriteString(strconv.Itoa(pdu.max_repetitions))
		buffer.WriteString("' and non_repeaters='")
		buffer.WriteString(strconv.Itoa(pdu.non_repeaters))
	}
	buffer.WriteString("'")
	return buffer.String()
}

func (pdu *V2CPDU) encodePDU(bs []byte, is_dump bool) ([]byte, SnmpError) {
	return nil, NotImplented
}

func (pdu *V2CPDU) decodePDU(bs []byte) (bool, SnmpError) {
	return false, NotImplented
}

type V3PDU struct {
	op               SnmpType
	requestId        int
	identifier       int
	securityModel    securityModelWithCopy
	variableBindings VariableBindings
	maxMsgSize       uint
	contextName      string
	contextEngine    []byte
	engine           *snmpEngine

	max_repetitions int
	non_repeaters   int
	error_status    int32
}

func (pdu *V3PDU) Init(params map[string]string) (err SnmpError) {
	var e error

	pdu.maxMsgSize = *maxPDUSize

	if v, ok := params["snmp.max_msg_size"]; ok {
		if num, e := strconv.ParseUint(v, 10, 0); nil == e {
			pdu.maxMsgSize = uint(num)
		}
	}

	if v, ok := params["snmp.max_repetitions"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.max_repetitions = int(num)
		}
	}

	if v, ok := params["snmp.non_repeaters"]; ok {
		if num, e := strconv.ParseInt(v, 10, 0); nil == e {
			pdu.non_repeaters = int(num)
		}
	}

	if s, ok := params["snmp.context_name"]; ok {
		pdu.contextName = s
		if s, ok = params["snmp.context_engine"]; ok {
			pdu.contextEngine, e = hex.DecodeString(s)
			if nil != e {
				return newError(SNMP_CODE_FAILED, e, "'context_engine' decode failed")
			}
		}
	}

	pdu.identifier = -1
	if s, ok := params["snmp.identifier"]; ok {
		pdu.identifier, e = strconv.Atoi(s)
		if nil != e {
			return newError(SNMP_CODE_FAILED, e, "'identifier' decode failed")
		}
	}

	if s, ok := params["snmp.engine_id"]; ok {
		pdu.engine = new(snmpEngine)
		pdu.engine.engine_id, e = hex.DecodeString(s)
		if nil != e {
			return newError(SNMP_CODE_FAILED, e, "'engine_id' decode failed")
		}

		if s, ok = params["snmp.engine_boots"]; ok {
			pdu.engine.engine_boots, e = strconv.Atoi(s)
			if nil != e {
				return newError(SNMP_CODE_FAILED, e, "'engine_boots' decode failed")
			}
		}
		if s, ok = params["snmp.engine_time"]; ok {
			pdu.engine.engine_time, e = strconv.Atoi(s)
			if nil != e {
				return newError(SNMP_CODE_FAILED, e, "'engine_time' decode failed")
			}
		}
	}
	pdu.securityModel, err = NewSecurityModel(params)
	return
}

func (pdu *V3PDU) GetRequestID() int {
	return pdu.requestId
}

func (pdu *V3PDU) SetRequestID(id int) {
	pdu.requestId = id
	pdu.identifier = id
}

func (pdu *V3PDU) GetVersion() SnmpVersion {
	return SNMP_V3
}

func (pdu *V3PDU) GetType() SnmpType {
	return pdu.op
}

func (pdu *V3PDU) GetErrorStatus() int32 {
	return pdu.error_status
}

func (pdu *V3PDU) SetErrorStatus(error_status int32) {
	pdu.error_status = error_status
}

func (pdu *V3PDU) GetVariableBindings() *VariableBindings {
	return &pdu.variableBindings
}

func (pdu *V3PDU) String() string {
	var buffer bytes.Buffer
	buffer.WriteString(pdu.op.String())
	buffer.WriteString(" variableBindings")
	buffer.WriteString(pdu.variableBindings.String())
	buffer.WriteString(" with ")
	if nil == pdu.securityModel {
		buffer.WriteString("securityModel is nil")
	} else {
		buffer.WriteString(pdu.securityModel.String())
	}
	buffer.WriteString(" and contextName='")
	buffer.WriteString(pdu.contextName)
	buffer.WriteString("' and contextEngine=")

	if nil == pdu.contextEngine {
		buffer.WriteString("nil")
	} else {
		buffer.WriteString("'")
		buffer.WriteString(hex.EncodeToString(pdu.contextEngine))
		buffer.WriteString("'")
	}

	buffer.WriteString(" and ")
	if nil == pdu.securityModel {
		buffer.WriteString("securityModel is nil")
	} else {
		buffer.WriteString(pdu.securityModel.String())
	}
	buffer.WriteString(" and requestId='")
	buffer.WriteString(strconv.Itoa(pdu.GetRequestID()))
	buffer.WriteString("' and identifier='")
	buffer.WriteString(strconv.Itoa(pdu.identifier))
	buffer.WriteString("' and version='v3' and error_status='")
	buffer.WriteString(strconv.Itoa(int(pdu.error_status)))

	if SNMP_PDU_GETBULK == pdu.op {
		buffer.WriteString("' and max_repetitions='")
		buffer.WriteString(strconv.Itoa(pdu.max_repetitions))
		buffer.WriteString("' and non_repeaters='")
		buffer.WriteString(strconv.Itoa(pdu.non_repeaters))
	}
	buffer.WriteString("'")
	return buffer.String()
}

var (
	context_engine_failed  = newError(SNMP_CODE_FAILED, nil, "copy context_engine failed")
	context_name_failed    = newError(SNMP_CODE_FAILED, nil, "copy context_name failed")
	engine_id_failed       = newError(SNMP_CODE_FAILED, nil, "copy engine_id failed")
	security_model_is_nil  = newError(SNMP_CODE_FAILED, nil, "security model is nil")
	security_model_failed  = newError(SNMP_CODE_FAILED, nil, "fill security model failed")
	encode_bindings_failed = newError(SNMP_CODE_FAILED, nil, "fill encode bindings failed")
)

func (pdu *V3PDU) encodePDU(to []byte) ([]byte, SnmpError) {
	return nil, NotImplented
}

func (pdu *V3PDU) decodePDU(from []byte) (bool, SnmpError) {
	return false, NotImplented
}

///////////////////////// Encode/Decode /////////////////////////////

const (
	ASN_MAXOIDLEN     = 128
	SNMP_MAX_BINDINGS = 100
)

var is_test bool = false
var debug_salt []byte = make([]byte, 8)

func debug_test_enable() {
	is_test = true
}

func debug_test_disable() {
	is_test = false
}

func DecodePDU(send_bytes []byte, priv_type PrivType, priv_key []byte, is_dump bool) (PDU, SnmpError) {
	return nil, NotImplented
}

func EncodePDU(pdu PDU, bs []byte, is_dump bool) ([]byte, SnmpError) {
	if pdu.GetVersion() != SNMP_V3 {
		return pdu.(*V2CPDU).encodePDU(bs, is_dump)
	}
	return pdu.(*V3PDU).encodePDU(bs)
}
