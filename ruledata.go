package libaudit

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

var rulesRetrieved AuditRuleData

// AuditRuleData is used while adding/deleting/listing audit rules
type AuditRuleData struct {
	Flags      uint32 // AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND
	Action     uint32 // AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS
	FieldCount uint32
	Mask       [AUDIT_BITMASK_SIZE]uint32 // syscall(s) affected
	Fields     [AUDIT_MAX_FIELDS]uint32
	Values     [AUDIT_MAX_FIELDS]uint32
	Fieldflags [AUDIT_MAX_FIELDS]uint32
	Buflen     uint32 // total length of string fields
	Buf        []byte // string fields buffer
}

// FMap denotes a field for rules
type FMap struct {
	Name    string
	Fieldid float64
}

// Field holds the array of fields retrieved from lookup table
type Field struct {
	Fieldmap []FMap
}

// ToWireFormat converts a AuditRuleData to byte stream
// relies on unsafe conversions
func (rule *AuditRuleData) ToWireFormat() []byte {

	newbuff := make([]byte, int(unsafe.Sizeof(*rule))-int(unsafe.Sizeof(rule.Buf))+int(rule.Buflen))
	*(*uint32)(unsafe.Pointer(&newbuff[0:4][0])) = rule.Flags
	*(*uint32)(unsafe.Pointer(&newbuff[4:8][0])) = rule.Action
	*(*uint32)(unsafe.Pointer(&newbuff[8:12][0])) = rule.FieldCount
	*(*[AUDIT_BITMASK_SIZE]uint32)(unsafe.Pointer(&newbuff[12:268][0])) = rule.Mask
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&newbuff[268:524][0])) = rule.Fields
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&newbuff[524:780][0])) = rule.Values
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&newbuff[780:1036][0])) = rule.Fieldflags
	*(*uint32)(unsafe.Pointer(&newbuff[1036:1040][0])) = rule.Buflen
	copy(newbuff[1040:1040+rule.Buflen], rule.Buf[:])
	return newbuff
}

// AuditDeleteRuleData deletes a rule from audit in kernel
func AuditDeleteRuleData(s *NetlinkConnection, rule *AuditRuleData, flags uint32, action uint32) error {
	if flags == AUDIT_FILTER_ENTRY {
		return errors.Wrap(errEntryDep, "AuditDeleteRuleData failed")
	}
	rule.Flags = flags
	rule.Action = action

	newbuff := rule.ToWireFormat()
	// avoiding standard method of unwrapping the struct due to occasional failures
	// buff := new(bytes.Buffer)
	// err := binary.Write(buff, nativeEndian(), *rule)
	// if err != nil {
	// 	log.Println("binary.Write failed:", err)
	// 	return err
	// }
	// wb := newNetlinkAuditRequest(AUDIT_DEL_RULE, syscall.AF_NETLINK, int(unsafe.Sizeof(sizePurpose))+int(rule.Buflen))
	// wb.Data = append(wb.Data[:], buff.Bytes()[:]...)

	newwb := newNetlinkAuditRequest(uint16(AUDIT_DEL_RULE), syscall.AF_NETLINK, len(newbuff) /*+int(rule.Buflen)*/)
	newwb.Data = append(newwb.Data[:], newbuff[:]...)
	if err := s.Send(newwb); err != nil {
		return errors.Wrap(err, "AuditDeleteRuleData failed")
	}
	return nil
}

// DeleteAllRules deletes all previous audit rules listed in the kernel
func DeleteAllRules(s *NetlinkConnection) error {
	wb := newNetlinkAuditRequest(uint16(AUDIT_LIST_RULES), syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		return errors.Wrap(err, "DeleteAllRules failed")
	}

done:
	for {
		// Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		// msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, 0)
		if err != nil {
			return errors.Wrap(err, "DeleteAllRules failed")
		}

		for _, m := range msgs {
			address, err := syscall.Getsockname(s.fd)
			if err != nil {
				return errors.Wrap(err, "DeleteAllRules: Getsockname failed")
			}
			switch v := address.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) {
					return fmt.Errorf("DeleteAllRules: Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("DeleteAllRules: Wrong PID %d, expected %d", m.Header.Pid, v.Pid)
				}
			default:
				return errors.Wrap(syscall.EINVAL, "DeleteAllRules: socket type unexpected")
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				e := int32(nativeEndian().Uint32(m.Data[0:4]))
				if e != 0 {
					return fmt.Errorf("DeleteAllRules: error receiving rules -%d", e)
				}
			}
			if m.Header.Type == uint16(AUDIT_LIST_RULES) {
				b := m.Data[:]
				//Avoid conversion to AuditRuleData, we just need to pass the recvd rule
				//as a Buffer in a newly packed rule to delete it
				// rules := (*AuditRuleData)(unsafe.Pointer(&b[0]))

				newwb := newNetlinkAuditRequest(uint16(AUDIT_DEL_RULE), syscall.AF_NETLINK, len(b) /*+int(rule.Buflen)*/)
				newwb.Data = append(newwb.Data[:], b[:]...)
				if err := s.Send(newwb); err != nil {
					return errors.Wrap(err, "DeleteAllRules failed")
				}
			}
		}
	}
	return nil
}

var auditPermAdded bool
var auditSyscallAdded bool

// Load x86_64 syscall table and field table
func loadSysMapFieldTab(x64Map interface{}, fieldmap *Field) error {

	err := json.Unmarshal([]byte(sysMapX64), &x64Map)
	if err != nil {
		return errors.Wrap(err, "loadSysMapFieldTab failed")
	}

	err = json.Unmarshal([]byte(fields), &fieldmap)
	if err != nil {
		return errors.Wrap(err, "loadSysMapFieldTab failed")
	}

	return nil
}

func auditWord(nr int) uint32 {
	word := (uint32)((nr) / 32)
	return (uint32)(word)
}

func auditBit(nr int) uint32 {
	bit := 1 << ((uint32)(nr) - auditWord(nr)*32)
	return (uint32)(bit)
}

// AuditRuleSyscallData makes changes in the rule struct according to system call number
func AuditRuleSyscallData(rule *AuditRuleData, scall int) error {
	word := auditWord(scall)
	bit := auditBit(scall)

	if word >= AUDIT_BITMASK_SIZE-1 {
		return fmt.Errorf("AuditRuleSyscallData failed: word Size greater than AUDIT_BITMASK_SIZE")
	}
	rule.Mask[word] |= bit
	return nil
}

// AuditNameToFtype to converts string field names to integer values based on lookup table ftypeTab
func AuditNameToFtype(name string, value *int) error {

	var filemap interface{}
	err := json.Unmarshal([]byte(ftypeTab), &filemap)

	if err != nil {
		return errors.Wrap(err, "AuditNameToFtype failed")
	}

	m := filemap.(map[string]interface{})

	for k, v := range m {
		if k == name {
			*value = int(v.(float64))
			return nil
		}
	}

	return fmt.Errorf("AuditNameToFtype failed: filetype %v not found", name)
}

var (
	errMaxField = errors.New("Max Fields for AuditRuleData exceeded")
	errNoStr    = errors.New("No support for string values")
	errUnset    = errors.New("Unable to set value")
	errNoSys    = errors.New("No syscall added")
	errMaxLen   = errors.New("Max Rule length Exceeded")
)

// AuditRuleFieldPairData process the passed AuditRuleData struct for passing to kernel
// according to passed fieldnames and flags
func AuditRuleFieldPairData(rule *AuditRuleData, fieldval interface{}, opval uint32, fieldname string, fieldmap Field, flags int) error {

	if rule.FieldCount >= (AUDIT_MAX_FIELDS - 1) {
		return errors.Wrap(errMaxField, "AuditRuleFieldPairData failed")
	}

	var fieldid uint32
	for f := range fieldmap.Fieldmap {
		if fieldmap.Fieldmap[f].Name == fieldname {
			fieldid = (uint32)(fieldmap.Fieldmap[f].Fieldid)
			break
		}
	}
	if fieldid == 0 {
		return fmt.Errorf("AuditRuleFieldPairData failed: unknown field %v", fieldname)
	}

	if flags == AUDIT_FILTER_EXCLUDE && fieldid != AUDIT_MSGTYPE {
		return fmt.Errorf("AuditRuleFieldPairData failed: only msgtype field can be used with exclude filter")
	}
	rule.Fields[rule.FieldCount] = fieldid
	rule.Fieldflags[rule.FieldCount] = opval

	switch fieldid {
	case AUDIT_UID, AUDIT_EUID, AUDIT_SUID, AUDIT_FSUID, AUDIT_LOGINUID, AUDIT_OBJ_UID, AUDIT_OBJ_GID:
		if val, isInt := fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if val, isString := fieldval.(string); isString {
			if val == "unset" {
				rule.Values[rule.FieldCount] = 4294967295
			} else {
				user, err := user.Lookup(val)
				if err != nil {
					return errors.Wrap(err, "AuditRuleFieldPairData failed: unknown user")
				}
				userID, err := strconv.Atoi(user.Uid)
				if err != nil {
					return errors.Wrap(err, "AuditRuleFieldPairData failed")
				}
				rule.Values[rule.FieldCount] = (uint32)(userID)
			}
		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v", fieldval))
		}

	case AUDIT_GID, AUDIT_EGID, AUDIT_SGID, AUDIT_FSGID:
		//IF DIGITS THEN
		if val, isInt := fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fieldval.(string); isString {
			return errors.Wrap(errNoStr, "AuditRuleFieldPairData failed")
			//TODO: audit_name_to_gid(string, sint*val)
		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v", fieldval))
		}

	case AUDIT_EXIT:

		if flags != AUDIT_FILTER_EXIT {
			return fmt.Errorf("AuditRuleFieldPairData failed: %v can only be used with exit filter list", fieldname)
		}
		if val, isInt := fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fieldval.(string); isString {
			// TODO: audit_name_to_errno
			return errors.Wrap(errNoStr, "AuditRuleFieldPairData failed")
		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v", fieldval))
		}

	case AUDIT_MSGTYPE:

		if flags != AUDIT_FILTER_EXCLUDE && flags != AUDIT_FILTER_USER {
			return fmt.Errorf("AuditRuleFieldPairData: msgtype field can only be used with exclude filter list")
		}
		if val, isInt := fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fieldval.(string); isString {
			// TODO: Add reverse mappings from msgType to audit constants (msg_typetab.h)
			return errors.Wrap(errNoStr, "AuditRuleFieldPairData failed")
		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v", fieldval))
		}

	//Strings
	case AUDIT_OBJ_USER, AUDIT_OBJ_ROLE, AUDIT_OBJ_TYPE, AUDIT_OBJ_LEV_LOW, AUDIT_OBJ_LEV_HIGH, AUDIT_WATCH, AUDIT_DIR:
		/* Watch & object filtering is invalid on anything
		 * but exit */

		if flags != AUDIT_FILTER_EXIT {
			return fmt.Errorf("AuditRuleFieldPairData failed: %v can only be used with exit filter list", fieldname)
		}
		if fieldid == AUDIT_WATCH || fieldid == AUDIT_DIR {
			auditPermAdded = true
		}

		fallthrough //IMP
	case AUDIT_SUBJ_USER, AUDIT_SUBJ_ROLE, AUDIT_SUBJ_TYPE, AUDIT_SUBJ_SEN, AUDIT_SUBJ_CLR, AUDIT_FILTERKEY:
		//If And only if a syscall is added or a permisission is added then this field should be set
		//TODO - More debugging required
		if fieldid == AUDIT_FILTERKEY && !(auditSyscallAdded || auditPermAdded) {
			return errors.Wrap(errNoSys, "AuditRuleFieldPairData failed: Key field needs a watch or syscall given prior to it")
		}
		if val, isString := fieldval.(string); isString {
			valbyte := []byte(val)
			vlen := len(valbyte)
			if fieldid == AUDIT_FILTERKEY && vlen > AUDIT_MAX_KEY_LEN {
				return errors.Wrap(errMaxLen, "AuditRuleFieldPairData failed")
			} else if vlen > PATH_MAX {
				return errors.Wrap(errMaxLen, "AuditRuleFieldPairData failed")
			}
			rule.Values[rule.FieldCount] = (uint32)(vlen)
			rule.Buflen = rule.Buflen + (uint32)(vlen)
			// log.Println(unsafe.Sizeof(*rule), vlen)
			//Now append the key value with the rule buffer space
			//May need to reallocate memory to rule.Buf i.e. the 0 size byte array, append will take care of that
			rule.Buf = append(rule.Buf, valbyte[:]...)
			// log.Println(int(unsafe.Sizeof(*rule)), *rule)
		} else {
			return fmt.Errorf("AuditRuleFieldPairData failed: string expected, found %v", fieldval)
		}

	case AUDIT_ARCH:
		if auditSyscallAdded == false {
			return errors.Wrap(errNoSys, "AuditRuleFieldPairData failed: arch should be mention before syscalls")
		}
		if !(opval == AUDIT_NOT_EQUAL || opval == AUDIT_EQUAL) {
			return fmt.Errorf("AuditRuleFieldPairData failed: arch only takes = or != operators")
		}
		// IMP NOTE: Considering X64 machines only
		if _, isInt := fieldval.(float64); isInt {
			rule.Values[rule.FieldCount] = AUDIT_ARCH_X86_64
		} else if _, isString := fieldval.(string); isString {
			return errors.Wrap(errNoStr, "AuditRuleFieldPairData failed")
		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v", fieldval))
		}

	case AUDIT_PERM:
		//Decide on various error types
		if flags != AUDIT_FILTER_EXIT {
			return fmt.Errorf("AuditRuleFieldPairData failed: %v can only be used with exit filter list", fieldname)
		} else if opval != AUDIT_EQUAL {
			return fmt.Errorf("AuditRuleFieldPairData failed: %v only takes = or != operators", fieldname)
		} else {
			if val, isString := fieldval.(string); isString {

				var i, vallen int
				vallen = len(val)
				var permval uint32
				if vallen > 4 {
					return errors.Wrap(errMaxLen, "AuditRuleFieldPairData failed")
				}
				lowerval := strings.ToLower(val)
				for i = 0; i < vallen; i++ {
					switch lowerval[i] {
					case 'r':
						permval |= AUDIT_PERM_READ
					case 'w':
						permval |= AUDIT_PERM_WRITE
					case 'x':
						permval |= AUDIT_PERM_EXEC
					case 'a':
						permval |= AUDIT_PERM_ATTR
					default:
						return fmt.Errorf("AuditRuleFieldPairData failed: permission can only contain  'rwxa'")
					}
				}
				rule.Values[rule.FieldCount] = permval
				auditPermAdded = true
			}
		}
	case AUDIT_FILETYPE:
		if val, isString := fieldval.(string); isString {
			if !(flags == AUDIT_FILTER_EXIT) && flags == AUDIT_FILTER_ENTRY {
				return fmt.Errorf("AuditRuleFieldPairData failed: %v can only be used with exit and entry filter list", fieldname)
			}
			var fileval int
			err := AuditNameToFtype(val, &fileval)
			if err != nil {
				return errors.Wrap(err, "AuditRuleFieldPairData failed")
			}
			rule.Values[rule.FieldCount] = uint32(fileval)
			if (int)(rule.Values[rule.FieldCount]) < 0 {
				return fmt.Errorf("AuditRuleFieldPairData failed: unknown file type %v", fieldname)
			}
		} else {
			return fmt.Errorf("AuditRuleFieldPairData failed: expected string but filetype found %v", fieldval)
		}

	case AUDIT_ARG0, AUDIT_ARG1, AUDIT_ARG2, AUDIT_ARG3:
		if val, isInt := fieldval.(float64); isInt {
			// if val < 0 {
			// 	// For trimming "-" and evaluating th condition vlen >=2 (which is not needed)
			// 	valString := strconv.FormatInt((int64)(val), 10)
			// 	fieldvalUID := strings.Replace(valString, "-", "", -1)
			// 	a, err := strconv.Atoi(fieldvalUID)
			// 	if err != nil {
			// 		return errors.Wrap(err, "AuditRuleFieldPairData: fieldvalUID conversion failed")
			// 	}
			// 	rule.Values[rule.FieldCount] = (uint32)(a)

			// } else {
			// 	rule.Values[rule.FieldCount] = (uint32)(val)
			// }
			rule.Values[rule.FieldCount] = (uint32)(val)
		} else if _, isString := fieldval.(string); isString {
			return errors.Wrap(errNoStr, fmt.Sprintf("AuditRuleFieldPairData failed: %v should be a number", fieldname))
		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v", fieldval))
		}
	case AUDIT_DEVMAJOR, AUDIT_INODE, AUDIT_SUCCESS:
		if flags != AUDIT_FILTER_EXIT {
			return fmt.Errorf("AuditRuleFieldPairData failed: %v can only be used with exit filter list", fieldname)
		}
		fallthrough
	default:
		if fieldid == AUDIT_INODE {
			if !(opval == AUDIT_NOT_EQUAL || opval == AUDIT_EQUAL) {
				return fmt.Errorf("AuditRuleFieldPairData failed: %v only takes = or != operators", fieldname)
			}
		}

		if fieldid == AUDIT_PPID && !(flags == AUDIT_FILTER_EXIT || flags == AUDIT_FILTER_ENTRY) {
			return fmt.Errorf("AuditRuleFieldPairData failed: %v can only be used with exit and entry filter list", fieldname)
		}

		if val, isInt := fieldval.(float64); isInt {

			if fieldid == AUDIT_INODE {
				// c version uses strtoul (in case of INODE)
				rule.Values[rule.FieldCount] = (uint32)(val)
			} else {
				// c version uses strtol
				rule.Values[rule.FieldCount] = (uint32)(val)
			}

		} else {
			return errors.Wrap(errUnset, fmt.Sprintf("AuditRuleFieldPairData failed to set: %v should be a number", fieldval))
		}
	}
	rule.FieldCount++
	return nil
}

var errEntryDep = errors.New("Use of entry filter is deprecated")

func setActionAndFilters(actions []interface{}) (int, int) {
	action := -1
	filter := AUDIT_FILTER_UNSET

	for _, value := range actions {
		if value == "never" {
			action = AUDIT_NEVER
		} else if value == "possible" {
			action = AUDIT_POSSIBLE
		} else if value == "always" {
			action = AUDIT_ALWAYS
		} else if value == "task" {
			filter = AUDIT_FILTER_TASK
		} else if value == "entry" {
			// log.Println("Support for Entry Filter is Deprecated. Switching back to Exit filter")
			filter = AUDIT_FILTER_EXIT
		} else if value == "exit" {
			filter = AUDIT_FILTER_EXIT
		} else if value == "user" {
			filter = AUDIT_FILTER_USER
		} else if value == "exclude" {
			filter = AUDIT_FILTER_EXCLUDE
		}
	}
	return action, filter
}

//AuditAddRuleData sends the prepared AuditRuleData struct via the netlink connection to kernel
func AuditAddRuleData(s *NetlinkConnection, rule *AuditRuleData, flags int, action int) error {

	if flags == AUDIT_FILTER_ENTRY {
		return errors.Wrap(errEntryDep, "AuditAddRuleData failed")
	}

	rule.Flags = uint32(flags)
	rule.Action = uint32(action)
	// Using unsafe for conversion
	newbuff := rule.ToWireFormat()
	// Following method avoided as it require the 0 byte array to be fixed size array
	// buff := new(bytes.Buffer)
	// err := binary.Write(buff, nativeEndian(), *rule)
	// if err != nil {
	// 	log.Println("binary.Write failed:", err)
	// 	return err
	// }
	// wb := newNetlinkAuditRequest(AUDIT_ADD_RULE, syscall.AF_NETLINK, int(buff.Len())+int(rule.Buflen))
	// wb.Data = append(wb.Data[:], buff.Bytes()[:]...)

	newwb := newNetlinkAuditRequest(uint16(AUDIT_ADD_RULE), syscall.AF_NETLINK, len(newbuff))
	newwb.Data = append(newwb.Data[:], newbuff[:]...)
	var err error
	if err = s.Send(newwb); err != nil {
		return errors.Wrap(err, "AuditAddRuleData failed")
	}
	return nil
}

//SetRules reads configuration file for audit rules and sets them in kernel
func SetRules(s *NetlinkConnection, content []byte) error {

	var (
		rules    interface{}
		x64Map   interface{}
		fieldmap Field
		err      error
	)
	err = json.Unmarshal(content, &rules)
	if err != nil {
		return errors.Wrap(err, "SetRules failed")
	}

	m := rules.(map[string]interface{})

	// Load x86_64 map and fieldtab.json
	err = loadSysMapFieldTab(&x64Map, &fieldmap)
	if err != nil {
		return errors.Wrap(err, "SetRules failed")
	}
	syscallMap := x64Map.(map[string]interface{})

	for k, v := range m {
		auditSyscallAdded = false
		switch k {
		case "file_rules":
			vi := v.([]interface{})
			for ruleNo := range vi {
				rule := vi[ruleNo].(map[string]interface{})
				path := rule["path"]
				if path == "" {
					return errors.Wrap(err, "SetRules failed: watch option needs a path")
				}
				perms := rule["permission"]
				//log.Println("Setting watch on", path)
				var ruleData AuditRuleData
				ruleData.Buf = make([]byte, 0)
				add := AUDIT_FILTER_EXIT
				action := AUDIT_ALWAYS
				auditSyscallAdded = true

				err = AuditSetupAndAddWatchDir(&ruleData, path.(string))
				if err != nil {
					return errors.Wrap(err, "SetRules failed")
				}
				if perms != nil {
					err = AuditSetupAndUpdatePerms(&ruleData, perms.(string))
					if err != nil {
						return errors.Wrap(err, "SetRules failed")
					}
				}

				key := rule["key"]
				if key != nil {
					err = AuditRuleFieldPairData(&ruleData, key, AUDIT_EQUAL, "key", fieldmap, AUDIT_FILTER_UNSET) // &AUDIT_BIT_MASK
					if err != nil {
						return errors.Wrap(err, "SetRules failed")
					}
				}

				err = AuditAddRuleData(s, &ruleData, add, action)
				if err != nil {
					return errors.Wrap(err, "SetRules failed")
				}

			}

		case "syscall_rules":
			vi := v.([]interface{})
			for sruleNo := range vi {
				srule := vi[sruleNo].(map[string]interface{})
				var (
					ruleData         AuditRuleData
					syscallsNotFound string
				)
				ruleData.Buf = make([]byte, 0)
				// Process syscalls
				// TODO: support syscall no
				syscalls, ok := srule["syscalls"].([]interface{})
				if ok {
					for _, syscall := range syscalls {
						syscall, ok := syscall.(string)
						if !ok {
							return fmt.Errorf("SetRules failed: unexpected syscall name %v", syscall)
						}
						if ival, ok := syscallMap[syscall]; ok {
							//log.Println("setting syscall rule", syscall)
							err = AuditRuleSyscallData(&ruleData, int(ival.(float64)))
							if err == nil {
								auditSyscallAdded = true
							} else {
								return errors.Wrap(err, "SetRules failed")
							}
						}
						syscallsNotFound += " " + syscall
					}
				}
				if auditSyscallAdded != true {
					return fmt.Errorf("SetRules failed: one or more syscalls not found: %v", syscallsNotFound)
				}

				// Process action
				actions := srule["actions"].([]interface{})

				//Apply action on syscall by separating the filters (exit) from actions (always)
				action, filter := setActionAndFilters(actions)

				// Process fields
				if srule["fields"] == nil {
					//TODO: add proper ways to display warnings
					log.Println("WARNING - 32/64 bit syscall mismatch, you should specify an arch")
				} else {
					for _, field := range srule["fields"].([]interface{}) {
						fieldval := field.(map[string]interface{})["value"]
						op := field.(map[string]interface{})["op"]
						fieldname := field.(map[string]interface{})["name"]
						//log.Println(fieldval, op, fieldname)
						var opval uint32
						if op == "nt_eq" {
							opval = AUDIT_NOT_EQUAL
						} else if op == "gt_or_eq" {
							opval = AUDIT_GREATER_THAN_OR_EQUAL
						} else if op == "lt_or_eq" {
							opval = AUDIT_LESS_THAN_OR_EQUAL
						} else if op == "and_eq" {
							opval = AUDIT_BIT_TEST
						} else if op == "eq" {
							opval = AUDIT_EQUAL
						} else if op == "gt" {
							opval = AUDIT_GREATER_THAN
						} else if op == "lt" {
							opval = AUDIT_LESS_THAN
						} else if op == "and" {
							opval = AUDIT_BIT_MASK
						}

						//Take appropriate action according to filters provided
						err = AuditRuleFieldPairData(&ruleData, fieldval, opval, fieldname.(string), fieldmap, filter) // &AUDIT_BIT_MASK
						if err != nil {
							return errors.Wrap(err, "SetRules failed")
						}
					}
				}

				key, ok := srule["key"]
				if ok {
					err = AuditRuleFieldPairData(&ruleData, key, AUDIT_EQUAL, "key", fieldmap, AUDIT_FILTER_UNSET) // &AUDIT_BIT_MASK
					if err != nil {
						return errors.Wrap(err, "SetRules failed")
					}
				}

				// foo.Fields[foo.FieldCount] = AUDIT_ARCH
				// foo.Fieldflags[foo.FieldCount] = AUDIT_EQUAL
				// foo.Values[foo.FieldCount] = AUDIT_ARCH_X86_64
				// foo.FieldCount++
				// AuditAddRuleData(s, &foo, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)

				if filter != AUDIT_FILTER_UNSET {
					err = AuditAddRuleData(s, &ruleData, filter, action)
					if err != nil {
						return errors.Wrap(err, "SetRules failed")
					}
				} else {
					return fmt.Errorf("SetRules failed: filters not set or invalid: %v , %v ", actions[0].(string), actions[1].(string))
				}
			}
		}
	}
	return nil
}

var errPathTooBig = errors.New("The path passed for the watch is too big")
var errPathStart = errors.New("The path must start with '/'")
var errBaseTooBig = errors.New("The base name of the path is too big")

func checkPath(pathName string) error {
	if len(pathName) >= PATH_MAX {
		return errors.Wrap(errPathTooBig, "checkPath failed")
	}
	if pathName[0] != '/' {
		return errors.Wrap(errPathStart, "checkPath failed")
	}

	base := path.Base(pathName)

	if len(base) > syscall.NAME_MAX {
		return errors.Wrap(errBaseTooBig, "checkPath failed")
	}

	if strings.ContainsAny(base, "..") {
		// TODO: better ways to show warnings
		log.Println("Warning - relative path notation is not supported!")
	}

	if strings.ContainsAny(base, "*") || strings.ContainsAny(base, "?") {
		// TODO: better ways to show warnings
		log.Println("Warning - wildcard notation is not supported!")
	}

	return nil
}

// AuditSetupAndAddWatchDir checks directory watch params for setting of fields in AuditRuleData
func AuditSetupAndAddWatchDir(rule *AuditRuleData, pathName string) error {
	typeName := uint16(AUDIT_WATCH)

	err := checkPath(pathName)
	if err != nil {
		return errors.Wrap(err, "AuditSetupAndAddWatchDir failed")
	}

	// Trim trailing '/' should they exist
	strings.TrimRight(pathName, "/")

	if fileInfo, err := os.Stat(pathName); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("AuditSetupAndAddWatchDir failed: file at %v does not exist", pathName)
		}

		if fileInfo.IsDir() {
			typeName = uint16(AUDIT_DIR)
		} else {
			return errors.Wrap(err, "AuditSetupAndAddWatchDir failed")
		}
	}

	err = AuditAddWatchDir(typeName, rule, pathName)
	if err != nil {
		return errors.Wrap(err, "AuditSetupAndAddWatchDir failed")
	}
	return nil

}

// AuditAddWatchDir sets fields in AuditRuleData for watching PathName
func AuditAddWatchDir(typeName uint16, rule *AuditRuleData, pathName string) error {

	// Check if Rule is Empty
	if rule.FieldCount != 0 {
		return fmt.Errorf("AuditAddWatchDir failed: rule is not empty")
	}

	if typeName != uint16(AUDIT_DIR) && typeName != uint16(AUDIT_WATCH) {
		return fmt.Errorf("AuditAddWatchDir failed: invalid type %v used", typeName)
	}

	rule.Flags = uint32(AUDIT_FILTER_EXIT)
	rule.Action = uint32(AUDIT_ALWAYS)
	// mark all bits as would be done by audit_rule_syscallbyname_data(rule, "all")
	for i := 0; i < AUDIT_BITMASK_SIZE-1; i++ {
		rule.Mask[i] = 0xFFFFFFFF
	}

	rule.FieldCount = uint32(2)
	rule.Fields[0] = uint32(typeName)

	rule.Fieldflags[0] = uint32(AUDIT_EQUAL)
	valbyte := []byte(pathName)
	vlen := len(valbyte)

	rule.Values[0] = (uint32)(vlen)
	rule.Buflen = (uint32)(vlen)
	//Now append the key value with the rule buffer space
	//May need to reallocate memory to rule.Buf i.e. the 0 size byte array, append will take care of that
	rule.Buf = append(rule.Buf, valbyte[:]...)

	rule.Fields[1] = uint32(AUDIT_PERM)
	rule.Fieldflags[1] = uint32(AUDIT_EQUAL)
	rule.Values[1] = uint32(AUDIT_PERM_READ | AUDIT_PERM_WRITE | AUDIT_PERM_EXEC | AUDIT_PERM_ATTR)

	return nil
}

// AuditSetupAndUpdatePerms validates permission string and passes their
// integer equivalents to set AuditRuleData
func AuditSetupAndUpdatePerms(rule *AuditRuleData, perms string) error {
	if len(perms) > 4 {
		return fmt.Errorf("AuditSetupAndUpdatePerms failed: invalid permission string %v", perms)
	}
	perms = strings.ToLower(perms)
	var permValue int
	for _, val := range perms {
		switch val {
		case 'r':
			permValue |= AUDIT_PERM_READ
		case 'w':
			permValue |= AUDIT_PERM_WRITE
		case 'x':
			permValue |= AUDIT_PERM_EXEC
		case 'a':
			permValue |= AUDIT_PERM_ATTR
		default:
			return fmt.Errorf("AuditSetupAndUpdatePerms failed: unsupported permission %v", val)
		}
	}

	err := AuditUpdateWatchPerms(rule, permValue)
	if err != nil {
		return errors.Wrap(err, "AuditSetupAndUpdatePerms failed")
	}
	return nil
}

// AuditUpdateWatchPerms sets permisission bits in AuditRuleData
func AuditUpdateWatchPerms(rule *AuditRuleData, perms int) error {
	var done bool

	if rule.FieldCount < 1 {
		return fmt.Errorf("AuditUpdateWatchPerms failed: empty rule")
	}

	// First see if we have an entry we are updating
	for i := range rule.Fields {
		if rule.Fields[i] == uint32(AUDIT_PERM) {
			rule.Values[i] = uint32(perms)
			done = true
		}
	}

	if !done {
		// If not check to see if we have room to add a field
		if rule.FieldCount >= AUDIT_MAX_FIELDS-1 {
			return fmt.Errorf("AuditUpdateWatchPerms: maximum field limit reached")
		}

		rule.Fields[rule.FieldCount] = uint32(AUDIT_PERM)
		rule.Values[rule.FieldCount] = uint32(perms)
		rule.Fieldflags[rule.FieldCount] = uint32(AUDIT_EQUAL)
		rule.FieldCount++
	}

	return nil
}

// ListAllRules lists all audit rules currently loaded in audit kernel
// TODO: this funcion needs a lot of work to print actual rules
// func ListAllRules(s *NetlinkConnection) error {
// 	wb := newNetlinkAuditRequest(uint16(AUDIT_LIST_RULES), syscall.AF_NETLINK, 0)
// 	if err := s.Send(wb); err != nil {
// 		//log.Print("Error:", err)
// 		return errors.Wrap(err, "ListAllRules failed")
// 	}

// done:
// 	for {
// 		// msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
// 		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, 0)
// 		if err != nil {
// 			return errors.Wrap(err, "ListAllRules failed")
// 		}

// 		for _, m := range msgs {

// 			address, err := syscall.Getsockname(s.fd)
// 			if err != nil {
// 				return errors.Wrap(err, "ListAllRules failed: Getsockname failed")
// 			}
// 			switch v := address.(type) {
// 			case *syscall.SockaddrNetlink:
// 				if m.Header.Seq != wb.Header.Seq {
// 					return fmt.Errorf("ListAllRules: Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
// 				}
// 				if m.Header.Pid != v.Pid {
// 					return fmt.Errorf("ListAllRules: Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
// 				}
// 			default:
// 				return errors.Wrap(syscall.EINVAL, "ListAllRules: socket type unexpected")
// 			}

// 			if m.Header.Type == syscall.NLMSG_DONE {
// 				break done
// 			}
// 			if m.Header.Type == syscall.NLMSG_ERROR {
// 				error := int32(nativeEndian().Uint32(m.Data[0:4]))
// 				if error == 0 {
// 					break done
// 				}
// 			}
// 			if m.Header.Type == uint16(AUDIT_LIST_RULES) {
// 				p := (*AuditRuleData)(unsafe.Pointer(&m.Data[0]))
// 				log.Println(p.Flags)
// 			}
// 		}
// 	}
// 	return nil
// }

//AuditSyscallToName takes syscall number can returns the syscall name. Applicable only for x64 arch only.
func AuditSyscallToName(syscall string) (name string, err error) {
	var x64Map interface{}
	err = json.Unmarshal([]byte(reverseSysMap), &x64Map)
	if err != nil {
		return "", errors.Wrap(err, "AuditSyscallToName failed")
	}
	syscallMap := x64Map.(map[string]interface{})
	_, ok := syscallMap[syscall]
	if ok {
		return syscallMap[syscall].(string), nil
	}
	return "", fmt.Errorf("AuditSyscallToName failed: syscall %v not found", syscall)

}
