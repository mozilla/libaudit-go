package libaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var rulesRetrieved AuditRuleData

// AuditRuleData is used while adding/deleting/listing audit rules
type AuditRuleData struct {
	Flags       uint32 // AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND
	Action      uint32 // AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS
	Field_count uint32
	Mask        [AUDIT_BITMASK_SIZE]uint32 // syscall(s) affected
	Fields      [AUDIT_MAX_FIELDS]uint32
	Values      [AUDIT_MAX_FIELDS]uint32
	Fieldflags  [AUDIT_MAX_FIELDS]uint32
	Buflen      uint32 // total length of string fields
	Buf         []byte // string fields buffer
}

// For fieldtab
type FMap struct {
	Name    string
	Fieldid float64
}

// For fields
type Field struct {
	Fieldmap []FMap
}

func (rule *AuditRuleData) ToWireFormat() []byte {

	newbuff := make([]byte, int(unsafe.Sizeof(*rule))-int(unsafe.Sizeof(rule.Buf))+int(rule.Buflen))
	*(*uint32)(unsafe.Pointer(&newbuff[0:4][0])) = rule.Flags
	*(*uint32)(unsafe.Pointer(&newbuff[4:8][0])) = rule.Action
	*(*uint32)(unsafe.Pointer(&newbuff[8:12][0])) = rule.Field_count
	*(*[AUDIT_BITMASK_SIZE]uint32)(unsafe.Pointer(&newbuff[12:268][0])) = rule.Mask
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&newbuff[268:524][0])) = rule.Fields
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&newbuff[524:780][0])) = rule.Values
	*(*[AUDIT_MAX_FIELDS]uint32)(unsafe.Pointer(&newbuff[780:1036][0])) = rule.Fieldflags
	*(*uint32)(unsafe.Pointer(&newbuff[1036:1040][0])) = rule.Buflen
	copy(newbuff[1040:1040+rule.Buflen], rule.Buf[:])
	return newbuff
}

// Delete Rule Data Function
func AuditDeleteRuleData(s *NetlinkConnection, rule *AuditRuleData, flags uint32, action uint32) error {
	if flags == AUDIT_FILTER_ENTRY {
		log.Println("Entry Filters Deprecated!!")
		return errEntryDep
	}
	rule.Flags = flags
	rule.Action = action

	newbuff := rule.ToWireFormat()
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
		return err
	}
	return nil
}

// This function Deletes all rules
func DeleteAllRules(s *NetlinkConnection) error {
	wb := newNetlinkAuditRequest(uint16(AUDIT_LIST_RULES), syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		//log.Print("Error:", err)
		return err
	}

done:
	for {
		// Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		// msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, 0)
		if err != nil {
			log.Println("ERROR while receiving rules:", err)
			return err
		}

		for _, m := range msgs {
			address, er := syscall.Getsockname(s.fd)
			if er != nil {
				//log.Println("ERROR:", er)
				return er
			}
			switch v := address.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) {
					return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
				}
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				log.Println("Deleting Done")
				break done

			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				error := int32(nativeEndian().Uint32(m.Data[0:4]))
				if error == 0 {
					//log.Println("Acknowledment")
				} else {
					log.Println("NLMSG_ERROR Received")
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
					return err
				}
			}
		}
	}
	return nil
}

var _audit_permadded bool
var _audit_syscalladded bool

// Load x86_64 map and fieldtab
func loadSysMapFieldTab(x64Map interface{}, fieldmap *Field) error {

	err := json.Unmarshal([]byte(sysMapX64), &x64Map)
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(fields), &fieldmap)
	if err != nil {
		return err
	}

	return nil
}

func auditWord(nr int) uint32 {
	audit_word := (uint32)((nr) / 32)
	return (uint32)(audit_word)
}

func auditBit(nr int) uint32 {
	audit_bit := 1 << ((uint32)(nr) - auditWord(nr)*32)
	return (uint32)(audit_bit)
}

// Make changes in the rule struct according to system call number
func AuditRuleSyscallData(rule *AuditRuleData, scall int) error {
	word := auditWord(scall)
	bit := auditBit(scall)

	if word >= AUDIT_BITMASK_SIZE-1 {
		return fmt.Errorf("Word Size greater than AUDIT_BITMASK_SIZE")
	}
	rule.Mask[word] |= bit
	return nil
}

func AuditNameToFtype(name string, value *int) error {

	var filemap interface{}
	err := json.Unmarshal([]byte(ftypeTab), &filemap)

	if err != nil {
		//log.Print("Error:", err)
		return err
	}

	m := filemap.(map[string]interface{})

	for k, v := range m {
		if k == name {
			*value = int(v.(float64))
			return nil
		}
	}

	return fmt.Errorf("Filetype not found")
}

var (
	errMaxField = errors.New("MAX Fields for AuditRuleData exceeded")
	errNoStr    = errors.New("No support for string values")
	errUnset    = errors.New("Unable to set value")
	errNoExit   = errors.New("Filter can only be used with AUDIT_EXIT")
	errNoSys    = errors.New("No syscall added")
	errMaxLen   = errors.New("MAX length Exceeded")
)

func AuditRuleFieldPairData(rule *AuditRuleData, fieldval interface{}, opval uint32, fieldname string, fieldmap Field, flags int) error {

	if rule.Field_count >= (AUDIT_MAX_FIELDS - 1) {
		log.Println("Max Fields Exceeded")
		return errMaxField
	}

	var fieldid uint32
	for f := range fieldmap.Fieldmap {
		if fieldmap.Fieldmap[f].Name == fieldname {
			//log.Println("Found :", fieldmap.Fieldmap[f])
			fieldid = (uint32)(fieldmap.Fieldmap[f].Fieldid)
		}
	}

	rule.Fields[rule.Field_count] = fieldid
	rule.Fieldflags[rule.Field_count] = opval

	switch fieldid {
	case AUDIT_UID, AUDIT_EUID, AUDIT_SUID, AUDIT_FSUID, AUDIT_LOGINUID, AUDIT_OBJ_UID, AUDIT_OBJ_GID:
		if val, isInt := fieldval.(float64); isInt {

			if val < 0 {
				// For trimming "-" and evaluating th condition vlen >=2 (which is not needed)
				valString := strconv.FormatInt((int64)(val), 10)
				fieldvalUid := strings.Replace(valString, "-", "", -1)
				a, err := strconv.Atoi(fieldvalUid)

				if err != nil {
					log.Println("Conversion not possible")
					return err
				} else {
					rule.Values[rule.Field_count] = (uint32)(a)
				}

			} else {
				rule.Values[rule.Field_count] = (uint32)(val)
			}
		} else if val, isString := fieldval.(string); isString {
			if fieldval.(string) == "unset" {
				rule.Values[rule.Field_count] = 4294967295
			} else {
				log.Println("No support for string values yet", val)
				return errNoStr
				//Insert audit_name_to_uid(string,int * val)
			}
		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset
		}

	case AUDIT_GID, AUDIT_EGID, AUDIT_SGID, AUDIT_FSGID:
		//IF DIGITS THEN
		if val, isInt := fieldval.(float64); isInt {
			rule.Values[rule.Field_count] = (uint32)(val)
		} else if val, isString := fieldval.(string); isString {
			log.Println("No support for string values yet", val)
			return errNoStr
			//audit_name_to_gid(string, sint*val)
		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset
		}

	case AUDIT_EXIT:

		if flags != AUDIT_FILTER_EXIT {
			return errNoExit
		}
		if val, isInt := fieldval.(float64); isInt {
			if val < 0 {
				// For trimming "-" and evaluating th condition vlen >=2 (which is not needed)
				valString := strconv.FormatInt((int64)(val), 10)
				fieldvalUid := strings.Replace(valString, "-", "", -1)
				a, err := strconv.Atoi(fieldvalUid)

				if err != nil {
					return err
				} else {
					rule.Values[rule.Field_count] = (uint32)(a)
				}

			} else {
				rule.Values[rule.Field_count] = (uint32)(val)
			}

		} else if val, isString := fieldval.(string); isString {
			log.Println("No support for string values yet", val)
			return errNoStr
		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset
		}

		//TODO: String handling part
		//else {
		//	rule->values[rule->field_count] =
		//			audit_name_to_errno(v);
		//	if (rule->values[rule->field_count] == 0)
		//		return -15;
		//}
		//break;

	case AUDIT_MSGTYPE:

		if flags != AUDIT_FILTER_EXCLUDE && flags != AUDIT_FILTER_USER {
			return fmt.Errorf("AUDIT_MSGTYPE can only be used with AUDIT_FILTER_EXCLUDE")
		}
		if val, isInt := fieldval.(float64); isInt {
			rule.Values[rule.Field_count] = (uint32)(val)
		} else if val, isString := fieldval.(string); isString {
			log.Println("No support for string values yet", val)
			return errNoStr
		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset

		}

	//Strings
	case AUDIT_OBJ_USER, AUDIT_OBJ_ROLE, AUDIT_OBJ_TYPE, AUDIT_OBJ_LEV_LOW, AUDIT_OBJ_LEV_HIGH, AUDIT_WATCH, AUDIT_DIR:
		/* Watch & object filtering is invalid on anything
		 * but exit */

		if flags != AUDIT_FILTER_EXIT {
			return errNoExit
		}
		if fieldid == AUDIT_WATCH || fieldid == AUDIT_DIR {
			_audit_permadded = true
		}

		fallthrough //IMP
	case AUDIT_SUBJ_USER, AUDIT_SUBJ_ROLE, AUDIT_SUBJ_TYPE, AUDIT_SUBJ_SEN, AUDIT_SUBJ_CLR, AUDIT_FILTERKEY:
		//If And only if a syscall is added or a permisission is added then this field should be set
		//TODO - More debugging required
		if fieldid == AUDIT_FILTERKEY && !(_audit_syscalladded || _audit_permadded) {
			return errNoSys
		}
		if val, isString := fieldval.(string); isString {
			valbyte := []byte(val)
			vlen := len(valbyte)
			if fieldid == AUDIT_FILTERKEY && vlen > AUDIT_MAX_KEY_LEN {
				return errMaxLen
			} else if vlen > PATH_MAX {
				return errMaxLen
			}
			rule.Values[rule.Field_count] = (uint32)(vlen)
			rule.Buflen = rule.Buflen + (uint32)(vlen)
			// log.Println(unsafe.Sizeof(*rule), vlen)
			//Now append the key value with the rule buffer space
			//May need to reallocate memory to rule.Buf i.e. the 0 size byte array, append will take care of that
			rule.Buf = append(rule.Buf, valbyte[:]...)
			// log.Println(int(unsafe.Sizeof(*rule)), *rule)
		}

	case AUDIT_ARCH:
		if _audit_syscalladded == false {
			return errNoSys
		} else {
			//AUDIT_ARCH_X86_64 is made specifically for Mozilla Heka purpose.
			if _, isInt := fieldval.(float64); isInt {
				rule.Values[rule.Field_count] = AUDIT_ARCH_X86_64
			} else if _, isString := fieldval.(string); isString {
				return errNoStr
			} else {
				return errUnset
			}
		}

	case AUDIT_PERM:
		//Decide on various error types
		if flags != AUDIT_FILTER_EXIT {
			return errNoExit
		} else if opval != AUDIT_EQUAL {
			return fmt.Errorf("Operator can only be AUDIT_EQUAL in case of AUDIT_PERM")
		} else {
			if val, isString := fieldval.(string); isString {

				var i, vallen int
				vallen = len(val)
				var permval uint32
				if vallen > 4 {
					return errMaxLen
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
						return fmt.Errorf(" %s is not found as permission", lowerval[i])
					}
				}
				rule.Values[rule.Field_count] = permval
				_audit_permadded = true
			}
		}
	case AUDIT_FILETYPE:
		if val, isString := fieldval.(string); isString {
			if !(flags == AUDIT_FILTER_EXIT) && flags == AUDIT_FILTER_ENTRY {
				return fmt.Errorf("Flag can only be AUDIT_EXIT in case of AUDIT_FILETYPE")
			}
			var fileval int
			err := AuditNameToFtype(val, &fileval)
			if err != nil {
				return err
			}
			rule.Values[rule.Field_count] = uint32(fileval)
			if (int)(rule.Values[rule.Field_count]) < 0 {
				return syscall.EINVAL
			}
		} else {
			return fmt.Errorf("Numbers as filetypes")
		}

	case AUDIT_ARG0, AUDIT_ARG1, AUDIT_ARG2, AUDIT_ARG3:
		if val, isInt := fieldval.(float64); isInt {
			if val < 0 {
				// For trimming "-" and evaluating th condition vlen >=2 (which is not needed)
				valString := strconv.FormatInt((int64)(val), 10)
				fieldvalUid := strings.Replace(valString, "-", "", -1)
				a, err := strconv.Atoi(fieldvalUid)

				if err != nil {
					return err
				} else {
					rule.Values[rule.Field_count] = (uint32)(a)
				}
			} else {
				rule.Values[rule.Field_count] = (uint32)(val)
			}
		} else if _, isString := fieldval.(string); isString {
			log.Println("Error Setting Value:", fieldval)
			return errNoStr
		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset
		}
	case AUDIT_DEVMAJOR, AUDIT_INODE, AUDIT_SUCCESS:
		if flags != AUDIT_FILTER_EXIT {
			return errNoExit
		}
		fallthrough
	default:
		if fieldid == AUDIT_INODE {
			if !(opval == AUDIT_NOT_EQUAL || opval == AUDIT_EQUAL) {
				return fmt.Errorf("OP can only be AUDIT_NOT_EQUAL or AUDIT_EQUAL")
			}
		}

		if fieldid == AUDIT_PPID && !(flags == AUDIT_FILTER_EXIT || flags == AUDIT_FILTER_ENTRY) {
			return fmt.Errorf("Flags can only be EXIT or ENTRY in case of AUDIT_PPID")
		}

		if val, isInt := fieldval.(float64); isInt {

			if fieldid == AUDIT_INODE {
				rule.Values[rule.Field_count] = (uint32)(val)
			} else {
				rule.Values[rule.Field_count] = (uint32)(val)
			}

		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset
		}
	}
	rule.Field_count++
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
			log.Println("Support for Entry Filter is Deprecated. Switching back to Exit filter")
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

func AuditAddRuleData(s *NetlinkConnection, rule *AuditRuleData, flags int, action int) error {

	if flags == AUDIT_FILTER_ENTRY {
		log.Println("Use of entry filter is deprecated")
		return errEntryDep
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
		return err
	}
	return nil
}

//Sets each rule after reading configuration file
func SetRules(s *NetlinkConnection, content []byte) error {

	var rules interface{}
	err := json.Unmarshal(content, &rules)
	if err != nil {
		//log.Print("Error:", err)
		return err
	}

	m := rules.(map[string]interface{})

	//var conf Config
	var x64Map interface{}
	var fieldmap Field

	// Load x86_64 map and fieldtab.json
	err = loadSysMapFieldTab(&x64Map, &fieldmap)
	if err != nil {
		log.Println("Error :", err)
		return err
	}
	syscallMap := x64Map.(map[string]interface{})

	for k, v := range m {
		_audit_syscalladded = false
		switch k {
		case "file_rules":
			vi := v.([]interface{})
			for ruleNo := range vi {
				rule := vi[ruleNo].(map[string]interface{})
				path := rule["path"]
				if path == "" {
					log.Fatalln("Watch option needs a path")
				}
				perms := rule["permission"]
				//log.Println("Setting watch on", path)
				var dd AuditRuleData
				dd.Buf = make([]byte, 0)
				add := AUDIT_FILTER_EXIT
				action := AUDIT_ALWAYS
				_audit_syscalladded = true

				err := AuditSetupAndAddWatchDir(&dd, path.(string))
				if err != nil {
					log.Fatalln(err)
				}
				if perms != nil {
					err = AuditSetupAndUpdatePerms(&dd, perms.(string))
					if err != nil {
						log.Fatalln(err)
					}
				}

				key := rule["key"]
				if key != nil {
					err = AuditRuleFieldPairData(&dd, key, AUDIT_EQUAL, "key", fieldmap, AUDIT_FILTER_UNSET) // &AUDIT_BIT_MASK
					if err != nil {
						return err
					}
				}

				err = AuditAddRuleData(s, &dd, add, action)
				if err != nil {
					log.Fatalln(err)
				}

			}
			log.Println("Done setting watches.")
		case "syscall_rules":
			vi := v.([]interface{})
			for sruleNo := range vi {
				srule := vi[sruleNo].(map[string]interface{})
				var dd AuditRuleData
				dd.Buf = make([]byte, 0)
				// Process syscalls
				// TODO: support syscall no
				if srule["syscalls"] != nil {
					syscalls := srule["syscalls"].([]interface{})
					syscalls_not_found := ""
					for _, syscall := range syscalls {
						syscall := syscall.(string)
						if syscallMap[syscall] != nil {
							//log.Println("setting syscall rule", syscall)
							err = AuditRuleSyscallData(&dd, int(syscallMap[syscall].(float64)))
							if err == nil {
								_audit_syscalladded = true
							} else {
								return err
							}
						}
						syscalls_not_found += " " + syscall
					}
					if _audit_syscalladded != true {
						return errors.New("One or more syscall not found: " + syscalls_not_found)
					}
				}

				// Process action
				actions := srule["actions"].([]interface{})

				//Apply action on syscall by separating the filters (exit) from actions (always)
				action, filter := setActionAndFilters(actions)

				// Process fields
				if srule["fields"] == nil {
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
						err = AuditRuleFieldPairData(&dd, fieldval, opval, fieldname.(string), fieldmap, filter) // &AUDIT_BIT_MASK
						if err != nil {
							return err
						}
					}
				}

				key := srule["key"]
				if key != nil {
					err = AuditRuleFieldPairData(&dd, key, AUDIT_EQUAL, "key", fieldmap, AUDIT_FILTER_UNSET) // &AUDIT_BIT_MASK
					if err != nil {
						return err
					}
				}

				// foo.Fields[foo.Field_count] = AUDIT_ARCH
				// foo.Fieldflags[foo.Field_count] = AUDIT_EQUAL
				// foo.Values[foo.Field_count] = AUDIT_ARCH_X86_64
				// foo.Field_count++
				// AuditAddRuleData(s, &foo, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)

				if filter != AUDIT_FILTER_UNSET {
					AuditAddRuleData(s, &dd, filter, action)
				} else {
					return fmt.Errorf("Filters not set or invalid: " + actions[0].(string) + ", " + actions[1].(string))
				}
			}
		}
	}
	return nil
}

var errPathTooBig = errors.New("The path passed for the watch is too big")
var errPathStart = errors.New("The path must start with '/'")
var errBaseTooBig = errors.New("The base name of the path is too big")

func check_path(path_name string) error {
	if len(path_name) >= PATH_MAX {
		return errPathTooBig
	}
	if path_name[0] != '/' {
		return errPathStart
	}

	base := path.Base(path_name)

	if len(base) > syscall.NAME_MAX {
		return errBaseTooBig
	}

	if strings.ContainsAny(base, "..") {
		log.Println("Warning - relative path notation is not supported!")
	}

	if strings.ContainsAny(base, "*") || strings.ContainsAny(base, "?") {
		log.Println("Warning - wildcard notation is not supported!")
	}

	return nil
}

func AuditSetupAndAddWatchDir(rule *AuditRuleData, path_name string) error {
	type_name := uint16(AUDIT_WATCH)

	err := check_path(path_name)
	if err != nil {
		return err
	}

	// Trim trailing '/' should they exist
	strings.TrimRight(path_name, "/")

	if fileInfo, err := os.Stat(path_name); err != nil {
		if os.IsNotExist(err) {
			return errors.New("File does Not exist: " + path_name)
		} else {
			return err
		}
		if fileInfo.IsDir() {
			type_name = uint16(AUDIT_DIR)
		}
	}

	err = AuditAddWatchDir(type_name, rule, path_name)
	if err != nil {
		return err
	}
	return nil

}

func AuditAddWatchDir(type_name uint16, rule *AuditRuleData, path_name string) error {

	// Check if Rule is Empty
	// if rule && rule.Field_count {
	// 	return errors.New("Rule is Not Empty!")
	// }

	if type_name != uint16(AUDIT_DIR) && type_name != uint16(AUDIT_WATCH) {
		return errors.New("Invalid Type Used!")
	}

	rule.Flags = uint32(AUDIT_FILTER_EXIT)
	rule.Action = uint32(AUDIT_ALWAYS)
	// set mask
	// TODO : Setup audit_rule_syscallbyname_data(rule, "all")
	for i := 0; i < AUDIT_BITMASK_SIZE-1; i++ {
		rule.Mask[i] = 0xFFFFFFFF
	}

	rule.Field_count = uint32(2)
	rule.Fields[0] = uint32(type_name)

	rule.Fieldflags[0] = uint32(AUDIT_EQUAL)
	valbyte := []byte(path_name)
	vlen := len(valbyte)
	// if fieldid == AUDIT_FILTERKEY && vlen > AUDIT_MAX_KEY_LEN {
	// 	return errMaxLen
	// } else if vlen > PATH_MAX {
	// 	return errMaxLen
	// }
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

func AuditSetupAndUpdatePerms(rule *AuditRuleData, perms string) error {
	if len(perms) > 4 {
		return errors.New("Permissions wrong!!")
	}
	perms = strings.ToLower(perms)
	perm_value := 0
	for _, val := range perms {

		switch val {
		case 'r':
			perm_value |= AUDIT_PERM_READ
		case 'w':
			perm_value |= AUDIT_PERM_WRITE
		case 'x':
			perm_value |= AUDIT_PERM_EXEC
		case 'a':
			perm_value |= AUDIT_PERM_ATTR
		default:
			return errors.New("Permission isn't supported")
		}
	}

	err := AuditUpdateWatchPerms(rule, perm_value)
	if err != nil {
		return err
	}
	return nil
}

func AuditUpdateWatchPerms(rule *AuditRuleData, perms int) error {
	done := false

	if rule.Field_count < 1 {
		return errors.New("No rules provided")
	}

	// First see if we have an entry we are updating
	for i, _ := range rule.Fields {
		if rule.Fields[i] == uint32(AUDIT_PERM) {
			rule.Values[i] = uint32(perms)
			done = true
		}
	}

	if !done {
		// If not check to see if we have room to add a field
		if rule.Field_count >= AUDIT_MAX_FIELDS-1 {
			return errors.New("No More rules can be added")
		}

		rule.Fields[rule.Field_count] = uint32(AUDIT_PERM)
		rule.Values[rule.Field_count] = uint32(perms)
		rule.Fieldflags[rule.Field_count] = uint32(AUDIT_EQUAL)
		rule.Field_count++
	}

	return nil
}

// List all rules
// TODO: this funcion needs a lot of work to print actual rules
func ListAllRules(s *NetlinkConnection) error {
	wb := newNetlinkAuditRequest(uint16(AUDIT_LIST_RULES), syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		//log.Print("Error:", err)
		return err
	}

done:
	for {
		// msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, 0)
		if err != nil {
			log.Println("ERROR while receiving rules:", err)
			return err
		}

		for _, m := range msgs {

			address, er := syscall.Getsockname(s.fd)
			if er != nil {
				log.Println("ERROR:", er)
				return err
			}
			switch v := address.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != wb.Header.Seq {
					return errors.New("Wrong Seq nr, " + strconv.FormatUint(uint64(m.Header.Seq), 10) +
						" expected " + strconv.FormatUint(uint64(wb.Header.Seq), 10))
				}
				if m.Header.Pid != v.Pid {
					return errors.New("Wrong pid," + strconv.FormatUint(uint64(m.Header.Pid), 10) +
						" expected" + strconv.FormatUint(uint64(v.Pid), 10))
				}
			default:
				log.Println("ERROR:", syscall.EINVAL)
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				log.Println("All rules deleted")
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				log.Println("NLMSG_ERROR")
			}
			if m.Header.Type == uint16(AUDIT_LIST_RULES) {
				p := (*AuditRuleData)(unsafe.Pointer(&m.Data[0]))
				log.Println(p.Flags)
			}
		}
	}
	return nil
}

//AuditSyscallToName takes syscall number can returns the syscall name. Applicable only for x64 arch only.
func AuditSyscallToName(syscall string) (name string, err error) {
	var x64Map interface{}
	err = json.Unmarshal([]byte(reverseSysMap), &x64Map)
	if err != nil {
		return "", err
	}
	syscallMap := x64Map.(map[string]interface{})
	_, ok := syscallMap[syscall]
	if ok {
		return syscallMap[syscall].(string), nil
	}
	return "", fmt.Errorf("syscall %v not found", syscall)

}
