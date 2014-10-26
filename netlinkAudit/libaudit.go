package netlinkAudit

import (
	"bytes"
	"encoding/json"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"syscall"
	"unsafe"
)

var ParsedResult AuditStatus

// This function makes a conncetion with kernel space and is to be used for all further socket communication
func GetNetlinkSocket() (*NetlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, err
	}
	s := &NetlinkSocket{
		fd: fd,
	}
	s.lsa.Family = syscall.AF_NETLINK
	s.lsa.Groups = 0
	s.lsa.Pid = 0 //Kernel space pid is always set to be 0

	if err := syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return s, nil
}

//To end the socket conncetion
func (s *NetlinkSocket) Close() {
	syscall.Close(s.fd)
}

func (s *NetlinkSocket) Send(request *NetlinkAuditRequest) error {
	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

func (s *NetlinkSocket) Receive(bytesize int, block int) ([]syscall.NetlinkMessage, error) {
	rb := make([]byte, bytesize)
	nr, _, err := syscall.Recvfrom(s.fd, rb, 0|block)
	//nr, _, err := syscall.Recvfrom(s, rb, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)

	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}
	rb = rb[:nr]
	return ParseAuditNetlinkMessage(rb)
}

//should it be changed to HandleAck ?
func AuditGetReply(s *NetlinkSocket, bytesize, block int, seq uint32) error {
done:
	for {
		msgs, err := s.Receive(bytesize, block) //ParseAuditNetlinkMessage(rb)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			lsa, err := syscall.Getsockname(s.fd)
			if err != nil {
				return err
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:

				if m.Header.Seq != seq {
					return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
				}
			default:
				return syscall.EINVAL
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				error := int32(nativeEndian().Uint32(m.Data[0:4]))
				if error == 0 {
					fmt.Println("ACK")
					break done
				} else {
					fmt.Println("NLMSG_ERROR")
				}
				break done
			}
			if m.Header.Type == AUDIT_GET {
				fmt.Println("AUDIT_GET")
				//				break done
			}
			if m.Header.Type == AUDIT_FIRST_USER_MSG {
				fmt.Println("AUDIT_FIRST_USER_MS")
				//break done
			}
			if m.Header.Type == AUDIT_LIST_RULES {
				fmt.Println("AUDIT_LIST_RULES")
				//break done
			}
			if m.Header.Type == AUDIT_FIRST_USER_MSG {
				fmt.Println("AUDIT_FIRST_USER_MSG")
				//break done
			}
		}
	}
	return nil
}

func AuditSetEnabled(s *NetlinkSocket /*, seq int*/) error {
	var status AuditStatus
	status.Enabled = 1
	status.Mask = AUDIT_STATUS_ENABLED
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(AUDIT_SET, syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}

	// Receiving IN JUST ONE TRY
	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return err
	}
	return nil
}

func AuditIsEnabled(s *NetlinkSocket /*seq int*/) error {
	wb := newNetlinkAuditRequest(AUDIT_GET, syscall.AF_NETLINK, 0)

	if err := s.Send(wb); err != nil {
		return err
	}

done:
	for {
		//Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		if err != nil {
			return err
		}

		for _, m := range msgs {
			lsa, er := syscall.Getsockname(s.fd)
			if er != nil {
				return nil
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:

				if m.Header.Seq != uint32(wb.Header.Seq) || m.Header.Pid != v.Pid {
					return syscall.EINVAL
				}
			default:
				return syscall.EINVAL
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("Done")
				break done

			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				fmt.Println("NLMSG_ERROR\n")
			}
			if m.Header.Type == AUDIT_GET {
				//Convert the data part written to AuditStatus struct
				b := m.Data[:]
				buf := bytes.NewBuffer(b)
				var dumm AuditStatus
				err = binary.Read(buf, nativeEndian(), &dumm)
				ParsedResult = dumm
				fmt.Println("ENABLED")
				break done
			}
		}
	}
	return nil
}

func AuditSetPid(s *NetlinkSocket, pid uint32 /*,Wait mode WAIT_YES | WAIT_NO */) error {
	var status AuditStatus
	status.Mask = AUDIT_STATUS_PID
	status.Pid = pid
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(AUDIT_SET, syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}

	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return err
	}
	//Polling in GO Is it needed ?
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

func AuditRuleSyscallData(rule *AuditRuleData, scall int) error {
	word := auditWord(scall)
	bit := auditBit(scall)

	if word >= AUDIT_BITMASK_SIZE-1 {
		fmt.Println("Some error occured")
	}
	rule.Mask[word] |= bit
	return nil
}

func AuditAddRuleData(s *NetlinkSocket, rule *AuditRuleData, flags int, action int) error {

	if flags == AUDIT_FILTER_ENTRY {
		fmt.Println("Use of entry filter is deprecated")
		return nil
	}

	rule.Flags = uint32(flags)
	rule.Action = uint32(action)

	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), *rule)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return err
	}
	//	err = AuditSend(s, AUDIT_ADD_RULE, buff.Bytes(), int(buff.Len())+int(rule.Buflen))
	wb := newNetlinkAuditRequest(AUDIT_ADD_RULE, syscall.AF_NETLINK, int(buff.Len())+int(rule.Buflen))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}

	if err != nil {
		fmt.Println("Error sending add rule data request ()")
		return err
	}
	return nil
}

//A very gibberish hack right now , Need to work on the design of this package.
func isDone(msgchan chan<- syscall.NetlinkMessage, errchan chan<- error, done <-chan bool) bool {
	var d bool
	select {
	case d = <-done:
		close(msgchan)
		close(errchan)
	default:
	}
	return d
}

func GetreplyWithoutSync(s *NetlinkSocket) {
	for {
		rb := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
		nr, _, err := syscall.Recvfrom(s.fd, rb, 0 )
		if err != nil {
			fmt.Println("Error While Recieving !!")
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			fmt.Println("Message Too Short!!")
			continue
		}

		rb = rb[:nr]
		msgs, err := ParseAuditNetlinkMessage(rb)

		if err != nil {
			fmt.Println("Not Parsed Successfuly !!")
			continue
		}
		for _, m := range msgs {
			//Decide on various message Types
			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("Done")
			} else if m.Header.Type == syscall.NLMSG_ERROR {
				err := int32(nativeEndian().Uint32(m.Data[0:4]))
				if err == 0 {
					//Acknowledgement from kernel
					fmt.Println("Ack")
				}
				fmt.Println("NLMSG_ERROR")
			} else if m.Header.Type == AUDIT_GET {
				fmt.Println("AUDIT_GET")
			} else if m.Header.Type == AUDIT_FIRST_USER_MSG {
				fmt.Println("AUDIT_FIRST_USER_MSG")
			} else if m.Header.Type == AUDIT_SYSCALL {
				fmt.Println("Syscall Event")
				fmt.Println(string(m.Data[:]))
			} else if m.Header.Type == AUDIT_CWD {
				fmt.Println("CWD Event")
				fmt.Println(string(m.Data[:]))
			} else if m.Header.Type == AUDIT_PATH {
				fmt.Println("Path Event")
				fmt.Println(string(m.Data[:]))
			} else if m.Header.Type == AUDIT_EOE {
				fmt.Println("Event Ends ", string(m.Data[:]))
			} else if m.Header.Type == AUDIT_CONFIG_CHANGE {
				fmt.Println("Config Change ", string(m.Data[:]))
			} else {
				fmt.Println("Unknown: ", m.Header.Type)
			}
		}
	}
}

func Getreply(s *NetlinkSocket, msgchan chan<- syscall.NetlinkMessage, errchan chan<- error, done <-chan bool) {

	//	rb := make([]byte, syscall.Getpagesize())
	for {
		rb := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
		nr, _, err := syscall.Recvfrom(s.fd, rb, 0 /*Do not use syscall.MSG_DONTWAIT*/)
		/*
			if isDone(msgchan, errchan, done) {
				return
			}
		*/
		if err != nil {
			//errchan <- err
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			//errchan <- syscall.EINVAL
			continue
		}
		rb = rb[:nr]
		msgs, err := ParseAuditNetlinkMessage(rb) //Or syscall.ParseNetlinkMessage(rb)

		if err != nil {
			//errchan <- err
			continue
		}
		for _, m := range msgs {
			/*
				Not needed while receiving from kernel ?
							lsa, err := syscall.Getsockname(s.fd)
							if err != nil {
								errchan <- err
								continue
								//return err
							}
								switch v := lsa.(type) {
								case *syscall.SockaddrNetlink:

									if m.Header.Seq != uint32(seq) || m.Header.Pid != v.Pid {
										fmt.Println("foo", seq, m.Header.Seq)
										errchan <- syscall.EINVAL
										//return syscall.EINVAL
									}
								default:
									errchan <- syscall.EINVAL
									//return syscall.EINVAL

								}
			*/
			//Decide on various message Types
			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("Done")
				//msgchan <- m
				//continue
			} else if m.Header.Type == syscall.NLMSG_ERROR {
				err := int32(nativeEndian().Uint32(m.Data[0:4]))
				if err == 0 {
					fmt.Println("Ack") //Acknowledgement from kernel
					//continue
				}

				fmt.Println("NLMSG_ERROR")
				//msgchan <- m
				//continue
			} else if m.Header.Type == AUDIT_GET {
				fmt.Println("AUDIT_GET")
				//msgchan <- m
				//continue
			} else if m.Header.Type == AUDIT_FIRST_USER_MSG {
				fmt.Println("AUDIT_FIRST_USER_MSG")
				//msgchan <- m
				//continue
			} else if m.Header.Type == AUDIT_SYSCALL {
				fmt.Println("Syscall Event")
				fmt.Println(string(m.Data[:]))
				//msgchan <- m
			} else if m.Header.Type == AUDIT_CWD {
				fmt.Println("CWD Event")
				fmt.Println(string(m.Data[:]))
				//msgchan <- m
			} else if m.Header.Type == AUDIT_PATH {
				fmt.Println("Path Event")
				fmt.Println(string(m.Data[:]))
				//msgchan <- m
			} else if m.Header.Type == AUDIT_EOE {
				fmt.Println("Event Ends ", string(m.Data[:]))
			} else {
				fmt.Println("UNKnown: ", m.Header.Type)
				//msgchan <- m
			}
		}
	}
}

// List all rules
// TODO: this funcion needs a lot of work to print actual rules
func ListAllRules(s *NetlinkSocket) {
	wb := newNetlinkAuditRequest(AUDIT_LIST_RULES, syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		fmt.Print("Error:", err)
	}
	
done:
	for {
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		if err != nil {
			fmt.Println("ERROR while receiving rules:", err)
		}

		for _, m := range msgs {
			lsa, er := syscall.Getsockname(s.fd)
			if er != nil {
				fmt.Println("ERROR:", er)
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) || m.Header.Pid != v.Pid {
					fmt.Println("ERROR:", syscall.EINVAL)
				}
			default:
				fmt.Println("ERROR:", syscall.EINVAL)
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("All rules deleted\n")
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				fmt.Println("NLMSG_ERROR\n")
			} 
			if m.Header.Type == AUDIT_LIST_RULES  {
				b := m.Data[:]
				buf := bytes.NewBuffer(b)
				var rules AuditRuleData
				err = binary.Read(buf, nativeEndian(), &rules)
				// TODO : save all rules to an array so delete all rules function can use this
				fmt.Println(rules)
			}
		}
	}
}

//Delete Rule Data Function
func AuditDeleteRuleData(s *NetlinkSocket, rule *AuditRuleData, flags uint32, action uint32) error{
	//var rc int;
	var sizePurpose AuditRuleData
	if (flags == AUDIT_FILTER_ENTRY) {
		fmt.Println("Error in delete")
		return nil;
	}
	rule.Flags = flags
	rule.Action = action

	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), *rule)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return err
	}
	wb := newNetlinkAuditRequest(AUDIT_DEL_RULE, syscall.AF_NETLINK, int(unsafe.Sizeof(sizePurpose)) + int(rule.Buflen))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}
	return nil;
}

// This function Deletes all rules
func DeleteAllRules(s *NetlinkSocket) {
	wb := newNetlinkAuditRequest(AUDIT_LIST_RULES, syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		fmt.Print("Error:", err)
	}
	
done:
	for {
		//Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		if err != nil {
			fmt.Println("ERROR while receiving rules:", err)
		}

		for _, m := range msgs {
			lsa, er := syscall.Getsockname(s.fd)
			if er != nil {
				fmt.Println("ERROR:", er)
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) || m.Header.Pid != v.Pid {
					fmt.Println("ERROR:", syscall.EINVAL)
				}
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("Done\n")
				break done

			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				fmt.Println("NLMSG_ERROR\n")
			} 
			if m.Header.Type == AUDIT_LIST_RULES  {
				b := m.Data[:]
				buf := bytes.NewBuffer(b)
				var rules AuditRuleData
				err = binary.Read(buf, nativeEndian(), &rules)
				AuditDeleteRuleData(s, &rules, rules.Flags, rules.Action)
			}
		}
	}
}

// function that sets each rule after reading configuration file
func SetRules(s *NetlinkSocket) {

	// Load all rules
	content, err := ioutil.ReadFile("netlinkAudit/audit.rules.json")
	if err!=nil{
        fmt.Print("Error:",err)
	}

	var rules interface{}
	err = json.Unmarshal(content, &rules)

	m := rules.(map[string]interface{})
	for k, v := range m {
    	switch k {
    		// TODO: use ordred maps instead of go inbuild maps
    		//case "delete":
    		//	DeleteAllRules(s)
    		case "syscall_rules":
    			vi := v.([]interface{})
	    		for sruleNo := range vi {
	    			srule := vi[sruleNo].(map[string]interface{})
    				// Load x86 map
    				content2, err := ioutil.ReadFile("netlinkAudit/audit_x86.json")
					if err!=nil{
			    	    fmt.Print("Error:",err)
					}
    
					var conf Config
					err = json.Unmarshal([]byte(content2), &conf)
					if err != nil {
						fmt.Print("Error:", err)
					}
					for l := range conf.Xmap {
						if conf.Xmap[l].Name == srule["name"] {
							// set rules 
							fmt.Println("setting syscall rule", conf.Xmap[l].Name)
							var foo AuditRuleData
							AuditRuleSyscallData(&foo,  conf.Xmap[l].Id)
							foo.Fields[foo.Field_count] = AUDIT_ARCH
							foo.Fieldflags[foo.Field_count] = AUDIT_EQUAL
							foo.Values[foo.Field_count] = AUDIT_ARCH_X86_64
							foo.Field_count++
							AuditAddRuleData(s, &foo, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)
						}
					}
				    //default:
				    //    fmt.Println(k, "is not yet supported")
		    }
		}
	}
}


/*
var fieldStrings []byte
fieldStrings = {"a", "a1", "a2", "a3", "arch", "auid", "devmajor", "devminor", "dir", "egid", "euid", "exit", "field_compare", "filetype", "fsgid", "fsuid", "gid", "inode", "key", "loginuid", "msgtype", "obj_gid", "obj_lev_high", "obj_lev_low", "obj_role", "obj_type", "obj_uid", "obj_user",  "path",  "perm",  "pers",  "pid",  "ppid",  "sgid",  "subj_clr",  "subj_role",  "subj_sen",  "subj_type",  "subj_user",  "success",  "suid",  "uid" }

var fieldS2i_s []uint = {0,3,6,9,12,17,22,31,40,44,49,54,59,73,82,88,94,98,104,108,117,125,133,146,158,167,176,184,193,198,203,208,212,217,222,231,241,250,260,270,278,283}

var fieldS2i_i []int{200,201,202,203,11,9,100,101,107,6,2,103,111,108,8,4,5,102,210,9,12,110,23,22,20,21,109,19,105,106,10,0,18,7,17,14,16,15,13,104,3,1}

func S2i(strings *[]byte, s_table *uint, i_table *int, int n, s *[]byte,value *int) bool{
	        var left, right int
	
	        left = 0
	        right = n - 1
	        while left <= right {
	                var mid int
	                var r int
	
	                mid = (left + right) / 2
	                r =  int(s) - int(s_table[mid])
	                if (r == 0) {
	                        &value = i_table[mid]
	                        return true
	                }
	                if (r < 0)
	                        right = mid - 1
	                else
	                        left = mid + 1
	        }
	        return false
}


func int FlagS2i(s *[]byte, value *int) bool{
	var len, i int
	i = 0
	c []byte
	len = unsafe.Sizeof(s);
	copy := make([]byte, len+1)
	//char copy[len + 1];	
	for i < len {
		c = &s[i]
		if unicode.IsUpper(c){
			copy[i] = c - 'A' + 'a'
		}else{
			copy[i] = c
		}
		i = i + 1
	}
	copy[i] = 0;
	return S2i(fieldStrings, fieldS2i_s, fieldS2i_i, 42, copy, value);
}

func AuditNameToField(const char *field) bool{
//#ifndef NO_TABLES
	//var res bool
	
	if FlagS2i(field, res) != false
	    return true;
//#endif	    
	return false;
}
*/
