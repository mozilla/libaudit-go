package netlinkAudit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var ParsedResult AuditStatus
var nextSeqNr uint32
var rulesRetrieved AuditRuleData

type AuditStatus struct {
	Mask          uint32 /* Bit mask for valid entries */
	Enabled       uint32 /* 1 = enabled, 0 = disabled */
	Failure       uint32 /* Failure-to-log action */
	Pid           uint32 /* pid of auditd process */
	Rate_limit    uint32 /* messages rate limit (per second) */
	Backlog_limit uint32 /* waiting messages limit */
	Lost          uint32 /* messages lost */
	Backlog       uint32 /* messages waiting in queue */
}

type AuditRuleData struct {
	Flags       uint32 /* AUDIT_PER_{TASK,CALL}, AUDIT_PREPEND */
	Action      uint32 /* AUDIT_NEVER, AUDIT_POSSIBLE, AUDIT_ALWAYS */
	Field_count uint32
	Mask        [AUDIT_BITMASK_SIZE]uint32 /* syscall(s) affected */
	Fields      [AUDIT_MAX_FIELDS]uint32
	Values      [AUDIT_MAX_FIELDS]uint32
	Fieldflags  [AUDIT_MAX_FIELDS]uint32
	Buflen      uint32 /* total length of string fields */
	Buf         []byte //[0]byte /* string fields buffer */
}

type NetlinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

type NetlinkAuditRequest struct {
	Header syscall.NlMsghdr
	Data   []byte
}

// for config
type CMap struct {
	Name string
	Id   int
}

//for fieldtab
type FMap struct {
	Name    string
	Fieldid float64
}

// for config
type Config struct {
	Xmap []CMap
}

type Field struct {
	Fieldmap []FMap
}

func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

func (rule *AuditRuleData) ToWireFormat() []byte {

	newbuff := make([]byte, int(unsafe.Sizeof(*rule))+int(rule.Buflen))
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

//recvfrom in go takes only a byte [] to put the data recieved from the kernel that removes the need
//for having a separate audit_reply Struct for recieving data from kernel.
func (rr *NetlinkAuditRequest) ToWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b = append(b[:16], rr.Data[:]...) //Important b[:16]
	return b
}

func newNetlinkAuditRequest(proto, family, sizeofData int) *NetlinkAuditRequest {
	rr := &NetlinkAuditRequest{}

	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + sizeofData)
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	rr.Header.Seq = atomic.AddUint32(&nextSeqNr, 1) //Autoincrementing Sequence
	return rr
	//	return rr.ToWireFormat()
}

// Round the length of a netlink message up to align it properly.
func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

// Parse a byte stream to an array of NetlinkMessage structs
func ParseAuditNetlinkMessage(b []byte) ([]syscall.NetlinkMessage, error) {

	var msgs []syscall.NetlinkMessage
	h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
	if err != nil {
		log.Println("Error in parsing")
		return nil, err
	}

	m := syscall.NetlinkMessage{Header: *h, Data: dbuf[:int(h.Len) /* -syscall.NLMSG_HDRLEN*/]}
	msgs = append(msgs, m)
	b = b[dlen:]

	return msgs, nil
}

// Internal Function, uses unsafe pointer conversions for separating Netlink Header and the Data appended with it
func netlinkMessageHeaderAndData(b []byte) (*syscall.NlMsghdr, []byte, int, error) {

	h := (*syscall.NlMsghdr)(unsafe.Pointer(&b[0]))
	if int(h.Len) < syscall.NLMSG_HDRLEN || int(h.Len) > len(b) {
		foo := int32(nativeEndian().Uint32(b[0:4]))
		log.Println("Headerlength with ", foo, b[0]) //bug!
		log.Println("Error due to....HDRLEN:", syscall.NLMSG_HDRLEN, " Header Length:", h.Len, " Length of BYTE Array:", len(b))
		return nil, nil, 0, syscall.EINVAL
	}
	return h, b[syscall.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
}

//Connect with kernel space and is to be used for all further socket communication
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

// Wrapper for Sendto
func (s *NetlinkSocket) Send(request *NetlinkAuditRequest) error {
	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

// Wrapper for Recvfrom
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

//HandleAck ?
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
					log.Println("Acknowledged!!")
					break done
				} else {
					log.Println("NLMSG_ERROR Received..")
				}
				break done
			}
			if m.Header.Type == AUDIT_GET {
				log.Println("AUDIT_GET")
				break done
			}
		}
	}
	return nil
}

// Sends a message to kernel to turn on audit
func AuditSetEnabled(s *NetlinkSocket) error {
	var status AuditStatus
	status.Enabled = 1
	status.Mask = AUDIT_STATUS_ENABLED
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		log.Println("binary.Write failed:", err)
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

// Sends a signal to kernel to check if Audit is enabled
func AuditIsEnabled(s *NetlinkSocket) error {
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
				if m.Header.Seq != uint32(wb.Header.Seq) {
					return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
				}

			default:
				return syscall.EINVAL
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				log.Println("Done")
				break done

			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				log.Println("NLMSG_ERROR Received..")
			}
			if m.Header.Type == AUDIT_GET {
				//Convert the data part written to AuditStatus struct
				b := m.Data[:]
				// h := (*AuditStatus)(unsafe.Pointer(&b[0])) Unsafe Method avoided
				buf := bytes.NewBuffer(b)
				var dumm AuditStatus
				err = binary.Read(buf, nativeEndian(), &dumm)
				if err != nil {
					log.Println("binary.Read failed:", err)
					return err
				}
				ParsedResult = dumm
				break done
			}
		}
	}
	return nil
}

// Sends a message to kernel for setting of program pid
func AuditSetPid(s *NetlinkSocket, pid uint32 /*,Wait mode WAIT_YES | WAIT_NO */) error {
	var status AuditStatus
	status.Mask = AUDIT_STATUS_PID
	status.Pid = pid
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		log.Println("binary.Write failed:", err)
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

/*
Requires More work
func AuditWatchRuleData(s *NetlinkSocket, rule *AuditRuleData, path []byte) error {
	rule.Flags = uint32(AUDIT_FILTER_EXIT)
	rule.Action = uint32(AUDIT_ALWAYS)
	// set mask
	rule.Field_count = uint32(2)
	rule.Fields[0] = uint32(105)
	rule.Values[0] = uint32(len(path))
	rule.Fieldflags[0] = uint32(AUDIT_EQUAL)
	rule.Buflen = uint32(len(path))
	rule.Buf = append(rule.Buf[:], path[:]...)

	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), *rule)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(AUDIT_ADD_RULE, syscall.AF_NETLINK, int(buff.Len())+int(rule.Buflen))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}

	return nil
}
*/
func AuditSetRateLimit(s *NetlinkSocket, limit int) error {
	var foo AuditStatus
	foo.Mask = AUDIT_STATUS_RATE_LIMIT
	foo.Rate_limit = (uint32)(limit)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), foo)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(AUDIT_SET, syscall.AF_NETLINK, int(unsafe.Sizeof(foo)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}

	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return err
	}
	return nil

}

func AuditSetBacklogLimit(s *NetlinkSocket, limit int) error {
	var foo AuditStatus
	foo.Mask = AUDIT_STATUS_BACKLOG_LIMIT
	foo.Backlog_limit = (uint32)(limit)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), foo)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(AUDIT_SET, syscall.AF_NETLINK, int(unsafe.Sizeof(foo)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}

	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return err
	}
	return nil

}

var errEntryDep = errors.New("Use of entry filter is deprecated")

func AuditAddRuleData(s *NetlinkSocket, rule *AuditRuleData, flags int, action int) error {

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

	newwb := newNetlinkAuditRequest(AUDIT_ADD_RULE, syscall.AF_NETLINK, len(newbuff) /*+int(rule.Buflen)*/) //Length of newbuff takes care of Rule.buf too
	newwb.Data = append(newwb.Data[:], newbuff[:]...)
	var err error
	if err = s.Send(newwb); err != nil {
		return err
	}

	if err != nil {
		log.Println("Error sending add rule data request")
		return err
	}
	return nil
}
func isDone(msgchan chan string, errchan chan error, done <-chan bool) bool {
	var d bool
	select {
	case d = <-done:
		close(msgchan)
		close(errchan)
	default:
	}
	return d
}

//For Debugging Purposes
func GetreplyWithoutSync(s *NetlinkSocket) {
	f, err := os.OpenFile("log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		log.Println("Error Creating File!!")
		return
	}
	defer f.Close()
	for {
		rb := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
		nr, _, err := syscall.Recvfrom(s.fd, rb, 0)
		if err != nil {
			log.Println("Error While Recieving !!")
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			log.Println("Message Too Short!!")
			continue
		}

		rb = rb[:nr]
		msgs, err := ParseAuditNetlinkMessage(rb)

		if err != nil {
			log.Println("Not Parsed Successfuly !!")
			continue
		}
		for _, m := range msgs {
			//Decide on various message Types
			if m.Header.Type == syscall.NLMSG_DONE {
				log.Println("Done")
			} else if m.Header.Type == syscall.NLMSG_ERROR {
				err := int32(nativeEndian().Uint32(m.Data[0:4]))
				if err == 0 {
					//Acknowledgement from kernel
					log.Println("Ack")
				} else {
					log.Println("NLMSG_ERROR...")
				}
			} else if m.Header.Type == AUDIT_GET {
				log.Println("AUDIT_GET")
			} else if m.Header.Type == AUDIT_FIRST_USER_MSG {
				log.Println("AUDIT_FIRST_USER_MSG")
			} else if m.Header.Type == AUDIT_SYSCALL {
				log.Println("Syscall Event")
				log.Println(string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}
			} else if m.Header.Type == AUDIT_CWD {
				log.Println("CWD Event")
				log.Println(string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}

			} else if m.Header.Type == AUDIT_PATH {
				log.Println("Path Event")
				log.Println(string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}

			} else if m.Header.Type == AUDIT_EOE {
				log.Println("Event Ends ", string(m.Data[:]))
			} else if m.Header.Type == AUDIT_CONFIG_CHANGE {
				log.Println("Config Change ", string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}
			} else {
				log.Println("Unknown: ", m.Header.Type)
			}
		}
	}
}

// Receives messages from Kernel and forwards to channels
func Getreply(s *NetlinkSocket, done <-chan bool, msgchan chan string, errchan chan error) {
	for {
		rb := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
		nr, _, err := syscall.Recvfrom(s.fd, rb, 0)
		if isDone(msgchan, errchan, done) {
			return
		}
		if err != nil {
			log.Println("Error While Recieving !!")
			errchan <- err
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			log.Println("Message Too Short!!")
			errchan <- syscall.EINVAL
			continue
		}

		rb = rb[:nr]
		msgs, err := ParseAuditNetlinkMessage(rb)

		if err != nil {
			log.Println("Not Parsed Successfuly !!")
			errchan <- err
			continue
		}
		for _, m := range msgs {
			//Decide on various message Types
			//Add more message Types
			if m.Header.Type == syscall.NLMSG_DONE {
				log.Println("Done")
			} else if m.Header.Type == syscall.NLMSG_ERROR {
				err := int32(nativeEndian().Uint32(m.Data[0:4]))
				if err == 0 {
					//Acknowledgement from kernel
					log.Println("Ack")
				} else {
					log.Println("NLMSG_ERROR")
				}
			} else if m.Header.Type == AUDIT_GET {
				log.Println("AUDIT_GET")
			} else if m.Header.Type == AUDIT_FIRST_USER_MSG {
				log.Println("AUDIT_FIRST_USER_MSG")
			} else if m.Header.Type == AUDIT_SYSCALL {
				msgchan <- ("type=SYSCALL " + "msg=" + string(m.Data[:]))
			} else if m.Header.Type == AUDIT_CWD {
				msgchan <- ("type=CWD " + "msg=" + string(m.Data[:]))
			} else if m.Header.Type == AUDIT_PATH {
				msgchan <- ("type=PATH " + "msg=" + string(m.Data[:]))
			} else if m.Header.Type == AUDIT_EOE {
				// log.Println("Event Ends ", string(m.Data[:]))
			} else if m.Header.Type == AUDIT_CONFIG_CHANGE {
				msgchan <- ("type=CONFIG_CHANGE " + "msg=" + string(m.Data[:]))
			} else {
				log.Println("Unknown: ", m.Header.Type)
			}
		}
	}

}

/*
// List all rules
// TODO: this funcion needs a lot of work to print actual rules
func ListAllRules(s *NetlinkSocket) error {
	wb := newNetlinkAuditRequest(AUDIT_LIST_RULES, syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		log.Print("Error:", err)
		return err
	}

done:
	for {
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		if err != nil {
			log.Println("ERROR while receiving rules:", err)
			return err
		}

		for _, m := range msgs {
			lsa, er := syscall.Getsockname(s.fd)
			if er != nil {
				log.Println("ERROR:", er)
				return err
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) {
					return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
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
			if m.Header.Type == AUDIT_LIST_RULES {
				b := m.Data[:]
				//Should revert to rule.ToWireFormat()
				buf := bytes.NewBuffer(b)
				var rules AuditRuleData
				rules.Buf = make([]byte, 0)
				err = binary.Read(buf, nativeEndian(), &rules)
				if err != nil {
					log.Println("binary.Read failed:", err)
					return err
				}
				// TODO : save all rules to an array so delete all rules function can use this
				rulesRetrieved = rules
			}
		}
	}
}
*/

//Delete Rule Data Function
func AuditDeleteRuleData(s *NetlinkSocket, rule *AuditRuleData, flags uint32, action uint32) error {
	var sizePurpose AuditRuleData
	sizePurpose.Buf = make([]byte, 0)
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

	newwb := newNetlinkAuditRequest(AUDIT_DEL_RULE, syscall.AF_NETLINK, len(newbuff) /*+int(rule.Buflen)*/)
	newwb.Data = append(newwb.Data[:], newbuff[:]...)
	if err := s.Send(newwb); err != nil {
		return err
	}
	return nil
}

// This function Deletes all rules
func DeleteAllRules(s *NetlinkSocket) error {
	wb := newNetlinkAuditRequest(AUDIT_LIST_RULES, syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		log.Print("Error:", err)
		return err
	}

done:
	for {
		//Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		if err != nil {
			log.Println("ERROR while receiving rules:", err)
			return err
		}

		for _, m := range msgs {
			lsa, er := syscall.Getsockname(s.fd)
			if er != nil {
				log.Println("ERROR:", er)
				return er
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) {
					return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
				}
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				log.Println("Deleting Done!")
				break done

			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				log.Println("NLMSG_ERROR\n")
			}
			if m.Header.Type == AUDIT_LIST_RULES {
				b := m.Data[:]
				rules := (*AuditRuleData)(unsafe.Pointer(&b[0]))
				//Sizeof rules is 1064 > 1056
				//Error handling here ?
				// log.Println(len(b), h)
				// buf := bytes.NewBuffer(b)
				// var rules AuditRuleData
				// rules.Buf = make([]byte, 0)
				// err = binary.Read(buf, nativeEndian(), &rules)
				// if err != nil {
				// 	log.Println("Binary Read Failed !!", err)
				// 	return err
				// }
				err = AuditDeleteRuleData(s, rules, rules.Flags, rules.Action)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

var _audit_permadded bool
var _audit_syscalladded bool

// Load x86 map and fieldtab.json
func loadSysMap_FieldTab(conf *Config, fieldmap *Field) error {
	content2, err := ioutil.ReadFile("netlinkAudit/audit_x86_64.json")
	if err != nil {
		return err
	}
	content3, err := ioutil.ReadFile("netlinkAudit/fieldtab.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal([]byte(content2), &conf)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(content3), &fieldmap)
	if err != nil {
		return err
	}

	return nil
}

//sets each rule after reading configuration file
func SetRules(s *NetlinkSocket) error {

	//var rule AuditRuleData
	//AuditWatchRuleData(s, &rule, []byte("/etc/passwd"))

	// Load all rules
	content, err := ioutil.ReadFile("netlinkAudit/audit.rules.json")
	if err != nil {
		log.Print("Error:", err)
		return err
	}

	var rules interface{}
	err = json.Unmarshal(content, &rules)
	if err != nil {
		log.Print("Error:", err)
		return err
	}

	m := rules.(map[string]interface{})

	if _, ok := m["delete"]; ok {
		//First Delete All rules and then add rules
		log.Println("Deleting all rules")
		err := DeleteAllRules(s)
		if err != nil {
			log.Println("Error Deleting Rules!")
			return err
		}
	}
	var conf Config
	var fieldmap Field

	// Load x86 map and fieldtab.json
	err = loadSysMap_FieldTab(&conf, &fieldmap)
	if err != nil {
		log.Println("Error :", err)
		return err
	}

	for k, v := range m {
		switch k {
		case "custom_rule":
			// Still Needed ?
			vi := v.([]interface{})
			for ruleNo := range vi {
				rule := vi[ruleNo].(map[string]interface{})
				for l, m := range rule {
					switch l {
					case "action":
						//TODO: handle actions case here
						action := m.([]interface{})
						log.Println("actions are : ", action[0])
					case "fields":
						//TODO: handle fields case here
						fields := m.([]interface{})
						for _, q := range fields {
							log.Println("fields are", q)
						}
					}
				}
			}
		case "syscall_rules":
			vi := v.([]interface{})
			for sruleNo := range vi {
				srule := vi[sruleNo].(map[string]interface{})

				for l := range conf.Xmap {
					if conf.Xmap[l].Name == srule["name"] {
						// set rules
						log.Println("setting syscall rule", conf.Xmap[l].Name)
						var dd AuditRuleData
						dd.Buf = make([]byte, 0)

						err = AuditRuleSyscallData(&dd, conf.Xmap[l].Id)
						if err == nil {
							_audit_syscalladded = true
						} else {
							return err
						}
						actions := srule["action"].([]interface{})
						//log.Println(actions)

						//NOW APPLY ACTIONS ON SYSCALLS by separating the filters i.e exit from action i.e. always
						action := 0
						filter := 0
						//This part supposes that actions and filters are written as always,exit or never,exit not viceversa
						if actions[0] == "never" {
							action = AUDIT_NEVER
						} else if actions[0] == "possible" {
							action = AUDIT_POSSIBLE
						} else if actions[0] == "always" {
							action = AUDIT_ALWAYS
						} else {
							action = -1
						}

						if actions[1] == "task" {
							filter = AUDIT_FILTER_TASK
						} else if actions[1] == "entry" {
							log.Println("Support for Entry Filter is Deprecated!! Switching back to Exit filter")
							filter = AUDIT_FILTER_EXIT
						} else if actions[1] == "exit" {
							filter = AUDIT_FILTER_EXIT
						} else if actions[1] == "user" {
							filter = AUDIT_FILTER_USER
						} else if actions[1] == "exclude" {
							filter = AUDIT_FILTER_EXCLUDE
						} else {
							filter = AUDIT_FILTER_UNSET
						}

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

						// foo.Fields[foo.Field_count] = AUDIT_ARCH
						// foo.Fieldflags[foo.Field_count] = AUDIT_EQUAL
						// foo.Values[foo.Field_count] = AUDIT_ARCH_X86_64
						// foo.Field_count++
						// AuditAddRuleData(s, &foo, AUDIT_FILTER_EXIT, AUDIT_ALWAYS)

						if filter != AUDIT_FILTER_UNSET {
							AuditAddRuleData(s, &dd, filter, action)
						} else {
							return fmt.Errorf("Filters Not Set")
						}

					}
				}
			}
		}
	}
	return nil
}

func AuditNameToFtype(name string, value *int) error {

	content, err := ioutil.ReadFile("netlinkAudit/ftypetab.json")

	if err != nil {
		log.Print("Error:", err)
		return err
	}

	var filemap interface{}
	err = json.Unmarshal(content, &filemap)

	if err != nil {
		log.Print("Error:", err)
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
		log.Println("Max Fields Exceeded !!")
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

	log.Println("Going for", fieldname)
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
				log.Println("No support for string values yet !", val)
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
			log.Println("No support for string values yet !", val)
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
			log.Println("No support for string values yet !", val)
			return errNoStr
		} else {
			log.Println("Error Setting Value:", fieldval)
			return errUnset
		}

		//TODO: String handling part
		//else {
		//	rule->values[rule->field_count] = //SEE HERE
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
			log.Println("No support for string values yet !", val)
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
		//IF And only if a syscall is added or a permisission is added then this field should be set
		//MORE Debugging Required
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
			//AUDIT_ARCH_X86_64 is made specifically for Mozilla Heka purpose, please make changes as per required
			if _, isInt := fieldval.(float64); isInt {
				rule.Values[rule.Field_count] = AUDIT_ARCH_X86_64
			} else if _, isString := fieldval.(string); isString {
				return errNoStr
			} else {
				return errUnset
			}
		}

	case AUDIT_PERM:
		//DECIDE ON VARIOUS ERROR TYPES
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

/*
If further needed
var ErrStrings = []string{"E2BIG", "EACCES", "EADDRINUSE", "EADDRNOTAVAIL", "EADV", "EAFNOSUPPORT", "EAGAIN", "EALREADY", "EBADE", "EBADF",
	"EBADFD", "EBADMSG", "EBADR", "EBADRQC", "EBADSLT", "EBFONT", "EBUSY", "ECANCELED", "ECHILD", "ECHRNG",
	"ECOMM", "ECONNABORTED", "ECONNREFUSED", "ECONNRESET", "EDEADLK", "EDEADLOCK", "EDESTADDRREQ", "EDOM", "EDOTDOT", "EDQUOT",
	"EEXIST", "EFAULT", "EFBIG", "EHOSTDOWN", "EHOSTUNREACH", "EIDRM", "EILSEQ", "EINPROGRESS", "EINTR", "EINVAL",
	"EIO", "EISCONN", "EISDIR", "EISNAM", "EKEYEXPIRED", "EKEYREJECTED", "EKEYREVOKED", "EL2HLT", "EL2NSYNC", "EL3HLT",
	"EL3RST", "ELIBACC", "ELIBBAD", "ELIBEXEC", "ELIBMAX", "ELIBSCN", "ELNRNG", "ELOOP", "EMEDIUMTYPE", "EMFILE",
	"EMLINK", "EMSGSIZE", "EMULTIHOP", "ENAMETOOLONG", "ENAVAIL", "ENETDOWN", "ENETRESET", "ENETUNREACH", "ENFILE", "ENOANO",
	"ENOBUFS", "ENOCSI", "ENODATA", "ENODEV", "ENOENT", "ENOEXEC", "ENOKEY", "ENOLCK", "ENOLINK", "ENOMEDIUM",
	"ENOMEM", "ENOMSG", "ENONET", "ENOPKG", "ENOPROTOOPT", "ENOSPC", "ENOSR", "ENOSTR", "ENOSYS", "ENOTBLK",
	"ENOTCONN", "ENOTDIR", "ENOTEMPTY", "ENOTNAM", "ENOTRECOVERABLE", "ENOTSOCK", "ENOTTY", "ENOTUNIQ", "ENXIO", "EOPNOTSUPP",
	"EOVERFLOW", "EOWNERDEAD", "EPERM", "EPFNOSUPPORT", "EPIPE", "EPROTO", "EPROTONOSUPPORT", "EPROTOTYPE", "ERANGE", "EREMCHG",
	"EREMOTE", "EREMOTEIO", "ERESTART", "EROFS", "ESHUTDOWN", "ESOCKTNOSUPPORT", "ESPIPE", "ESRCH", "ESRMNT", "ESTALE",
	"ESTRPIPE", "ETIME", "ETIMEDOUT", "ETOOMANYREFS", "ETXTBSY", "EUCLEAN", "EUNATCH", "EUSERS", "EWOULDBLOCK", "EXDEV",
	"EXFULL"}

var ErrS2iI = []int{7, 13, 98, 99, 68, 97, 11, 114, 52, 9, 77, 74, 53, 56, 57, 59, 16, 125, 10, 44, 70, 103, 111, 104, 35, 35, 89, 33, 73, 122, 17, 14, 27, 112, 113, 43, 84, 115, 4, 22,
	5, 106, 21, 120, 127, 129, 128, 51, 45, 46, 47, 79, 80, 83, 82, 81, 48, 40, 124, 24, 31, 90, 72, 36, 119, 100, 102, 101, 23, 55, 105, 50, 61, 19, 2, 8, 126, 37, 67, 123, 12, 42, 64, 65, 92, 28, 63, 60, 38, 15,
	107, 20, 39, 118, 131, 88, 25, 76, 6, 95, 75, 130, 1, 96, 32, 71, 93, 91, 34, 78, 66, 121, 85, 30, 108, 94, 29, 3, 69, 116, 86, 62, 110, 109, 26, 117, 49, 87, 11, 18, 54}

var audit_elf uint = 0
*/
