package netlinkAudit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

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
	Buf         byte   //[0]string /* string fields buffer */

}

type NetlinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

type NetlinkAuditRequest struct {
	Header syscall.NlMsghdr
	Data   []byte
}

var ParsedResult AuditStatus

func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

//The recvfrom in go takes only a byte [] to put the data recieved from the kernel that removes the need
//for having a separate audit_reply Struct for recieving data from kernel.
func (rr *NetlinkAuditRequest) ToWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b = append(b[:], rr.Data[:]...)
	return b
}

func newNetlinkAuditRequest(proto, seq, family, sizeofData int) *NetlinkAuditRequest {
	rr := &NetlinkAuditRequest{}

	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + sizeofData)
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	rr.Header.Seq = uint32(seq)
	return rr
	//	return rr.ToWireFormat()
}

// Round the length of a netlink message up to align it properly.
func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

func ParseAuditNetlinkMessage(b []byte) ([]syscall.NetlinkMessage, error) {
	var msgs []syscall.NetlinkMessage
	for len(b) >= syscall.NLMSG_HDRLEN {
		h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
		if err != nil {
			fmt.Println("Error in parsing")
			return nil, err
		}
		m := syscall.NetlinkMessage{Header: *h, Data: dbuf[:int(h.Len)-syscall.NLMSG_HDRLEN]}
		msgs = append(msgs, m)
		b = b[dlen:]
	}
	return msgs, nil
}

func netlinkMessageHeaderAndData(b []byte) (*syscall.NlMsghdr, []byte, int, error) {

	h := (*syscall.NlMsghdr)(unsafe.Pointer(&b[0]))
	if int(h.Len) < syscall.NLMSG_HDRLEN || int(h.Len) > len(b) {
		fmt.Println("Error due to....HDRLEN:", syscall.NLMSG_HDRLEN, " Header Length:", h.Len, " Length of BYTE Array:", len(b))
		return nil, nil, 0, syscall.EINVAL
	}
	return h, b[syscall.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
}

// This function makes a conncetion with kernel space and is to be used for all further socket communication

func GetNetlinkSocket() (*NetlinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT) //connect to the socket of type RAW
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
	//var tab []byte
	//append(tab, rb...)
	return ParseAuditNetlinkMessage(rb) //Or syscall.ParseNetlinkMessage(rb)
}

//func audit_send(socket, proto, Data * struct, sizeof struct)
//func audit_get_reply(socket, proto, Data* struct , block int)
func AuditSend(s *NetlinkSocket, proto int, data []byte, sizedata, seq int) error {

	wb := newNetlinkAuditRequest(proto, seq, syscall.AF_NETLINK, sizedata) //Need to work on sequence
	wb.Data = append(wb.Data[:], data[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}
	return nil
}

func AuditGetReply(s *NetlinkSocket, bytesize, block, seq int) error {
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

				if m.Header.Seq != uint32(seq) || m.Header.Pid != v.Pid {
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
				fmt.Println("NLMSG_ERROR")
				break done
				//return nil
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
			if m.Header.Type == 1009 {
				fmt.Println("Watchlist")
			}

		}
	}
	return nil

}

func AuditSetEnabled(s *NetlinkSocket, seq int) error {
	var status AuditStatus
	status.Enabled = 1
	status.Mask = AUDIT_STATUS_ENABLED
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return err
	}

	AuditSend(s, AUDIT_SET, buff.Bytes(), int(unsafe.Sizeof(status)), seq)
	// Receiving IN JUST ONE TRY
	AuditGetReply(s, syscall.Getpagesize(), 0, seq)
	return nil
}

func AuditIsEnabled(s *NetlinkSocket, seq int) error {
	fmt.Println("Now Sending AUDIT_GET for Checking if Audit is enabled or not \n")
	wb := newNetlinkAuditRequest(AUDIT_GET, seq, syscall.AF_NETLINK, 0)

	if err := s.Send(wb); err != nil {
		return err
	}

done:
	for {
		//Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT) //ParseAuditNetlinkMessage(rb)
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

				if m.Header.Seq != uint32(seq) || m.Header.Pid != v.Pid {
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
				fmt.Println("NLMSG_ERROR\n\n")
			}
			if m.Header.Type == AUDIT_GET {
				//Conversion of the data part written to AuditStatus struct
				//Nil error : successfuly parsed
				b := m.Data[:]
				buf := bytes.NewBuffer(b)
				var dumm AuditStatus
				err = binary.Read(buf, nativeEndian(), &dumm)
				ParsedResult = dumm
				//fmt.Println("\nstruct :", dumm, err)
				//fmt.Println("\nStatus: ", dumm.Enabled)

				fmt.Println("ENABLED")
				break done
			}

		}

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

func AuditAddRuleData(s *NetlinkSocket, rule *AuditRuleData, flags int, action int) error {
	if flags == AUDIT_FILTER_ENTRY {
		fmt.Println("Use of entry filter is deprecated")
		return nil
	}

	rule.flags = (uint32)(flags)
	rule.action = (uint32)(action)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), rule)

	if err != nil {
		fmt.Println("binary.Write failed:", err)
		return err
	}

	seq := 0
	err = AuditSend(s, AUDIT_ADD_RULE, buff.Bytes(), int(unsafe.Sizeof(rule))+int(rule.buflen), seq)
	//rc := syscall.Sendto(fd, AUDIT_ADD_RULE, rule, unsafe.Sizeof(auditstruct) + rule.buflen)
	//rc := syscall.Sendto(fd, rule, AUDIT_ADD_RULE, syscall.Getsockname(fd))
	if err != nil {
		fmt.Println("Error sending add rule data request ()")
		return err
	}
	return err
}

func AuditRuleSyscallData(rule *AuditRuleData, scall int) error {
	word := auditWord(scall)
	bit := auditBit(scall)

	if word >= AUDIT_BITMASK_SIZE-1 {
		fmt.Println("Some error occured")
	}
	rule.mask[word] |= bit
	return nil
}

/* How the file should look like
-- seprate constant, stuct to function
-- have a library function for different things like list all rules etc
-- have a main function like audit_send/get_reply
*/

/* Form of main function
package main

import (
	"fmt"
	"github.com/..../netlinkAudit"
)
func main() {
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		fmt.Println(err)
	}
	defer s.Close()

	netlinkAudit.AuditSetEnabled(s, 1)
	err = netlinkAudit.AuditIsEnabled(s, 2)
	fmt.Println("parsedResult")
	fmt.Println(netlinkAudit.ParsedResult)
	if err == nil {
		fmt.Println("Horrah")
	}

}

*/
