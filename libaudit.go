package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8960
	AUDIT_GET                = 1000
	AUDIT_SET                = 1001 /* Set status (enable/disable/auditd) */
	AUDIT_LIST               = 1002
	AUDIT_LIST_RULES         = 1013
	AUDIT_FIRST_USER_MSG     = 1100 /* Userspace messages mostly uninteresting to kernel */
	AUDIT_MAX_FIELDS         = 64
	AUDIT_BITMASK_SIZE       = 64
	AUDIT_GET_FEATURE        = 1019
	AUDIT_STATUS_ENABLED     = 0x0001
	AUDIT_FILTER_ENTRY 		 = 0x02
	AUDIT_ADD_RULE           = 1011
	EEXIST                   = 17
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
	flags       uint32
	action      uint32
	field_count uint32
	mask        [AUDIT_BITMASK_SIZE]uint32
	fields      [AUDIT_MAX_FIELDS]uint32
	values      [AUDIT_MAX_FIELDS]uint32
	fieldflags  [AUDIT_MAX_FIELDS]uint32
	buflen      uint32
	buf         [0]string
}

type AuditReply struct {
	Header   syscall.NlMsghdr
	Message  NetlinkAuditRequest
	Type     uint16
	Len      uint32
	RuleData AuditRuleData
}

type NetlinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

type NetlinkAuditRequest struct {
	Header syscall.NlMsghdr
	Data   []byte
}

func auditWord(nr int) uint32{
	audit_word := (uint32)((nr)/32)
	return (uint32)(audit_word)
}

func auditBit(nr int) uint32{ 
	audit_bit := 1 << ((uint32)(nr) - auditWord(nr)*32)
	return (uint32)(audit_bit)
}

func AuditSend(s *NetlinkSocket, proto int, data []byte, sizedata, seq int) error {
	wb := newNetlinkAuditRequest(proto, seq, syscall.AF_NETLINK, sizedata) //Need to work on sequence
	wb.Data = append(wb.Data[:], data[:]...)
	if err := s.Send(wb); err != nil {
		return err
	}
	return nil
}

func AuditAddRuleData(s *NetlinkSocket, rule *AuditRuleData, flags int, action int) error {
	if flags == AUDIT_FILTER_ENTRY {
		fmt.Println("Use of entry filter is deprecated")
	return nil
	}
	
	rule.flags =  (uint32)(flags)
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

func auditRuleSyscallData(rule *AuditRuleData, scall int) error{
	word := auditWord(scall);
	bit  := auditBit(scall);
	
	if word >= AUDIT_BITMASK_SIZE-1 { 
	    fmt.Println("Some error occured")
	}    
    rule.mask[word] |= bit;
       	return nil
}


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
	s.lsa.Pid = 0

	if err := syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return s, nil
}

func (s *NetlinkSocket) Close() {
	syscall.Close(s.fd)
}

func (s *NetlinkSocket) Send(request *NetlinkAuditRequest) error {
	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {

	rb := make([]byte, syscall.Getpagesize()) //Need to be changed
	nr, _, err := syscall.Recvfrom(s.fd, rb, 0)
	//nr, _, err := syscall.Recvfrom(s, rb, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL //ErrShortResponse
	}
	rb = rb[:nr]
	//var tab []byte
	//append(tab, rb...)
	/*
		for i, e := range sd {
			fmt.Println("index ", i)
			//fmt.Println(e.Data[:])
			if len(e.Data) == 0 {
				fmt.Println("0 DATA")
			} else {

				b := e.Data[:]
				//		c := (string)(e.Header)
				for i, _ := range b {
					a := *(*string)(unsafe.Pointer(&b[i]))
					//d := *a
					fmt.Println(a) //Printing EMPTY
				}

			}
		}
	*/
	return ParseAuditNetlinkMessage(rb) //Or syscall.ParseNetlinkMessage(rb)
}

func AuditNetlink(proto, family int) ([]byte, error) {

	s, err := GetNetlinkSocket()

	if err != nil {
		return nil, err
	}

	defer s.Close()

	wb := newNetlinkAuditRequest(proto, 1, family, 0)

	if err := s.Send(wb); err != nil {
		return nil, err
	}

	var tab []byte

done:
	for {
		/*
			rb := make([]byte, syscall.Getpagesize())

			nr, _, err := syscall.Recvfrom(s, rb, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)

			if err != nil {
				fmt.Println("Error on Receiving")
				return nil, err
			}
			if nr < syscall.NLMSG_HDRLEN {
				return nil, syscall.EINVAL
			}
			rb = rb[:nr]
		*/
		//	tab = append(tab, rb...)
		msgs, err := s.Receive() //ParseAuditNetlinkMessage(rb)
		if err != nil {
			fmt.Println("Error in Parsing")
			return nil, err
		}

		for _, m := range msgs {
			lsa, err := syscall.Getsockname(s.fd)
			if err != nil {
				fmt.Println("Error in getting Sockaddr name")
				return nil, err
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:

				if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
					fmt.Println("Messgage sequence or Pid didn't match")
					return nil, syscall.EINVAL
				}
			default:
				fmt.Println("foo4")
				return nil, syscall.EINVAL
				/*
					if m.Header.Seq != wb.seq {
						return fmt.Errorf("Wrong Seq nr %d, expected %d", m.Header.Seq, seq)
					}
					if m.Header.Pid != pid {
						return fmt.Errorf("Wrong pid %d, expected %d", m.Header.Pid, pid)
					}

				*/

			}

			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("Done")
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				//error := int32(native.Uint32(m.Data[0:4]))
				fmt.Println("NLMSG_ERROR")
				return nil, syscall.EINVAL
			}
			if m.Header.Type == AUDIT_GET { //SHORT FOR AUDIT_GET
				fmt.Println("ENABLED")
				fmt.Println(m.Header, m.Data)
				break done
			}
			if m.Header.Type == AUDIT_FIRST_USER_MSG {
				fmt.Println("FFFF")
				break done
			}
			if m.Header.Type == AUDIT_LIST_RULES {
				fmt.Println("WE got RUles")
				fmt.Println(m.Header)
				break done
			}
			if m.Header.Type == AUDIT_FIRST_USER_MSG {
				fmt.Println("HAA")
				break done
			}
			if m.Header.Type == 1009 {
				fmt.Println("Watchlist")
			}

		}
	}
	return tab, nil

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

	wb := newNetlinkAuditRequest(AUDIT_SET, seq, syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data, buff.Bytes()...)

	if err := s.Send(wb); err != nil {
		return err
	}
	/*
		rb := make([]byte, syscall.Getpagesize()) //This is an important Part.

		nr, _, err := syscall.Recvfrom(s.fd, rb, 0)

		if err != nil {
			return err
		}

		if nr < syscall.NLMSG_HDRLEN {
			return syscall.EINVAL //ErrShortResponse
		}

		rb = rb[:nr]
	*/
	// Receiving IN JUST ONE TRY
done:
	for {
		msgs, err := s.Receive() //ParseAuditNetlinkMessage(rb)
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

				if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
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
				//NLMSG_ERR means everything is Fine ?? AUDITD says so netlink.c L283
				fmt.Println("NLMSG_ERROR")
				break done
			}
			if m.Header.Type == AUDIT_GET {
				fmt.Println("ENABLED")
				break done

			}

		}

	}
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
		rb := make([]byte, MAX_AUDIT_MESSAGE_LENGTH)
		nr, _, err := syscall.Recvfrom(s.fd, rb, 0|syscall.MSG_DONTWAIT) //The | here matters as we are receiving multiple messages

		if err != nil {
			return err
		}

		if nr < syscall.NLMSG_HDRLEN {
			return syscall.EINVAL //ErrShortResponse
		}

		rb = rb[:nr]
		fmt.Println(rb, nr)

		msgs, er := ParseAuditNetlinkMessage(rb)
		if er != nil {
			return er
		}
		//fmt.Println(sd)

		for _, m := range msgs {
			lsa, er := syscall.Getsockname(s.fd)
			if er != nil {
				return nil
			}
			switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:

				if m.Header.Seq != 2 || m.Header.Pid != v.Pid {
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
				//Here conversion of the data part written to audit_status Structure
				//Nil error means successfuly parsed
				b := m.Data[:]
				buf := bytes.NewBuffer(b)
				var dumm AuditStatus
				err = binary.Read(buf, nativeEndian(), &dumm)
				fmt.Println("\nstruct :", dumm, err)
				fmt.Println("\nStatus: ", dumm.Enabled)

				fmt.Println("ENABLED")
				break done
			}

		}

	}
	return nil

}

/* How the file should look like
-- seprate constant, stuct to function
-- have a library function for different things like list all rules etc
-- have a main function like audit_send/get_reply
*/
func main() {
	s, err := GetNetlinkSocket()
	if err != nil {
		fmt.Println(err)
	}
	defer s.Close()

	AuditSetEnabled(s, 1)
	err = AuditIsEnabled(s, 2)
	if err == nil {
		fmt.Println("Horrah")
	}

}

/*
	_, er := AuditNetlink(AUDIT_GET, syscall.AF_NETLINK)
	//Types are defined in /usr/include/linux/audit.h
	//See https://www.redhat.com/archives/linux-audit/2011-January/msg00030.html
	if er != nil {
		fmt.Println("Got error on last")

		//fmt.Println(er)
	} else {
		//str := string(v[:])
		fmt.Println("Sucess!")
	}
*/
