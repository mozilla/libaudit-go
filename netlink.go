package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8970
	AUDIT_GET                = 1000
	AUDIT_SET                = 1001 /* Set status (enable/disable/auditd) */
	AUDIT_LIST               = 1002
	AUDIT_LIST_RULES         = 1013
	AUDIT_FIRST_USER_MSG     = 1100 /* Userspace messages mostly uninteresting to kernel */
	AUDIT_MAX_FIELDS         = 64
	AUDIT_BITMASK_SIZE       = 64
	AUDIT_GET_FEATURE        = 1019
	AUDIT_STATUS_ENABLED     = 0x0001
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

func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

type NetlinkAuditRequest struct {
	Header syscall.NlMsghdr
	Data   []byte
}

//The recvfrom in go takes only a byte [] to put the data recieved from the kernel that removes the need
//for having a separate audit_reply Struct for recieving data from kernel.
func (rr *NetlinkAuditRequest) ToWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	//	fmt.Printf("%+v,%+v\n", *(*uint16)(unsafe.Pointer(&b[4:6][0])), rr.Header.Type)
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	//	fmt.Printf("%+v,%+v\n", *(*uint16)(unsafe.Pointer(&b[6:8][0])), rr.Header.Flags)

	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	//append(b[:],rr.Data[:])
	//b[16:] = rr.Data[:]
	b = append(b[:], rr.Data[:]...) //Is this correct ?
	fmt.Println(b)
	return b
}

func newNetlinkAuditRequest(proto, seq, family int) *NetlinkAuditRequest {
	rr := &NetlinkAuditRequest{}

	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN) //
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = syscall.NLM_F_REQUEST
	rr.Header.Seq = uint32(seq)
	return rr
	//	return rr.ToWireFormat()
}

type AuditReply struct {
	Header   syscall.NlMsghdr
	Message  NetlinkAuditRequest
	Type     uint16
	Len      uint32
	RuleData AuditRuleData
}

/*
func ParseAuditNetlinkReply(b []byte) ([]AuditReply, error) {
	var msgs []AuditReply
	for len(b) >= syscall.NLMSG_HDRLEN {
		h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
		if err != nil {
			fmt.Println("Error in parse")
			return nil, err
		}
		v := NetlinkAuditRequest{Header: *h, Data: dbuf[:int(h.Len)-syscall.NLMSG_HDRLEN]}
		m := AuditReply{Type: h.Type, Len: h.Len, Header: *h,
			Message: v,
		}
		msgs = append(msgs, m)
		b = b[dlen:]
	}
	return msgs, nil
}
*/
// Round the length of a netlink message up to align it properly.
func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

func ParseAuditNetlinkMessage(b []byte) ([]syscall.NetlinkMessage, error) {
	var msgs []syscall.NetlinkMessage
	for len(b) >= syscall.NLMSG_HDRLEN {
		h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
		if err != nil {
			fmt.Println("Error in parse")
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
		fmt.Println(syscall.NLMSG_HDRLEN, h.Len, h.Len, len(b))
		return nil, nil, 0, syscall.EINVAL
	}
	return h, b[syscall.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
}

type NetlinkSocket struct {
	fd  int
	lsa syscall.SockaddrNetlink
}

func getNetlinkSocket() (*NetlinkSocket, error) {
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
	//fmt.Printf("Sent(Raw) %+v\n", wb)
	//Sending the request to kernel

	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.lsa); err != nil {
		return err
	}
	return nil
}

func (s *NetlinkSocket) Receive() ([]syscall.NetlinkMessage, error) {
	rb := make([]byte, syscall.Getpagesize())
	//rb := NetlinkAuditRequest{}
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
	//	fmt.Printf("Received (Raw)%v\n", rb)
	sd, _ := syscall.ParseNetlinkMessage(rb)
	fmt.Println(sd[0].Header.Type)

	//fmt.Printf("Received (Raw)%v\n", sd)
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
			//TO DO GET LIST DATA FROM KERNEL audit_rule_data ???
			//Represent the value in hex form
			//}
			//		a := (*string)(unsafe.Pointer(&b[0]))
			//		c := (*string)(unsafe.Pointer(&b[1])) //Conversion Success

		}
	*/
	/*
		on, _ := ParseAuditNetlinkReply(rb)
		for i, e := range on {
			fmt.Println("index", i)
			if len(e.Message.Data) == 0 {
				fmt.Println("FOOF DATA", e.Header)
			} else {
				b := e.Message.Data[:]
				//for i, _ := range b {
				a := (*string)(unsafe.Pointer(&b[0]))
				//d := *a
				fmt.Println(a)

			}

		}
	*/
	return ParseAuditNetlinkMessage(rb) //Or syscall.ParseNetlinkMessage(rb)
}
func Send_audit_set() ([]byte, error) {
	s, err := getNetlinkSocket()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	var status AuditStatus
	status.Enabled = 1
	status.Mask = AUDIT_STATUS_ENABLED
	buff := new(bytes.Buffer)
	err = binary.Write(buff, nativeEndian(), status)
	fmt.Println(buff.Bytes())
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	/*
		Just Checking
			buf := bytes.NewBuffer(buff.Bytes())
			var dumm AuditStatus
			err = binary.Read(buf, nativeEndian(), &dumm)
			fmt.Println(dumm, err)
	*/
	wb := newNetlinkAuditRequest(AUDIT_SET, 1, syscall.AF_NETLINK)
	wb.Data = append(wb.Data, buff.Bytes()...)
	fmt.Println(wb)
	if err := s.Send(wb); err != nil {
		return nil, err
	}

	rb := make([]byte, syscall.Getpagesize())

	nr, _, err := syscall.Recvfrom(s.fd, rb, 0)

	if err != nil {
		return nil, err
	}

	if nr < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL //ErrShortResponse
	}

	rb = rb[:nr]
done:
	for {
		sd, _ := syscall.ParseNetlinkMessage(rb)
		fmt.Println(sd)

		fmt.Println(sd[0].Header.Type)
		if sd[0].Header.Type == syscall.NLMSG_DONE {
			fmt.Println("Done")

		}
		if sd[0].Header.Type == syscall.NLMSG_ERROR {
			//error := int32(native.Uint32(m.Data[0:4]))
			//Can NLMSG_ERR means everything is Fine ?? AUDITD says so netlink.c L283
			fmt.Println("NLMSG_ERROR")
			return nil, syscall.EINVAL
		}
		if sd[0].Header.Type == AUDIT_GET { //SHORT FOR AUDIT_GET
			fmt.Println("ENABLED")
			break done
			//	fmt.Println(m.Header, m.Data)

		}

	}
	return nil, nil
}
func AuditNetlink(proto, family int) ([]byte, error) {
	//native := nativeEndian()
	s, err := getNetlinkSocket()

	if err != nil {
		return nil, err
	}

	defer s.Close()

	wb := newNetlinkAuditRequest(proto, 1, family)

	if err := s.Send(wb); err != nil {
		return nil, err
	}

	/*
		if err := syscall.Sendto(s, wb, 0, lsa); err != nil {
			return nil, err
		}
	*/
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

func main() {

	_, sd := Send_audit_set()
	if sd == nil {
		fmt.Println("Horrah")
	}
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

	//	NetLinkListener()
}

/*
	Problems
	1. Sending Data Format Incompatibility with the C version Lack of working examples
	2. Parsing is a big Problem. What is unsafe.Pointer What its purpose ?
	3. Successful Parse still not done
	5. Recieved messages are empty or some sort of signal
	6. Working of Audit (not auditd) behind the scenes
	7. What type of Responses Kernel Sent ? Convert it to what ? byte ==> string or uint16,uint32
*/
