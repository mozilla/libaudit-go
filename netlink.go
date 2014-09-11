package main

import (
	//	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8970
	AUDIT_GET                = 1000
	AUDIT_LIST               = 1002
	AUDIT_LIST_RULES         = 1013
)

/*
#define MAX_AUDIT_MESSAGE_LENGTH    8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1
struct audit_message {
	struct nlmsghdr nlh;
	char   data[MAX_AUDIT_MESSAGE_LENGTH];
};
*/
/*
struct audit_reply {
	int                      type;
	int                      len;
	struct nlmsghdr         *nlh;
	struct audit_message     msg;

	// Using a union to compress this structure since only one of
	 * the following should be valid for any packet. //
	union {
	struct audit_status     *status;
	struct audit_rule_data  *ruledata;
	struct audit_login      *login;
	const char              *message;
	struct nlmsgerr         *error;
	struct audit_sig_info   *signal_info;
	struct daemon_conf      *conf;
#if HAVE_DECL_AUDIT_FEATURE_VERSION
	struct audit_features	*features;
#endif
	};
};

*/
/*
func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
*/

type NetlinkAuditRequest struct {
	Header syscall.NlMsghdr
	Data   string
}

type AuditReply struct {
	RepHeader syscall.NlMsghdr
	Message   NetlinkAuditRequest
}

func (rr *NetlinkAuditRequest) ToWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	//	fmt.Printf("%+v,%+v\n", *(*uint16)(unsafe.Pointer(&b[4:6][0])), rr.Header.Type)
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	//	fmt.Printf("%+v,%+v\n", *(*uint16)(unsafe.Pointer(&b[6:8][0])), rr.Header.Flags)

	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	//b[16] = byte(family)
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
		fmt.Println("Error Here")
		fmt.Println(syscall.NLMSG_HDRLEN, h.Len, h.Len, len(b))
		return nil, nil, 0, syscall.EINVAL
	}
	return h, b[syscall.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
}

/*
Inspired from Docker library

type NetlinkRequest struct {
	syscall.NlMsghdr
	Data []NetlinkRequestData
}

func (rr *NetlinkRequest) ToWireFormat() []byte {
	native := nativeEndian()

	length := rr.Len
	dataBytes := make([][]byte, len(rr.Data))
	for i, data := range rr.Data {
		dataBytes[i] = data.ToWireFormat()
		length += uint32(len(dataBytes[i]))
	}
	b := make([]byte, length)
	native.PutUint32(b[0:4], length)
	native.PutUint16(b[4:6], rr.Type)
	native.PutUint16(b[6:8], rr.Flags)
	native.PutUint32(b[8:12], rr.Seq)
	native.PutUint32(b[12:16], rr.Pid)

	next := 16
	for _, data := range dataBytes {
		copy(b[next:], data)
		next += len(data)
	}
	return b
}

func (rr *NetlinkRequest) AddData(data NetlinkRequestData) {
	if data != nil {
		rr.Data = append(rr.Data, data)
	}
}

func newNetlinkRequest(proto, flags int) *NetlinkRequest {
	return &NetlinkRequest{
		NlMsghdr: syscall.NlMsghdr{
			Len:   uint32(syscall.NLMSG_HDRLEN),
			Type:  uint16(proto),
			Flags: syscall.NLM_F_REQUEST | uint16(flags),
			Seq:   atomic.AddUint32(&nextSeqNr, 1),
		},
	}
}
*/
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
	nr, _, err := syscall.Recvfrom(s.fd, rb, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
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
	//fmt.Printf("Received (Raw)%v\n", sd)
	for i, e := range sd {
		fmt.Println("index ", i)
		//fmt.Println(e.Data[:])
		b := e.Data[:]
		a := (*string)(unsafe.Pointer(&b[0])) //Conversion Success
		fmt.Println(a)
	}
	return ParseAuditNetlinkMessage(rb) //Or syscall.ParseNetlinkMessage(rb)
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

	// done:
	//for {
	//Running for one time only
	/*rb := make([]byte, syscall.Getpagesize())

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
			break //done
		}
		if m.Header.Type == syscall.NLMSG_ERROR {
			//error := int32(native.Uint32(m.Data[0:4]))
			fmt.Println("NLMSG_ERROR")
			return nil, syscall.EINVAL
		}
		if m.Header.Type == AUDIT_GET { //SHORT FOR AUDIT_GET
			fmt.Println("ENABLED")
			break
		}

	}
	//}
	return tab, nil

}

func main() {
	_, er := AuditNetlink(AUDIT_LIST_RULES, syscall.AF_NETLINK)
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
