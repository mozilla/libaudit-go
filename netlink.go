package main

import (
	//	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MAX_AUDIT_MESSAGE_LENGTH = 8970
)

/*
#define MAX_AUDIT_MESSAGE_LENGTH    8970 // PATH_MAX*2+CONTEXT_SIZE*2+11+256+1
struct audit_message {
	struct nlmsghdr nlh;
	char   data[MAX_AUDIT_MESSAGE_LENGTH];
};
*/
/*
type AuditMessage struct {
	Mesg   []byte
	Family uint8
}
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
type netlinkAuditRequest struct {
	Header syscall.NlMsghdr
	Data   byte
}

/*
func (rr *netlinkAuditRequest) toWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b[16] = byte(rr.Data.Family)
	return b
}
*/

func newNetlinkAuditRequest(proto, seq, family int) []byte {
	rr := &netlinkAuditRequest{}

	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN) //
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = syscall.NLM_F_REQUEST
	rr.Header.Seq = uint32(seq)
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

// Round the length of a netlink message up to align it properly.
func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

/*
func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
*/
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

func newNetlink(proto, family int) ([]byte, error) {
	//native := nativeEndian()
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(s)
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK, Pid: 0, Groups: 0}
	if err := syscall.Bind(s, lsa); err != nil {
		return nil, err
	}

	wb := newNetlinkAuditRequest(proto, 1, family)
	//Sending the request to kernel

	//fmt.Printf("Sent(Raw) %+v\n", wb)
	if err := syscall.Sendto(s, wb, 0, lsa); err != nil {
		return nil, err
	}
	var tab []byte
	// done:
	//for {
	//Running for one time only
	rb := make([]byte, syscall.Getpagesize())

	nr, _, err := syscall.Recvfrom(s, rb, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
	//		fmt.Printf("%v\n", nr)

	if err != nil {
		fmt.Println("Error on Receiving")
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, syscall.EINVAL
	}
	rb = rb[:nr]
	//		fmt.Printf("Received (Raw)%v\n", rb)
	//		fmt.Printf("Received (Raw)%x\n", rb)

	tab = append(tab, rb...)
	msgs, err := ParseAuditNetlinkMessage(rb)
	if err != nil {
		fmt.Println("Error in Parsing")
		return nil, err
	}
	for _, m := range msgs {
		lsa, err := syscall.Getsockname(s)
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
		}
		if m.Header.Type == syscall.NLMSG_DONE {
			//return tab, nil
			fmt.Println("Message parsed..")
			break
		}
		if m.Header.Type == syscall.NLMSG_ERROR {

			//	fmt.Printf("%x\n", m.Data)
			//	fmt.Printf("%v\n", m.Header.Flags)
			//				fmt.Println("%x\n", m.Header.Type)
			fmt.Println("NLMSG_ERROR")
			//				fmt.Println(error)
			break
			//return nil, EINVAL
		}
	}
	//}
	return tab, nil

}

func main() {
	v, er := newNetlink(1000, syscall.AF_NETLINK)
	//Types are defined in /usr/include/linux/audit.h
	//See https://www.redhat.com/archives/linux-audit/2011-January/msg00030.html
	if er != nil {
		fmt.Println("Got error on last")

		//fmt.Println(er)
	} else {
		//str := string(v[:])
		fmt.Println(v)
	}
	//	NetLinkListener()
}
