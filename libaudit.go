package libaudit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

var sequenceNumber uint32

type NetlinkMessage syscall.NetlinkMessage

// AuditStatus is used for "audit_status" messages
type AuditStatus struct {
	Mask            uint32 /* Bit mask for valid entries */
	Enabled         uint32 /* 1 = enabled, 0 = disabled */
	Failure         uint32 /* Failure-to-log action */
	Pid             uint32 /* pid of auditd process */
	RateLimit       uint32 /* messages rate limit (per second) */
	BacklogLimit    uint32 /* waiting messages limit */
	Lost            uint32 /* messages lost */
	Backlog         uint32 /* messages waiting in queue */
	Version         uint32 /* audit api version number */
	BacklogWaitTime uint32 /* message queue wait timeout */
}

// NetlinkConnection holds the file descriptor and address for
// an opened netlink connection
type NetlinkConnection struct {
	fd      int
	address syscall.SockaddrNetlink
}

func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// ToWireFormat converts a NetlinkMessage to byte stream
// Recvfrom in go takes only a byte [] to put the data recieved from the kernel that removes the need
// for having a separate audit_reply Struct for recieving data from kernel.
func (rr *NetlinkMessage) ToWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b = append(b[:16], rr.Data[:]...) //b[:16] is crucial for aligning the header and data properly.
	return b
}

// Round the length of a netlink message up to align it properly.
func nlmAlignOf(msglen int) int {
	return (msglen + syscall.NLMSG_ALIGNTO - 1) & ^(syscall.NLMSG_ALIGNTO - 1)
}

// Parse a byte stream to an array of NetlinkMessage structs
func parseAuditNetlinkMessage(b []byte) ([]NetlinkMessage, error) {

	var msgs []NetlinkMessage
	h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
	if err != nil {
		return nil, errors.Wrap(err, "error while parsing NetlinkMessage")
	}

	m := NetlinkMessage{Header: *h, Data: dbuf[:int(h.Len) /* -syscall.NLMSG_HDRLEN*/]}
	msgs = append(msgs, m)
	b = b[dlen:]

	return msgs, nil
}

// Internal Function, uses unsafe pointer conversions for separating Netlink Header and the Data appended with it
func netlinkMessageHeaderAndData(b []byte) (*syscall.NlMsghdr, []byte, int, error) {

	h := (*syscall.NlMsghdr)(unsafe.Pointer(&b[0]))
	if int(h.Len) < syscall.NLMSG_HDRLEN || int(h.Len) > len(b) {
		// foo := int32(nativeEndian().Uint32(b[0:4]))
		// log.Println("Headerlength with ", foo, b[0]) //bug!
		// log.Println("Error due to....HDRLEN:", syscall.NLMSG_HDRLEN, " Header Length:", h.Len, " Length of BYTE Array:", len(b))
		return nil, nil, 0, errors.Wrap(syscall.EINVAL, "Nlmsghdr header length unexpected")
	}
	return h, b[syscall.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
}

func newNetlinkAuditRequest(proto uint16, family, sizeofData int) *NetlinkMessage {
	rr := &NetlinkMessage{}
	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + sizeofData)
	rr.Header.Type = proto
	rr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	rr.Header.Seq = atomic.AddUint32(&sequenceNumber, 1) //Autoincrementing Sequence
	return rr
}

// NewNetlinkConnection creates a fresh netlink connection
func NewNetlinkConnection() (*NetlinkConnection, error) {

	// Check for root user
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("not root user, exiting")
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, errors.Wrap(err, "could not obtain socket")
	}
	s := &NetlinkConnection{
		fd: fd,
	}
	s.address.Family = syscall.AF_NETLINK
	s.address.Groups = 0
	s.address.Pid = 0 //Kernel space pid is always set to be 0

	if err := syscall.Bind(fd, &s.address); err != nil {
		syscall.Close(fd)
		return nil, errors.Wrap(err, "could not bind socket to address")
	}
	return s, nil
}

// Close is a wrapper for closing netlink socket
func (s *NetlinkConnection) Close() {
	syscall.Close(s.fd)
}

// Send is a wrapper for sending NetlinkMessage across netlink socket
func (s *NetlinkConnection) Send(request *NetlinkMessage) error {
	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.address); err != nil {
		return errors.Wrap(err, "could not send NetlinkMessage")
	}
	return nil
}

// Receive is a wrapper for recieving from netlink socket and return an array of NetlinkMessage
func (s *NetlinkConnection) Receive(bytesize int, block int) ([]NetlinkMessage, error) {
	rb := make([]byte, bytesize)
	nr, _, err := syscall.Recvfrom(s.fd, rb, 0|block)

	if err != nil {
		return nil, errors.Wrap(err, "recvfrom failed")
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, errors.Wrap(err, "message length shorter than expected")
	}
	rb = rb[:nr]
	return parseAuditNetlinkMessage(rb)
}

// AuditGetReply connects to kernel to recieve a reply
func AuditGetReply(s *NetlinkConnection, bytesize, block int, seq uint32) error {
done:
	for {
		msgs, err := s.Receive(bytesize, block) //parseAuditNetlinkMessage(rb)
		if err != nil {
			return errors.Wrap(err, "AuditGetReply failed")
		}
		for _, m := range msgs {
			address, err := syscall.Getsockname(s.fd)
			if err != nil {
				return errors.Wrap(err, "AuditGetReply: Getsockname failed")
			}
			switch v := address.(type) {
			case *syscall.SockaddrNetlink:

				if m.Header.Seq != seq {
					return fmt.Errorf("AuditGetReply: Wrong Seq nr %d, expected %d", m.Header.Seq, seq)
				}
				if m.Header.Pid != v.Pid {
					return fmt.Errorf("AuditGetReply: Wrong pid %d, expected %d", m.Header.Pid, v.Pid)
				}
			default:
				return errors.Wrap(syscall.EINVAL, "AuditGetReply: socket type unexpected")
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				error := int32(nativeEndian().Uint32(m.Data[0:4]))
				if error == 0 {
					//log.Println("Acknowledged!!")
					break done
				} else {
					//log.Println("NLMSG_ERROR Received..")
					//should be added: appropriate flow of actions
				}
				break done
			}
			// acknowledge AUDIT_GET replies from kernel
			if m.Header.Type == uint16(AUDIT_GET) {
				break done
			}
		}
	}
	return nil
}

// AuditSetEnabled enables or disables audit in kernel
// `enabled` should be 1 for enabling and 0 for disabling
func AuditSetEnabled(s *NetlinkConnection, enabled uint32) error {
	var (
		status AuditStatus
		err    error
	)

	status.Enabled = enabled
	status.Mask = AUDIT_STATUS_ENABLED
	buff := new(bytes.Buffer)
	err = binary.Write(buff, nativeEndian(), status)
	if err != nil {
		return errors.Wrap(err, "AuditSetEnabled: binary write from AuditStatus failed")
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return errors.Wrap(err, "AuditSetEnabled failed")
	}

	// Receive in just one try
	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return errors.Wrap(err, "AuditSetEnabled failed")
	}
	return nil
}

// AuditIsEnabled returns 0 if auditing is NOT enabled and
// 1 if enabled, and -1 on failure.
func AuditIsEnabled(s *NetlinkConnection) (state int, err error) {
	var status AuditStatus

	wb := newNetlinkAuditRequest(uint16(AUDIT_GET), syscall.AF_NETLINK, 0)
	if err = s.Send(wb); err != nil {
		return -1, errors.Wrap(err, "AuditIsEnabled failed")
	}

done:
	for {
		// MSG_DONTWAIT has implications on systems with low memory and CPU
		// msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, 0)
		if err != nil {
			return -1, errors.Wrap(err, "AuditIsEnabled failed")
		}

		for _, m := range msgs {
			address, err := syscall.Getsockname(s.fd)
			if err != nil {
				return -1, errors.Wrap(err, "AuditIsEnabled: Getsockname failed")
			}

			switch v := address.(type) {
			case *syscall.SockaddrNetlink:
				if m.Header.Seq != uint32(wb.Header.Seq) {

					return -1, fmt.Errorf("AuditIsEnabled: Wrong Seq nr %d, expected %d", m.Header.Seq, wb.Header.Seq)
				}
				if m.Header.Pid != v.Pid {
					return -1, fmt.Errorf("AuditIsEnabled: Wrong PID %d, expected %d", m.Header.Pid, v.Pid)
				}

			default:
				return -1, errors.Wrap(syscall.EINVAL, "AuditIsEnabled: socket type unexpected")
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			} else if m.Header.Type == syscall.NLMSG_ERROR {
				e := int32(nativeEndian().Uint32(m.Data[0:4]))
				if e == 0 {
					//TODO: Better way to notify
					log.Println("ACK")
					continue
				}
				break done

			}

			if m.Header.Type == uint16(AUDIT_GET) {
				//Convert the data part written to AuditStatus struct
				buf := bytes.NewBuffer(m.Data[:])
				err = binary.Read(buf, nativeEndian(), &status)
				if err != nil {
					return -1, errors.Wrap(err, "AuditIsEnabled: binary read into AuditStatus failed")
				}
				state = int(status.Enabled)
				return state, nil
			}
		}
	}
	return -1, nil
}

// AuditSetPID sends a message to kernel for setting of program PID
// Wait mode WAIT_YES | WAIT_NO
func AuditSetPID(s *NetlinkConnection, pid uint32) error {
	var status AuditStatus
	status.Mask = AUDIT_STATUS_PID
	status.Pid = pid
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		return errors.Wrap(err, "AuditSetPID: binary write from AuditStatus failed")
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return errors.Wrap(err, "AuditSetPID failed")
	}

	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return errors.Wrap(err, "AuditSetPID failed")
	}
	return nil
}

// AuditSetRateLimit sets rate limit for audit messages from kernel
func AuditSetRateLimit(s *NetlinkConnection, limit int) error {
	var status AuditStatus
	status.Mask = AUDIT_STATUS_RATE_LIMIT
	status.RateLimit = (uint32)(limit)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		return errors.Wrap(err, "AuditSetRateLimit: binary write from AuditStatus failed")
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return errors.Wrap(err, "AuditSetRateLimit failed")
	}

	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return err
	}
	return nil

}

// AuditSetBacklogLimit sets backlog limit for audit messages from kernel
func AuditSetBacklogLimit(s *NetlinkConnection, limit int) error {
	var status AuditStatus
	status.Mask = AUDIT_STATUS_BACKLOG_LIMIT
	status.BacklogLimit = (uint32)(limit)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		return errors.Wrap(err, "AuditSetBacklogLimit: binary write from AuditStatus failed")
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
	wb.Data = append(wb.Data[:], buff.Bytes()[:]...)
	if err := s.Send(wb); err != nil {
		return errors.Wrap(err, "AuditSetBacklogLimit failed")
	}

	err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
	if err != nil {
		return errors.Wrap(err, "AuditSetBacklogLimit failed")
	}
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
