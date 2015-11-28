package netlinkAudit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var sequenceNumber uint32

type NetlinkMessage syscall.NetlinkMessage

// This is the struct for an "audit_status" message.
type AuditStatus struct {
	Mask              uint32 /* Bit mask for valid entries */
	Enabled           uint32 /* 1 = enabled, 0 = disabled */
	Failure           uint32 /* Failure-to-log action */
	Pid               uint32 /* pid of auditd process */
	Rate_limit        uint32 /* messages rate limit (per second) */
	Backlog_limit     uint32 /* waiting messages limit */
	Lost              uint32 /* messages lost */
	Backlog           uint32 /* messages waiting in queue */
	Version           uint32 /* audit api version number */
	BacklogWaitTime   uint32 /* message queue wait timeout */
}

type NetlinkConnection struct {
	fd  int
	address syscall.SockaddrNetlink
}

func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

//recvfrom in go takes only a byte [] to put the data recieved from the kernel that removes the need
//for having a separate audit_reply Struct for recieving data from kernel.
func (rr *NetlinkMessage) ToWireFormat() []byte {
	b := make([]byte, rr.Header.Len)
	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
	b = append(b[:16], rr.Data[:]...) //Important b[:16]
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
		log.Println("Error in parsing")
		return nil, err
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
		foo := int32(nativeEndian().Uint32(b[0:4]))
		log.Println("Headerlength with ", foo, b[0]) //bug!
		log.Println("Error due to....HDRLEN:", syscall.NLMSG_HDRLEN, " Header Length:", h.Len, " Length of BYTE Array:", len(b))
		return nil, nil, 0, syscall.EINVAL
	}
	return h, b[syscall.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
}

func newNetlinkAuditRequest(proto uint16, family, sizeofData int) *NetlinkMessage {
	rr := &NetlinkMessage{}

	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + sizeofData)
	rr.Header.Type = uint16(proto)
	rr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	rr.Header.Seq = atomic.AddUint32(&sequenceNumber , 1) //Autoincrementing Sequence
	return rr
	//	return rr.ToWireFormat()
}

// Create a fresh connection and used it for all further communication
func NewNetlinkConnection() (*NetlinkConnection, error) {

	// Check for root user
	if os.Getuid() != 0 {
		log.Fatalln("Not Root User! Exiting!")
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, err
	}
	s := &NetlinkConnection{
		fd: fd,
	}
	s.address.Family = syscall.AF_NETLINK
	s.address.Groups = 0
	s.address.Pid = 0 //Kernel space pid is always set to be 0

	if err := syscall.Bind(fd, &s.address); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return s, nil
}

//To end the socket conncetion
func (s *NetlinkConnection) Close() {
	syscall.Close(s.fd)
}

// Wrapper for Sendto
func (s *NetlinkConnection) Send(request *NetlinkMessage) error {
	if err := syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.address); err != nil {
		return err
	}
	return nil
}

// Wrapper for Recvfrom
func (s *NetlinkConnection) Receive(bytesize int, block int) ([]NetlinkMessage, error) {
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
	return parseAuditNetlinkMessage(rb)
}

//HandleAck ?
func AuditGetReply(s *NetlinkConnection, bytesize, block int, seq uint32) error {
done:
	for {
		msgs, err := s.Receive(bytesize, block) //parseAuditNetlinkMessage(rb)
		if err != nil {
			return err
		}
		for _, m := range msgs {
			address, err := syscall.Getsockname(s.fd)
			if err != nil {
				return err
			}
			switch v := address.(type) {
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

			if m.Header.Type == uint16(AUDIT_GET) {
				log.Println("AUDIT_GET")
				break done
			}
		}
	}
	return nil
}

// Sends a message to kernel to turn on audit
func AuditSetEnabled(s *NetlinkConnection) error {
	var status AuditStatus
	status.Enabled = 1
	status.Mask = AUDIT_STATUS_ENABLED
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
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

/* 
 * This function will return 0 if auditing is NOT enabled and
 * 1 if enabled, and -1 and an error on error.
 */
func AuditIsEnabled(s *NetlinkConnection) (state int, err error) {

	wb := newNetlinkAuditRequest(uint16(AUDIT_GET), syscall.AF_NETLINK, 0)
	if err = s.Send(wb); err != nil {
		return -1, err
	}

done:
	for {
		//TODO: Make the rb byte bigger because of large messages from Kernel doesn't fit in 4096
		msgs, err := s.Receive(MAX_AUDIT_MESSAGE_LENGTH, syscall.MSG_DONTWAIT)
		if err != nil {
			return -1, err
		}

		for _, m := range msgs {
			address, er := syscall.Getsockname(s.fd)
			if er != nil {
				return -1, er
			}

			switch v := address.(type) {
				case *syscall.SockaddrNetlink:
					if m.Header.Seq != uint32(wb.Header.Seq) {
						return -1, errors.New("Wrong Seq no " +
							        string(int(m.Header.Seq)) +
							        ", expected " + string(int(wb.Header.Seq)))
					}
					if m.Header.Pid != v.Pid {
						return -1, errors.New("Wrong Seq nr " +
										string(int(m.Header.Pid)) +
										", expected " + string(int(v.Pid)))
					}

				default:
					return -1, syscall.EINVAL
			}

			if m.Header.Type == syscall.NLMSG_DONE {
				//log.Println("Done")
				break done
			}

			if m.Header.Type == syscall.NLMSG_ERROR {
				log.Println("NLMSG_ERROR Received..")
			}

			if m.Header.Type == uint16(AUDIT_GET) {
				//Convert the data part written to AuditStatus struct
				buf := bytes.NewBuffer(m.Data[:])
				var dumm AuditStatus
				err = binary.Read(buf, nativeEndian(), &dumm)
				if err != nil {
					log.Println("binary.Read failed:", err)
					return -1, err
				}
				state = int(dumm.Enabled)
				break done
			}
		}
	}
	return state, nil
}

// Sends a message to kernel for setting of program pid
/*,Wait mode WAIT_YES | WAIT_NO */
func AuditSetPid(s *NetlinkConnection, pid uint32 ) error {
	var status AuditStatus
	status.Mask = AUDIT_STATUS_PID
	status.Pid = pid
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), status)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(status)))
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


func AuditSetRateLimit(s *NetlinkConnection, limit int) error {
	var foo AuditStatus
	foo.Mask = AUDIT_STATUS_RATE_LIMIT
	foo.Rate_limit = (uint32)(limit)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), foo)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(foo)))
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

func AuditSetBacklogLimit(s *NetlinkConnection, limit int) error {
	var foo AuditStatus
	foo.Mask = AUDIT_STATUS_BACKLOG_LIMIT
	foo.Backlog_limit = (uint32)(limit)
	buff := new(bytes.Buffer)
	err := binary.Write(buff, nativeEndian(), foo)
	if err != nil {
		log.Println("binary.Write failed:", err)
		return err
	}

	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, int(unsafe.Sizeof(foo)))
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
func GetreplyWithoutSync(s *NetlinkConnection) {
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
		msgs, err := parseAuditNetlinkMessage(rb)

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
			} else if m.Header.Type == uint16(AUDIT_GET) {
				log.Println("AUDIT_GET")
			} else if m.Header.Type == uint16(AUDIT_FIRST_USER_MSG) {
				log.Println("AUDIT_FIRST_USER_MSG")
			} else if m.Header.Type == uint16(AUDIT_SYSCALL) {
				log.Println("Syscall Event")
				log.Println(string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}
			} else if m.Header.Type == uint16(AUDIT_CWD) {
				log.Println("CWD Event")
				log.Println(string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}

			} else if m.Header.Type == uint16(AUDIT_PATH) {
				log.Println("Path Event")
				log.Println(string(m.Data[:]))
				_, err := f.WriteString(string(m.Data[:]) + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}

			} else if m.Header.Type == uint16(AUDIT_EOE) {
				log.Println("Event Ends ", string(m.Data[:]))
			} else if m.Header.Type == uint16(AUDIT_CONFIG_CHANGE) {
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
func Getreply(s *NetlinkConnection, done <-chan bool, msgchan chan string, errchan chan error) {
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
		msgs, err := parseAuditNetlinkMessage(rb)

		if err != nil {
			log.Println("Not Parsed Successfuly !!")
			errchan <- err
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
					log.Println("NLMSG_ERROR")
				}
			} else if m.Header.Type == uint16(AUDIT_EOE) {
				// log.Println("Event Ends ", string(m.Data[:]))
			} else if m.Header.Type == uint16(AUDIT_GET) {
				log.Println("AUDIT_GET")
			} else if m.Header.Type == uint16(AUDIT_FIRST_USER_MSG) {
				log.Println("AUDIT_FIRST_USER_MSG")
			} else {
				Type := auditConstant(m.Header.Type)
				if Type.String() == "auditConstant("+strconv.Itoa(int(m.Header.Type))+")" {
					log.Println("Unknown: ", m.Header.Type)
				} else {
					msgchan <- ("type=" + Type.String()[6:] + " msg=" + string(m.Data[:]))
				}
			}
		}
	}

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
