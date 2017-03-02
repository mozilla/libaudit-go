/*
Package libaudit is a client library in pure Go for talking with audit framework in the linux kernel.
It provides API for dealing with audit related tasks like setting audit rules, deleting audit rules etc.
The idea is to provide the same set of API as auditd (linux audit daemon).

NOTE: Currently the library is only applicable for x64 architecture.

Example usage of the library:

	package main

	import (
		"fmt"
		"ioutil"
		"syscall"
		"time"
		"github.com/mozilla/libaudit-go"
	)

	func main() {
		s, err := libaudit.NewNetlinkConnection()
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		defer s.Close()
		// enable audit in kernel
		err = libaudit.AuditSetEnabled(s, 1)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		// check if audit is enabled
		status, err := libaudit.AuditIsEnabled(s)
		if err == nil && status == 1 {
			fmt.Printf("Enabled Audit\n")
		} else if err == nil && status == 0 {
			fmt.Prinft("Audit Not Enabled\n")
			return
		} else {
			fmt.Printf("%v\n", err)
			return
		}
		// set the maximum number of messages
		// that the kernel will send per second
		err = libaudit.AuditSetRateLimit(s, 450)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		// set max limit audit message queue
		err = libaudit.AuditSetBacklogLimit(s, 16438)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		// register current pid with audit
		err = libaudit.AuditSetPID(s, syscall.Getpid())
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		// delete all rules that are previously present in kernel
		err = libaudit.DeleteAllRules(s)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		// set audit rules
		// specify rules in JSON format (for example see: https://github.com/arunk-s/gsoc16/blob/master/audit.rules.json)
		out, _ := ioutil.ReadFile("audit.rules.json")
		err = libaudit.SetRules(s, out)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		// create a channel to indicate libaudit to stop collecting messages
		done := make(chan, bool)
		// spawn a go routine that will stop the collection after 5 seconds
		go func(){
			time.Sleep(time.Second*5)
			done <- true
		}()
		// collect messages and handle them in a function
		libaudit.GetAuditMessages(s, callback, &done)
	}

	// provide a function to handle the messages
	func callback(msg *libaudit.AuditEvent, ce error, args ...interface{}) {
		if ce != nil {
			fmt.Printf("%v\n", ce)
		} else if msg != nil {
			// AuditEvent struct holds all message details including a map of audit fields => values
			fmt.Println(msg.Raw)
		}
	}
*/
package libaudit

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

var sequenceNumber uint32

// NetlinkMessage is the struct type that is used for communicating on netlink sockets.
type NetlinkMessage syscall.NetlinkMessage

// auditStatus is the c compatible struct of audit_status (libaudit.h).
// It is used for passing information involving status of audit services.
type auditStatus struct {
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

//Netlink is used for specifying the netlink connection types
type Netlink interface {
	Send(request *NetlinkMessage) error
	// Receive requires bytesize which specify the buffer size for incoming message and block which specify the mode for
	// reception (blocking and nonblocking)
	Receive(nonblocking bool) ([]NetlinkMessage, error)
	// GetPID returns the PID of the program the socket is being used to talk to
	// in our case we talk to the kernel so it is set to 0
	GetPID() (int, error)
}

// NetlinkConnection describes a netlink interface with the kernel.
//
// Programs should call NewNetlinkConnection() to create a new instance.
type NetlinkConnection struct {
	fd      int                     // File descriptor used for communication
	address syscall.SockaddrNetlink // Netlink sockaddr
}

// Close fd associated with netlink connection
func (s *NetlinkConnection) Close() {
	syscall.Close(s.fd)
}

// Send netlink message using the netlink connection
func (s *NetlinkConnection) Send(request *NetlinkMessage) error {
	return syscall.Sendto(s.fd, request.ToWireFormat(), 0, &s.address)
}

// Receive any available netlink messages being sent to us by the kernel
func (s *NetlinkConnection) Receive(nonblocking bool) ([]NetlinkMessage, error) {
	var (
		flags = 0
	)
	if nonblocking {
		flags |= syscall.MSG_DONTWAIT
	}
	buf := make([]byte, MAX_AUDIT_MESSAGE_LENGTH+syscall.NLMSG_HDRLEN)
	nr, _, err := syscall.Recvfrom(s.fd, buf, flags)
	if err != nil {
		return nil, err
	}
	return parseAuditNetlinkMessage(buf[:nr])
}

// Retrieves port ID of netlink socket peer
func (s *NetlinkConnection) GetPID() (int, error) {
	var (
		address syscall.Sockaddr
		v       *syscall.SockaddrNetlink
		err     error
	)
	address, err = syscall.Getsockname(s.fd)
	if err != nil {
		return 0, err
	}
	v = address.(*syscall.SockaddrNetlink)
	return int(v.Pid), nil
}

// Determine the byte order for the platform, used to order data being
// written to the kernel
func nativeEndian() binary.ByteOrder {
	var x uint32 = 0x01020304
	if *(*byte)(unsafe.Pointer(&x)) == 0x01 {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// ToWireFormat converts a NetlinkMessage to byte stream.
// Recvfrom in go takes only a byte [] to put the data recieved from the kernel that removes the need
// for having a separate audit_reply struct for recieving data from kernel.
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

// Process an incoming netlink message from the socket, and return a slice of
// NetlinkMessage types, or an error if an error is encountered.
//
// This function handles incoming messages with NLM_F_MULTI; in the case of
// a multipart message, ret will contain all netlink messages which are part
// of the kernel message. If it is not a multipart message, ret will simply
// contain a single message.
func parseAuditNetlinkMessage(b []byte) (ret []NetlinkMessage, err error) {
	for len(b) != 0 {
		multi := false
		var (
			m NetlinkMessage
		)
		m.Header.Len, b, err = netlinkPopuint32(b)
		// Determine our alignment size given the reported header length
		alignbounds := nlmAlignOf(int(m.Header.Len))
		padding := alignbounds - int(m.Header.Len)
		if len(b) < alignbounds-4 {
			return ret, fmt.Errorf("short read on audit message, expected %v bytes had %v",
				alignbounds, len(b)+4)
		}
		// If we get here, we have enough data for the entire message
		m.Header.Type, b, err = netlinkPopuint16(b)
		if err != nil {
			return ret, err
		}
		m.Header.Flags, b, err = netlinkPopuint16(b)
		if err != nil {
			return ret, err
		}
		if (m.Header.Flags & syscall.NLM_F_MULTI) != 0 {
			multi = true
		}
		m.Header.Seq, b, err = netlinkPopuint32(b)
		if err != nil {
			return ret, err
		}
		m.Header.Pid, b, err = netlinkPopuint32(b)
		if err != nil {
			return ret, err
		}
		datalen := m.Header.Len - syscall.NLMSG_HDRLEN
		m.Data = b[:datalen]
		b = b[int(datalen)+padding:]
		ret = append(ret, m)
		if !multi {
			break
		}
	}
	return ret, nil
}

func netlinkPopuint16(b []byte) (uint16, []byte, error) {
	if len(b) < 2 {
		return 0, b, fmt.Errorf("not enough bytes for uint16")
	}
	return binary.LittleEndian.Uint16(b[:2]), b[2:], nil
}

func netlinkPopuint32(b []byte) (uint32, []byte, error) {
	if len(b) < 4 {
		return 0, b, fmt.Errorf("not enough bytes for uint32")
	}
	return binary.LittleEndian.Uint32(b[:4]), b[4:], nil
}

func newNetlinkAuditRequest(proto uint16, family, sizeofData int) *NetlinkMessage {
	rr := &NetlinkMessage{}
	rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + sizeofData)
	rr.Header.Type = proto
	rr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	rr.Header.Seq = atomic.AddUint32(&sequenceNumber, 1) //Autoincrementing Sequence
	return rr
}

// Create a new netlink connection with the kernel audit subsystem and return a
// NetlinkConnection describing it. The process should ensure it has the required
// privileges before calling. An error is returned if any error is encountered
// creating the netlink connection.
func NewNetlinkConnection() (ret *NetlinkConnection, err error) {
	ret = &NetlinkConnection{}
	ret.fd, err = syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return
	}
	ret.address.Family = syscall.AF_NETLINK
	ret.address.Groups = 0
	ret.address.Pid = 0 // 0 for kernel space
	if err = syscall.Bind(ret.fd, &ret.address); err != nil {
		syscall.Close(ret.fd)
		return
	}
	return
}

// Get a reply to a message from the kernel. The message(s) we are looking for are indicated
// by passing sequence number seq.
//
// Once we recieve the full response any matching messages are returned. Note this function
// would generally be used to retrieve a response from various AUDIT_SET functions or similar
// configuration routines, and we do not use this for draining the audit event queue.
//
// XXX Right now we just discard any unrelated messages, which is not neccesarily
// ideal. This could be adapted to handle this better.
//
// XXX This function also waits until it gets the correct message, so if for some reason
// the message does not come through it will not return. This should also be improved.
func auditGetReply(s Netlink, seq uint32, chkAck bool) (ret []NetlinkMessage, err error) {
done:
	for {
		dbrk := false
		msgs, err := s.Receive(false)
		if err != nil {
			return ret, err
		}
		for _, m := range msgs {
			socketPID, err := s.GetPID()
			if err != nil {
				return ret, err
			}
			if m.Header.Seq != seq {
				// Wasn't the sequence number we are looking for, just discard it
				continue
			}
			if int(m.Header.Pid) != socketPID {
				// PID didn't match, just discard it
				continue
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				e := int32(nativeEndian().Uint32(m.Data[0:4]))
				if e == 0 {
					// ACK response from the kernel; if chkAck is true
					// we just return as there is nothing left to do
					if chkAck {
						break done
					}
					// Otherwise, keep going so we can get the response
					// we want
					continue
				} else {
					return ret, fmt.Errorf("auditGetReply: error while recieving reply -%d", e)
				}
			}
			ret = append(ret, m)
			if (m.Header.Flags & syscall.NLM_F_MULTI) == 0 {
				// If it's not a multipart message, once we get one valid
				// message just return
				dbrk = true
				break
			}
		}
		if dbrk {
			break
		}
	}
	return ret, nil
}

// Send AUDIT_SET with the associated auditStatus configuration
func auditSendStatus(s Netlink, status auditStatus) (err error) {
	buf := new(bytes.Buffer)
	err = binary.Write(buf, nativeEndian(), status)
	if err != nil {
		return
	}
	wb := newNetlinkAuditRequest(uint16(AUDIT_SET), syscall.AF_NETLINK, AUDIT_STATUS_SIZE)
	wb.Data = buf.Bytes()
	if err = s.Send(wb); err != nil {
		return
	}
	_, err = auditGetReply(s, wb.Header.Seq, true)
	if err != nil {
		return errors.Wrap(err, "AuditSetEnabled failed")
	}
	return nil
}

// Enable or disable auditing in the kernel
func AuditSetEnabled(s Netlink, enabled bool) (err error) {
	var status auditStatus
	if enabled {
		status.Enabled = 1
	} else {
		status.Enabled = 0
	}
	status.Mask = AUDIT_STATUS_ENABLED
	return auditSendStatus(s, status)
}

// Returns true if the auditing subsystem is enabled in the kernel
func AuditIsEnabled(s Netlink) (bool, error) {
	var status auditStatus

	wb := newNetlinkAuditRequest(uint16(AUDIT_GET), syscall.AF_NETLINK, 0)
	if err := s.Send(wb); err != nil {
		return false, err
	}

	msgs, err := auditGetReply(s, wb.Header.Seq, false)
	if err != nil {
		return false, err
	}
	if len(msgs) != 1 {
		return false, fmt.Errorf("unexpected number of responses from kernel for status request")
	}
	m := msgs[0]
	if m.Header.Type != uint16(AUDIT_GET) {
		return false, fmt.Errorf("status request response type was invalid")
	}
	// Convert the response to auditStatus
	buf := bytes.NewBuffer(m.Data)
	err = binary.Read(buf, nativeEndian(), &status)
	if err != nil {
		return false, err
	}
	if status.Enabled == 1 {
		return true, nil
	}
	return false, nil
}

// Set PID for audit daemon in kernel (audit_set_pid(3))
func AuditSetPID(s Netlink, pid int) error {
	var status auditStatus
	status.Mask = AUDIT_STATUS_PID
	status.Pid = uint32(pid)
	return auditSendStatus(s, status)
}

// AuditSetRateLimit sets the rate limit for audit messages from the kernel
func AuditSetRateLimit(s Netlink, limit int) error {
	var status auditStatus
	status.Mask = AUDIT_STATUS_RATE_LIMIT
	status.RateLimit = uint32(limit)
	return auditSendStatus(s, status)
}

// AuditSetBacklogLimit sets the backlog limit for audit messages in the kernel
func AuditSetBacklogLimit(s Netlink, limit int) error {
	var status auditStatus
	status.Mask = AUDIT_STATUS_BACKLOG_LIMIT
	status.BacklogLimit = uint32(limit)
	return auditSendStatus(s, status)
}
