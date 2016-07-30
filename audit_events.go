package libaudit

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
)

// EventCallback is the function signature for any function that wants to receive an AuditEvent as soon as
// it is received from the kernel. Error channel will be used to indicate any error that happens while receiving
// messages.
type EventCallback func(*AuditEvent, chan error, ...interface{})

// RawEventCallback is similar to EventCallback and provides a function signature but the difference is that the function
// will receive only the message string which contains the audit event and not the parsed AuditEvent struct.
type RawEventCallback func(string, chan error, ...interface{})

// AuditEvent holds a parsed audit message.
// Serial holds the serial number for the message.
// Timestamp holds the unix timestamp of the message.
// Type indicates the type of the audit message.
// Data holds a map of field values of audit messages where keys => field names and values => field values.
// Raw string holds the original audit message received from kernel.
type AuditEvent struct {
	Serial    string
	Timestamp string
	Type      string
	Data      map[string]string
	Raw       string
}

//NewAuditEvent takes a NetlinkMessage passed from the netlink connection
//and parses the data from the message header to return an AuditEvent struct.
func NewAuditEvent(msg NetlinkMessage) (*AuditEvent, error) {
	x, err := ParseAuditEvent(string(msg.Data[:]), auditConstant(msg.Header.Type), true)
	if err != nil {
		return nil, err
	}
	if (*x).Type == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
		return nil, fmt.Errorf("NewAuditEvent failed: unknown message type %d", msg.Header.Type)
	}

	return x, nil
}

// GetAuditEvents receives audit messages from the kernel and parses them to AuditEvent struct.
// It passes them along the callback function and the error channel is used to indicate any error that happens while
// receiving the message. Code that receives the message runs inside a go-routine.
func GetAuditEvents(s *NetlinkConnection, cb EventCallback, ec chan error, args ...interface{}) {
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err != 0 {
							ec <- fmt.Errorf("error receiving events -%d", err)
						}
					} else {
						nae, err := NewAuditEvent(msg)
						if err != nil {
							ec <- err
						}
						cb(nae, ec, args...)
					}
				}
			}
		}
	}()
}

// GetRawAuditEvents receives raw audit messages from kernel parses them to AuditEvent struct.
// It passes them along the raw callback function and error channel is to indicate any error that happens while
// receiving the message. Code that receives the message runs inside a go-routine.
func GetRawAuditEvents(s *NetlinkConnection, cb RawEventCallback, ec chan error, args ...interface{}) {
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					m := ""
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err != 0 {
							ec <- fmt.Errorf("error receiving events -%d", err)
						}
					} else {
						Type := auditConstant(msg.Header.Type)
						if Type.String() == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
							ec <- errors.New("Unknown Type: " + string(msg.Header.Type))
						} else {
							m = "type=" + Type.String()[6:] + " msg=" + string(msg.Data[:]) + "\n"
						}
					}
					cb(m, ec, args...)
				}
			}
		}
	}()
}

// GetAuditMessages is a blocking function (runs in forever for loop) that
// receives audit messages from kernel and parses them to AuditEvent.
// It passes them along the callback cb and the error channel is used to indicate any error
// that happens while receiving the message.
// It will return when a signal is received on the done channel.
func GetAuditMessages(s *NetlinkConnection, cb EventCallback, ec *chan error, done *chan bool, args ...interface{}) {
	for {
		select {
		case <-*done:
			return
		default:
			msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
			for _, msg := range msgs {
				if msg.Header.Type == syscall.NLMSG_ERROR {
					err := int32(nativeEndian().Uint32(msg.Data[0:4]))
					if err != 0 {
						*ec <- fmt.Errorf("error receiving events -%d", err)
					}
				} else {
					nae, err := NewAuditEvent(msg)
					if err != nil {
						*ec <- err
					}
					cb(nae, *ec, args...)
				}
			}
		}
	}

}
