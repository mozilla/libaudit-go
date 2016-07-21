package libaudit

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/pkg/errors"
)

type EventCallback func(*AuditEvent, chan error, ...interface{})

type RawEventCallback func(string, chan error, ...interface{})

// AuditEvent holds a parsed audit message
type AuditEvent struct {
	Serial    string
	Timestamp string
	Type      string
	Data      map[string]string
	Raw       string
}

//NewAuditEvent takes NetlinkMessage passed from the netlink connection
//and parses the data from message to return an AuditEvent struct
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

func GetAuditEvents(s *NetlinkConnection, cb EventCallback, ec chan error, args ...interface{}) {
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err == 0 {
							//Note - NLMSG_ERROR can be Acknowledgement from kernel
							//If the first 4 bytes of Data part are zero
						} else {
							// log.Println("NLMSG ERROR")
							continue
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
						if err == 0 {
							//Acknowledgement from kernel
						} else {
							continue
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
					if err == 0 {
						//Acknowledgement from kernel
					} else {
						continue
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
