package netlinkAudit

import (
	"syscall"
	"strconv"
	"regexp"
	"errors"
	"encoding/hex"
	"strings"
	"sync"
)

type EventCallback func(*AuditEvent, chan error, ...interface{})

type RawEventCallback func(string, chan error, ...interface{})

type AuditEvent struct {
	Serial				int
	Timestamp			float64
	Type 				string
	Data 				map[string]string
}

func ParseAuditKeyValue(str string) (map[string]string) {
	audit_key_string := map[string]bool{
		"name":true,
	}

	re_kv := regexp.MustCompile(`((?:\\.|[^= ]+)*)=("(?:\\.|[^"\\]+)*"|(?:\\.|[^ "\\]+)*)`)
	re_quotedstring := regexp.MustCompile(`".+"`)

	kv := re_kv.FindAllStringSubmatch(str, -1)
	m := make(map[string]string)

	for _,e := range(kv) {
		key := e[1]
		value := e[2]
		if re_quotedstring.MatchString(value) {
			value = strings.Trim(value, "\"")
		}

		if audit_key_string[key] {
			if re_quotedstring.MatchString(value) == false  {
				v,err := hex.DecodeString(value)
				if err == nil {
					m[key] = string(v)
				}
			}
		} else {
			m[key] = value
		}
	}
	return m
}

func ParseAuditEvent(str string) (int, float64, map[string]string, error) {
	re := regexp.MustCompile(`^audit\((\d+\.\d+):(\d+)\): (.*)$`)
	match := re.FindStringSubmatch(str)

	if len(match) != 4 {
		return 0,0,nil,errors.New("Error while parsing audit message : Invalid Message")
	}

	serial, err := strconv.ParseInt(match[2], 10, 32)
	if err != nil {
		return 0,0,nil,errors.New("Error while parsing audit message : Invalid Message")
	}

	timestamp, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0,0,nil,errors.New("Error while parsing audit message : Invalid Message")
	}

	data := ParseAuditKeyValue(match[3])

	return int(serial), timestamp, data, nil
}

func NewAuditEvent(msg NetlinkMessage) (*AuditEvent, error) {
	serial, timestamp, data, err := ParseAuditEvent(string(msg.Data[:]))
	if err != nil {
		return nil, err
	}

	aetype :=  auditConstant(msg.Header.Type).String()
	if aetype == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
		return nil, errors.New("Unknown Type: " + string(msg.Header.Type))
	}

	ae := &AuditEvent{
		Serial:		serial,
		Timestamp:	timestamp,
		Type:		aetype,
		Data:		data,
	}
	return ae,nil
}

func GetAuditEvents(s *NetlinkConnection, cb EventCallback, ec chan error, args ...interface{}) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN + MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err == 0 {
							//Acknowledgement from kernel
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
	wg.Wait()
}


func GetRawAuditEvents(s *NetlinkConnection, cb RawEventCallback, ec chan error, args ...interface{}) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN + MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					m := ""
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err == 0 {
							//Acknowledgement from kernel
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
	wg.Wait()
}
