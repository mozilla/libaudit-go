// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package libaudit

import (
	"fmt"
	"strconv"
	"strings"
)

type record struct {
	syscallNum string
	arch       string
	a0         int
	a1         int
}

// ParseAuditEvent parses an incoming audit message from kernel and returns an AuditEvent.
//
// msgType is supposed to come from the calling function which holds the msg header indicating header
// type of the messages. It uses simple string parsing techniques and provider better performance than
// the regex parser, idea taken from parse_up_record(rnode* r) in ellist.c (libauparse).
func ParseAuditEvent(str string, msgType auditConstant, interpret bool) (*AuditEvent, error) {
	var r record
	var event = AuditEvent{
		Raw: str,
	}

	m := make(map[string]string)

	if strings.HasPrefix(str, "audit(") {
		str = str[6:]
	} else {
		return nil, fmt.Errorf("malformed audit message")
	}
	index := strings.Index(str, ":")
	if index == -1 {
		return nil, fmt.Errorf("malformed audit message")
	}

	// determine timestamp
	timestamp := str[:index]
	// move further on string, skipping ':'
	str = str[index+1:]
	index = strings.Index(str, ")")
	if index == -1 {
		return nil, fmt.Errorf("malformed audit message")
	}
	serial := str[:index]
	if strings.HasPrefix(str, serial+"): ") {
		str = str[index+3:]
	} else {
		return nil, fmt.Errorf("malformed audit message")
	}

	var (
		nBytes string
		orig   = len(str)
		n      int
		key    string
		value  string
		av     bool
	)

	for n < orig {
		getSpaceSlice(&str, &nBytes, &n)
		var newIndex int
		newIndex = strings.Index(nBytes, "=")
		if newIndex == -1 {
			// check type for special cases of AVC and USER_AVC
			if msgType == AUDIT_AVC || msgType == AUDIT_USER_AVC {
				if nBytes == "avc:" && strings.HasPrefix(str, "avc:") {
					// skip over 'avc:'
					str = str[len(nBytes)+1:]
					av = true
					continue
				}
				if av {
					key = "seresult"
					value = nBytes
					m[key] = value
					av = false
					if len(str) == len(nBytes) {
						break
					} else {
						str = str[len(nBytes)+1:]
					}
					continue
				}
				if strings.HasPrefix(nBytes, "{") {
					key = "seperms"
					str = str[len(nBytes)+1:]
					var v string
					getSpaceSlice(&str, &nBytes, &n)
					for nBytes != "}" {
						if len(v) != 0 {
							v += ","
						}
						v += nBytes
						str = str[len(nBytes)+1:]
						getSpaceSlice(&str, &nBytes, &n)
					}
					value = v
					m[key] = value
					fixPunctuations(&value)
					if len(str) == len(nBytes) {
						//reached the end of message
						break
					} else {
						str = str[len(nBytes)+1:]
					}
					continue
				} else {
					// We might get values with space, add it to prev key
					// skip 'for' in avc message (special case)
					if nBytes == "for" {
						str = str[len(nBytes)+1:]
						continue
					}
					value += " " + nBytes
					fixPunctuations(&value)
					m[key] = value
				}
			} else {
				// We might get values with space, add it to prev key
				value += " " + nBytes
				fixPunctuations(&value)
				m[key] = value
			}

		} else {
			key = nBytes[:newIndex]
			value = nBytes[newIndex+1:]
			// for cases like msg='
			// we look again for key value pairs
			if strings.HasPrefix(value, "'") && key == "msg" {
				newIndex = strings.Index(value, "=")
				if newIndex == -1 {
					// special case USER_AVC messages, start of: msg='avc:
					if strings.HasPrefix(str, "msg='avc") {
						str = str[5:]
					}
					continue
				}
				key = value[1:newIndex]
				value = value[newIndex+1:]
			}

			fixPunctuations(&value)
			if key == "arch" {
				// determine machine type
			}
			if key == "a0" {
				val, err := strconv.ParseInt(value, 16, 64)
				if err != nil {
					r.a0 = -1
				} else {
					r.a0 = int(val)
				}
			}
			if key == "a1" {
				val, err := strconv.ParseInt(value, 16, 64)
				if err != nil {
					r.a1 = -1
				} else {
					r.a1 = int(val)
				}
			}
			if key == "syscall" {
				r.syscallNum = value
			}
			m[key] = value
		}
		if len(str) == len(nBytes) {
			// Reached the end of message
			break
		} else {
			str = str[len(nBytes)+1:]
		}

	}
	if interpret {
		for key, value := range m {
			ivalue, err := interpretField(key, value, msgType, r)
			if err != nil {
				return nil, err
			}
			m[key] = ivalue
		}
	}

	event.Timestamp = timestamp
	event.Serial = serial
	event.Data = m
	event.Type = msgType.String()[6:]
	return &event, nil

}

// getSpaceSlice checks the index of the next space and put the string up to that space into
// the second string, total number of characters processed is updated with each call to the function
func getSpaceSlice(str *string, b *string, v *int) {
	index := strings.Index(*str, " ")
	if index != -1 {
		if index == 0 {
			// Found space on the first location only, just forward on the orig
			// string and try again
			*str = (*str)[1:]
			getSpaceSlice(str, b, v)
		} else {
			*b = (*str)[:index]
			// Keep updating total characters processed
			*v += len(*b)
		}
	} else {
		*b = (*str)
		// Keep updating total characters processed
		*v += len(*b)
	}
}

func fixPunctuations(value *string) {
	// Remove trailing punctuation
	l := len(*value)
	if l > 0 && strings.HasSuffix(*value, "'") {
		*value = (*value)[:l-1]
		l--
	}
	if l > 0 && strings.HasSuffix(*value, ",") {
		*value = (*value)[:l-1]
		l--
	}
	if l > 0 && strings.HasSuffix(*value, ")") {
		if *value != "(none)" && *value != "(null)" {
			*value = (*value)[:l-1]
			l--
		}
	}
}
