package main

import (
	"fmt"
	"github.com/arunk-s/netlinkAudit" //Should be changed according to individual settings
	///	"unsafe"
)

func main() {
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		fmt.Println(err)
	}
	defer s.Close()

	//netlinkAudit.AuditSetEnabled(s, 1)
	err = netlinkAudit.AuditIsEnabled(s, 1)
	fmt.Println("parsedResult")
	fmt.Println(netlinkAudit.ParsedResult)
	if err == nil {
		fmt.Println("Horrah")
	}
	var foo netlinkAudit.AuditRuleData

	//NO Fields for now
	// we need audit_name_to_field( ) && audit_rule_fieldpair_data
	//Syscall rmdir() is 84 on table
	//fmt.Println(unsafe.Sizeof(foo))
	netlinkAudit.AuditRuleSyscallData(&foo, 84)
	//fmt.Println(foo)
	foo.Fields[foo.Field_count] = netlinkAudit.AUDIT_ARCH
	foo.Fieldflags[foo.Field_count] = netlinkAudit.AUDIT_EQUAL
	foo.Values[foo.Field_count] = 64
	foo.Field_count++

	netlinkAudit.AuditAddRuleData(s, &foo, netlinkAudit.AUDIT_FILTER_EXIT, netlinkAudit.AUDIT_ALWAYS)
	//auditctl -a rmdir exit,always
	//Flags are exit
	//Action is always
}
