package main

import (
	"fmt";
	"./netlinkAudit"
)

func main() {
	// Open netlink socket
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		fmt.Println(err)
	}
	defer s.Close()

	// Check if audit is enabled
	err = netlinkAudit.AuditIsEnabled(s, 1)
	fmt.Println("parsedResult")
	fmt.Println(netlinkAudit.ParsedResult)
	if err == nil {
		fmt.Println("Horrah")
	}

	//set a rule
	var foo netlinkAudit.AuditRuleData
	netlinkAudit.AuditRuleSyscallData(&foo, 84)
	foo.Fields[foo.Field_count] = netlinkAudit.AUDIT_ARCH
	foo.Fieldflags[foo.Field_count] = netlinkAudit.AUDIT_EQUAL
	foo.Values[foo.Field_count] = netlinkAudit.AUDIT_ARCH_X86_64
	foo.Field_count++
	netlinkAudit.AuditAddRuleData(s, &foo, netlinkAudit.AUDIT_FILTER_EXIT, netlinkAudit.AUDIT_ALWAYS)


	//auditctl -a rmdir exit,always
	//Flags are exit
	//Action is always
}