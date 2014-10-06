package main

import (
	"fmt"
	"github.com/arunk-s/netlinkAudit" //Should be changed according to individual settings
)

func main() {
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		fmt.Println(err)
	}
	defer s.Close()

	netlinkAudit.AuditSetEnabled(s, 1)
	err = netlinkAudit.AuditIsEnabled(s, 2)
	fmt.Println("parsedResult")
	fmt.Println(netlinkAudit.ParsedResult)
	if err == nil {
		fmt.Println("Horrah")
	}
	var foo netlinkAudit.AuditRuleData

	//NO Fields for now
	// we need audit_name_to_field( ) && audit_rule_fieldpair_data

	/*
		nr := 84
		word := uint32(nr / 32)
		bit := (1 << (uint32(nr) - word*32))
		if word >= (netlinkAudit.AUDIT_BITMASK_SIZE - 1) {
			fmt.Println("Error")
		}

		foo.Mask[word] = foo.Mask[word] | uint32(bit)
	*/
	//Syscall rmdir() is 84 on table
	netlinkAudit.AuditRuleSyscallData(&foo, 84)
	netlinkAudit.AuditAddRuleData(s, &foo, netlinkAudit.AUDIT_FILTER_EXIT, netlinkAudit.AUDIT_ALWAYS)
	//auditctl -a rmdir exit,always
	//Flags are exit
	//Action is always
}
