package main

import (
	"fmt"
	"github.com/arunk-s/netlinkAudit" //Should be changed according to individual settings
	"syscall"
	///	"unsafe"
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
	netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))
	var foo netlinkAudit.AuditRuleData
	// we need audit_name_to_field( ) && audit_rule_fieldpair_data
	//Syscall rmdir() is 84 on table
	//fmt.Println(unsafe.Sizeof(foo))
	netlinkAudit.AuditRuleSyscallData(&foo, 84)
	//fmt.Println(foo)
	foo.Fields[foo.Field_count] = netlinkAudit.AUDIT_ARCH
	foo.Fieldflags[foo.Field_count] = netlinkAudit.AUDIT_EQUAL
	foo.Values[foo.Field_count] = netlinkAudit.AUDIT_ARCH_X86_64
	foo.Field_count++
	//seq := 3
	netlinkAudit.AuditAddRuleData(s, &foo, netlinkAudit.AUDIT_FILTER_EXIT, netlinkAudit.AUDIT_ALWAYS)
	//TODO: Need to comeup with a method to generate atomic sequence numbers for sending the messages.
	//Listening in a while loop from kernel when some event goes down through Kernel
	/*
		Creating Errors for now
			seq := 3

			for {
				err := netlinkAudit.AuditGetReply(s, syscall.Getpagesize(), syscall.MSG_DONTWAIT, seq)
				if err != nil {
					continue
				}

				seq++
			}
	*/
	//auditctl -a rmdir exit,always
	//Flags are exit
	//Action is always
}
