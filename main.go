package main

import (
	"fmt"
	"github.com/arunk-s/netlinkAudit" //Should be changed according to individual settings
	"syscall"
	//	"time"
	//	"unsafe"
)

var done chan bool

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

	//	Uncomment this once to first add the rules and then comment it again to just receive !
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

	netlinkAudit.GetreplyWithoutSync(s)

	/*
		DO NOT USE SYNC VERSION! IT is not Correct.
		done = make(chan bool)
		msgchan := make(chan syscall.NetlinkMessage)
		errchan := make(chan error)

			go netlinkAudit.Getreply(s, msgchan, errchan, done)

			go func() {
				for {
					select {
					case ev := <-errchan:
						fmt.Println("\nError Occured!", ev, "\n")
					case ev := <-msgchan:
						fmt.Println("\nMessage", string(ev.Data[:]), "\n")
					}

				}
			}()
			time.Sleep(5 * time.Second)
			done <- true
	*/
	//Listening in a while loop from kernel when some event goes down through Kernel
	//TODO : Make a HandleAck
	//Remove seq dependency in AuditReply............
	//Important point is that NLMSG_ERROR is also an acknowledgement from Kernel If the first 4 bytes of Data part are zero
	// than it means the message is acknowledged
	//Design changes resulting from Handle Ack
	//Incorporate more AUDIT Constants and find way to load them
	//Work on loading rules from files : Json Format,various names to constants conversion :lookup-table.c
	//auditctl -a rmdir exit,always
	//Flags are exit
	//Action is always
}
