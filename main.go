package main

import (
	"./netlinkAudit" //Should be changed according to individual settings
	"fmt"
	"os"
	"syscall"
	"time"
)

var done chan bool
var debug bool

func main() {
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		fmt.Println(err)
	}
	defer s.Close()
	debug = true
	netlinkAudit.AuditSetEnabled(s)
	err = netlinkAudit.AuditIsEnabled(s)
	if debug == true {
		fmt.Println(netlinkAudit.ParsedResult)
	}
	if err == nil && netlinkAudit.ParsedResult.Enabled == 1 {
		fmt.Println("Enabled Audit!!")
	}
	err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))
	if err == nil {
		fmt.Println("Set pid successful!!")
	}

	// we need audit_name_to_field( ) && audit_rule_fieldpair_data
	netlinkAudit.SetRules(s)
	//netlinkAudit.GetreplyWithoutSync(s)
	done := make(chan bool, 1)
	msg := make(chan string)
	errchan := make(chan error)
	f, err := os.OpenFile("/tmp/log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		fmt.Println("Error Creating File!!")
	}
	defer f.Close()
	go func() {
		for {
			select {
			case ev := <-msg:
				fmt.Println("Message :" + ev + "\n")
				_, err := f.WriteString(ev + "\n")
				if err != nil {
					fmt.Println("Writing Error!!")
				}
			case ev := <-errchan:
				fmt.Println(ev)
			}
		}
	}()

	go netlinkAudit.Getreply(s, done, msg, errchan)
	//fmt.Println("bogogogogog")
	//ListAllRules(s)
	time.Sleep(time.Second * 10)
	done <- true
	close(done)
	//Important point is that NLMSG_ERROR is also an acknowledgement from Kernel If the first 4 bytes of Data part are zero
	// than it means the message is acknowledged
}
