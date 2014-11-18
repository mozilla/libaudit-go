package main

import (
	"./netlinkAudit"
	"log"
	"os"
	"syscall"
	"time"
)

var done chan bool
var debug bool

func main() {
	s, err := netlinkAudit.GetNetlinkSocket()
	if err != nil {
		log.Println(err)
		log.Fatalln("Error while availing socket! Exiting!")
	}
	defer s.Close()
	debug = false

	if os.Getuid() != 0 {
		log.Fatalln("Not Root User! Exiting!")
	}
	err = netlinkAudit.AuditSetEnabled(s)
	if err != nil {
		log.Fatal("Error while enabling Audit !", err)
	}
	err = netlinkAudit.AuditIsEnabled(s)

	if debug == true {
		log.Println(netlinkAudit.ParsedResult)
	}

	if err == nil && netlinkAudit.ParsedResult.Enabled == 1 {
		log.Println("Enabled Audit!!")
	} else {
		log.Fatalln("Audit Not Enabled! Exiting")
	}

	err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))

	if err == nil {
		log.Println("Set pid successful!!")
	}

	netlinkAudit.SetRules(s)
	//netlinkAudit.GetreplyWithoutSync(s)
	done := make(chan bool, 1)
	msg := make(chan string)
	errchan := make(chan error)
	f, err := os.OpenFile("/tmp/log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		log.Fatalln("Error Creating File!!")
	}
	defer f.Close()
	go func() {
		for {
			select {
			case ev := <-msg:
				log.Println("Message :" + ev + "\n")
				_, err := f.WriteString(ev + "\n")
				if err != nil {
					log.Println("Writing Error!!")
				}
			case ev := <-errchan:
				log.Println(ev)
			}
		}
	}()

	go netlinkAudit.Getreply(s, done, msg, errchan)

	time.Sleep(time.Second * 10)
	done <- true
	close(done)
	//Important point is that NLMSG_ERROR is also an acknowledgement from Kernel.
	//If the first 4 bytes of Data part are zero then it means the message is acknowledged
}
