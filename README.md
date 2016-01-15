# Libaudit in Golang
Golang package (lib) for Linux Audit

Libaudit-go is a go library that provide helper methods to talk to Linux Audit.
Originally developed for [Audit GO Heka Pluigin](https://github.com/mozilla/audit-go) 

## Supported Methods (API)

### General 


#### NewNetlinkConnection 
Open a audit netlink socket connection
Similar to audit_open, NewNetlinkConnection  creates a NETLINK_AUDIT socket for communication with the kernel part of the Linux Audit Subsystem.

It provide three methods

* Close 
* Send
* Receive

Example : 

    s, err := netlinkAudit.NewNetlinkConnection()

    if err != nil {
        log.Println(err)
	    log.Fatalln("Error while availing socket! Exiting!")
    } 

    defer s.Close()

#### AuditGetEvents

Start a Audit event monitor

```
func AuditGetEvents(s *NetlinkConnection, cb EventCallback, ec chan error, args ...interface{})
```

This function start a audit event monitor and accept a callback that get called on each audit event received  from the Audit Subsysten.

Example:

```golang

func EventCallback(msg string, ce chan error, args ...interface{}) {
	log.Println(msg)
}

// Go rutine to monitor events and call callback for each event fired
netlinkAudit.Get_audit_events(s, EventCallback, errchan)
```



#### AuditGetReply

Get the audit system's reply

```
func AuditGetReply(s *NetlinkConnection, bytesize, block int, seq uint32) error
```

This function gets the next data packet sent on the audit netlink socket. This function is usually called after sending a command to the audit system. block is of type reply_t which is either: GET_REPLY_BLOCKING and GET_REPLY_NONBLOCKING.

Example :

```
err = AuditGetReply(s, syscall.Getpagesize(), 0, wb.Header.Seq)
```

#### AuditIsEnabled

This function will return 0 if auditing is NOT enabled and 1 if enabled, and -1 and an error on error.

```
func AuditIsEnabled(s *NetlinkConnection) (state int, err error)
```

Example :

```
status, err := netlinkAudit.AuditIsEnabled(s)
```


### Audit Set

#### AuditSetEnabled

Enable or disable auditing

```
func AuditSetEnabled(s *NetlinkConnection) error
```

Example : 

```
status, err := netlinkAudit.AuditSetEnabled(s)
```



#### AuditSetRateLimit

Set audit rate limit

```
func AuditSetRateLimit(s *NetlinkConnection, limit int) error
```

This function set the maximum number of messages that the kernel will send per second.

Example:

```
err = netlinkAudit.AuditSetRateLimit(s, 600)
```

#### AuditSetBacklogLimit

Set the audit backlog limit

```
func AuditSetBacklogLimit(s *NetlinkConnection, limit int) error
```

This function sets the queue length for audit events awaiting transfer to the audit daemon


Example :
```
err = netlinkAudit.AuditSetBacklogLimit(s, 420)
```

#### AuditSetPid

Set audit daemon process ID


```
func AuditSetPid(s *NetlinkConnection, pid uint32 ) error 
```

This function tells the kernel what the pid is of the audit daemon


Example :
```
err = netlinkAudit.AuditSetPid(s, uint32(syscall.Getpid()))
```