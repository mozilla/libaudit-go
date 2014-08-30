package main

import . "syscall"
import "fmt"
import "unsafe"

type NetlinkAuditRequest struct {
    Header NlMsghdr
    Data   RtGenmsg
}

func (rr *NetlinkAuditRequest) toWireFormat() []byte {
    b := make([]byte, rr.Header.Len)
    *(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
    *(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
    *(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
    *(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
    *(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
    b[16] = byte(rr.Data.Family)
    return b
}

func newNetlinkAuditRequest(proto, seq, family int) []byte {
    rr := &NetlinkAuditRequest{}
    rr.Header.Len = uint32(NLMSG_HDRLEN + SizeofRtGenmsg)
    rr.Header.Type = uint16(proto)
    rr.Header.Flags = NLM_F_DUMP | NLM_F_REQUEST
    rr.Header.Seq = uint32(seq)
    rr.Data.Family = uint8(family)
    return rr.toWireFormat()
}



func main() {

    s, err := Socket(AF_NETLINK, SOCK_RAW, NETLINK_AUDIT)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer Close(s)

    lsa := &SockaddrNetlink{Family: AF_NETLINK}
    if err := Bind(s, lsa); err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println("**** Starting Netlink")

    // this should be 10 or not??
    //the purpose of sequence number is to give index number to the request , so for each request there will be different 
    //sequence number , this sequence number should be matched with the corresponding reply we get from kernel space
    wb := newNetlinkAuditRequest(AF_NETLINK, 10, NETLINK_AUDIT)
    if err := Sendto(s, wb, 0, lsa); err != nil {
        fmt.Println(err)
        return
    }
    var tab []byte
    for {
        //In the below statement, make variable initialization we used Getpagesize(), this function returns us the PAGE_SIZE of the system,
        // PAGE_SIZE of the system depends upon archietecture of the system, the use of page size is to store some memory during one
        // run cycle of the cpu, greater the PAGE_SIZE, greater can be the memory stored during one run time of the CPU cycle
        rb := make([]byte, Getpagesize())
        nr, _, err := Recvfrom(s, rb, 0)
        if err != nil {
            fmt.Println(err)
            return
        }
        if nr < NLMSG_HDRLEN {
            fmt.Println(EINVAL)
            fmt.Println("**** Starting Netlink")
            return
        }
        rb = rb[:nr]
        //fmt.Println(rb);
        tab = append(tab, rb...)
        msgs, err := ParseNetlinkMessage(rb)
        //fmt.Println(msgs);
        if err != nil {
            fmt.Println(err)
        }
        for _, m := range msgs {
            lsa, err := Getsockname(s)
            if err != nil {
                fmt.Println(err)
            }
            switch v := lsa.(type) {
            case *SockaddrNetlink:
                if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
                    fmt.Println(EINVAL)
                }
            default:
                fmt.Println(EINVAL)
            }
            if m.Header.Type == NLMSG_DONE {
                fmt.Println("*****Done******")
            }
            if m.Header.Type == NLMSG_ERROR {
                fmt.Println(EINVAL)
            }
        }           

    }

    ////////////////////

    fmt.Println(tab)

    ///////////////////
}

