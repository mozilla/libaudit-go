package main

import s "syscall"
import "fmt"
import "unsafe"

type NetlinkAuditRequest struct {
    Header s.NlMsghdr
    Data   byte  //s.RtGenmsg
}

func (rr *NetlinkAuditRequest) toWireFormat() []byte {
    b := make([]byte, rr.Header.Len)
    *(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
    *(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
    *(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
    *(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
    *(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
    //b[16] = byte(rr.Data.Family)
    return b
}

func newNetlinkAuditRequest(proto, seq, family int) []byte {
    rr := &NetlinkAuditRequest{}
    rr.Header.Len = uint32(s.NLMSG_HDRLEN) //+ s.SizeofRtGenmsg)
    rr.Header.Type = uint16(proto)
    rr.Header.Flags = s.NLM_F_REQUEST//s.MSG_PEEK|s.MSG_DONTWAIT//s.NLM_F_REQUEST //| s.NLM_F_ACK
    rr.Header.Seq = uint32(seq)
    //rr.Data.Family = uint8(family)
    return rr.toWireFormat()
}

func nlmAlignOf(msglen int) int {
    return (msglen + s.NLMSG_ALIGNTO - 1) & ^(s.NLMSG_ALIGNTO - 1)
}

func main() {

    // Create a netlink socket
    sock, err := s.Socket(s.AF_NETLINK, s.SOCK_RAW, s.NETLINK_AUDIT)
    if err != nil {
        fmt.Println("scoket error:")
        fmt.Println(err)
        return
    }
    defer s.Close(sock)

    lsa := &s.SockaddrNetlink{Family: s.AF_NETLINK}
    if err := s.Bind(sock, lsa); err != nil {
        fmt.Println("bind error:")
        fmt.Println(err)
        return
    }
    fmt.Println("**** Starting Netlink")

    // sendto(fd, &req, req.nlh.nlmsg_len, 0,(struct sockaddr*)&addr, sizeof(addr))
    // sendto(3, "\20\0\0\0\350\3\5\0\1\0\0\0\0\0\0\0", 16, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 16
    // sendto(3, "\20\0\0\0\350\3\1\0\1\0\0\0\0\0\0\0", 16, 0, {sa_family=AF_NETLINK, pid=0, groups=00000000}, 12) = 16
    wb := newNetlinkAuditRequest(1000, 1, s.NETLINK_AUDIT)
    if err := s.Sendto(sock, wb, 0, lsa); err != nil {
        fmt.Println("sending error: ", err)
        return
    }
    var tab []byte
done:
    for {

        // recvfrom(fd, &rep->msg, sizeof(rep->msg), block|peek,   (struct sockaddr*)&nladdr, &nladdrlen);
        // recvfrom(3, "$\0\0\0\2\0\0\0\1\0\0\0\234K\0\0\0\0\0\0\20\0\0\0\350\3\5\0\1\0\0\0"..., 8988, MSG_PEEK|MSG_DONTWAIT, {sa_family=AF_NETLINK, pid=0, groups=00000000}, [12]) = 36
        // recvfrom(3, "0\0\0\0\350\3\0\0\1\0\0\0r\177\0\0\0\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0"..., 8988, MSG_PEEK|MSG_DONTWAIT, {sa_family=AF_NETLINK, pid=0, groups=00000000}, [12]) = 48
        rb := make([]byte, s.Getpagesize())

        //nr, _, err := Recvfrom(s, rb, MSG_PEEK|MSG_DONTWAIT)
        nr, _, err := s.Recvfrom(sock, rb, 0)
        if err != nil {
            fmt.Println("rec err: ", err)
            return
        }
        if nr < s.NLMSG_HDRLEN {
            fmt.Println(s.EINVAL)
            fmt.Println("nr < nlmsg hdrlen")
            return
        }
        rb = rb[:nr]
        tab = append(tab, rb...)
        msgs, err := s.ParseNetlinkMessage(rb)

        if err != nil {
            fmt.Println("parse error:", err)
            return
        }

        for _, m := range msgs {

            fmt.Println(m.Header.Pid)
 
            lsa, err := s.Getsockname(sock)
            if err != nil {
                fmt.Println("get socket name error:", err)
                return
            }

            switch v := lsa.(type) {
            case *s.SockaddrNetlink:
                if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
                    fmt.Println("case")
                    fmt.Println(s.EINVAL)
                    return 
                }
            default:
                fmt.Println(s.EINVAL)
                fmt.Println("default case")
                return
            }
            if m.Header.Type == s.NLMSG_DONE {
                break done
            }

            if m.Header.Type == s.NLMSG_ERROR {
                fmt.Println(s.EINVAL)
                fmt.Println("somewhere below")
                return
            }

        }
        fmt.Println(string(tab[:]));
    }
}
