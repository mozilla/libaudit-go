package main

import s "syscall"
import "fmt"
import "unsafe"

const (
    MAX_AUDIT_MESSAGE_LENGTH = 8970
    AUDIT_GET                = 1000
    AUDIT_LIST               = 1002
    AUDIT_LIST_RULES         = 1013
)

type NetlinkAuditRequest struct {
    Header s.NlMsghdr
    Data   []byte //string
}

type AuditReply struct {

    RepHeader s.NlMsghdr
    Message   NetlinkAuditRequest
}

func (rr *NetlinkAuditRequest) toWireFormat() []byte {
    b := make([]byte, uint32(s.NLMSG_HDRLEN + MAX_AUDIT_MESSAGE_LENGTH))
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
    rr.Header.Len = uint32(s.NLMSG_HDRLEN + MAX_AUDIT_MESSAGE_LENGTH) //+ s.SizeofRtGenmsg)
    rr.Header.Type = uint16(proto)
    rr.Header.Flags = s.NLM_F_REQUEST//s.MSG_PEEK|s.MSG_DONTWAIT//s.NLM_F_REQUEST //| s.NLM_F_ACK
    rr.Header.Seq = uint32(seq)
    //rr.Data.Family = uint8(family)
    return rr.toWireFormat()
}

func  newNetlinkAuditReply() []byte {
    rr := &NetlinkAuditRequest{}
    return rr.toWireFormat()
}

func nlmAlignOf(msglen int) int {
    return (msglen + s.NLMSG_ALIGNTO - 1) & ^(s.NLMSG_ALIGNTO - 1)
}

func ParseAuditNetlinkMessage(b []byte) ([]NetlinkAuditRequest, error) {
    var msgs []NetlinkAuditRequest
    for len(b) >= s.NLMSG_HDRLEN {
        h, dbuf, dlen, err := netlinkMessageHeaderAndData(b)
        if err != nil {
            fmt.Println("Error in parse audit")
            return nil, err
        }
        m := NetlinkAuditRequest{Header: *h, Data: dbuf[:int(h.Len)-s.NLMSG_HDRLEN]}
        msgs = append(msgs, m)
        b = b[dlen:]
    }
    return msgs, nil
}

func netlinkMessageHeaderAndData(b []byte) (*s.NlMsghdr, []byte, int, error) {
    h := (*s.NlMsghdr)(unsafe.Pointer(&b[0]))
    //fmt.Println(int(s.NLMSG_HDRLEN));
    if int(h.Len) < s.NLMSG_HDRLEN || int(h.Len) > len(b) {
        fmt.Println("Error Here")
        fmt.Println(s.NLMSG_HDRLEN, h.Len, h.Len, len(b))
        return nil, nil, 0, s.EINVAL
    }
    return h, b[s.NLMSG_HDRLEN:], nlmAlignOf(int(h.Len)), nil
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

    wb := newNetlinkAuditRequest(1005, 1, s.NETLINK_AUDIT)

    //TODO: try sendmsg here 
    if err := s.Sendto(sock, wb, 0, lsa); err != nil {
        fmt.Println("sending error: ", err)
        return
    }
    var tab []byte

done:
    for {

        // r := make([]byte, s.Getpagesize())     
        r := newNetlinkAuditReply();

        //nr, _, err := s.Recvfrom(sock, r, s.MSG_PEEK|s.MSG_DONTWAIT)
        nr, _, err := s.Recvfrom(sock, r, 0)

        //r = r[s.NLMSG_HDRLEN:nr]
        if err != nil {
            fmt.Println("rec err: ", err)
            return
        }
        if nr < s.NLMSG_HDRLEN {
            fmt.Println(s.EINVAL)
            fmt.Println("nr < nlmsg hdrlen")
            return
        }

        r = r[:nr]
        tab = append(tab, r...)
        msgs, err := ParseAuditNetlinkMessage(r)

        if err != nil {
            fmt.Println("parse error:", err)
            return
        }

        for _, m := range msgs {

            fmt.Println(string(m.Data))
 
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
        
        fmt.Println(tab[:]);
        //a,_ := s.ParseNetlinkMessage(tab)
        //fmt.Println(a)
    }
    fmt.Println(tab);
}
