/*
 * mysql-sniffer.go
 *
 * A straightforward program for sniffing MySQL query streams and providing
 * diagnostic information on the realtime queries your database is handling.
 *
 * FIXME: this assumes IPv4.
 * FIXME: tokenizer doesn't handle negative numbers or floating points.
 * FIXME: canonicalizer should collapse "IN (?,?,?,?)" and "VALUES (?,?,?,?)"
 * FIXME: tokenizer breaks on '"' or similarly embedded quotes
 * FIXME: tokenizer parses numbers in words wrong, i.e. s2compiled -> s?compiled
 *
 * written by Mark Smith <mark@qq.is>
 *
 * requires the gopcap library to be installed from:
 *   https://github.com/akrennmair/gopcap
 *
 */

package main

import (
    "flag"
    "fmt"
    "./gopcap"
    _ "./go-spew/spew"
    "log"
    "math/rand"
    "strings"
    "time"
    "encoding/json"
    zmq "./zmq4"
)

const (
    TOKEN_WORD       = 0
    TOKEN_QUOTE      = 1
    TOKEN_NUMBER     = 2
    TOKEN_WHITESPACE = 3
    TOKEN_OTHER      = 4

    // Internal tuning
    TIME_BUCKETS = 10000

    // ANSI colors
    COLOR_RED     = "\x1b[31m"
    COLOR_GREEN   = "\x1b[32m"
    COLOR_YELLOW  = "\x1b[33m"
    COLOR_CYAN    = "\x1b[36m"
    COLOR_WHITE   = "\x1b[37m"
    COLOR_DEFAULT = "\x1b[39m"

    // MySQL packet types
    COM_QUERY = 3

    // These are used for formatting outputs
    F_NONE = iota
    F_QUERY
    F_ROUTE
    F_SOURCE
    F_SOURCEIP
)

type packet struct {
    request bool // request or response
    data    []byte
}

type sortable struct {
    value float64
    line  string
}
type sortableSlice []sortable

type source struct {
    src       string
    srcip     string
    synced    bool
    reqbuffer []byte
    resbuffer []byte
    reqSent   *time.Time
    reqTimes  [TIME_BUCKETS]uint64
    qbytes    uint64
    qdata     *queryData
    qtext     string
}

type queryData struct {
    count uint64
    bytes uint64
    times [TIME_BUCKETS]uint64
}

var start int64 = UnixNow()
var qbuf map[string]*queryData = make(map[string]*queryData)
var querycount int
var chmap map[string]*source = make(map[string]*source)
var verbose bool = false
var noclean bool = false
var dirty bool = false
var format []interface{}
var port uint16
var times [TIME_BUCKETS]uint64
var puber *zmq.Socket
var service_id string = ""
var tenant_id string = ""
var zmqaddr string = ""
var topic string = ""

var stats struct {
    packets struct {
        rcvd      uint64
        rcvd_sync uint64
    }
    desyncs uint64
    streams uint64
}

func UnixNow() int64 {
    return time.Now().Unix()
}

func main() {
    var lport *int = flag.Int("P", 3306, "MySQL port to use")
    var eth *string = flag.String("i", "eth0", "Interface to sniff")
    var ldirty *bool = flag.Bool("u", false, "Unsanitized -- do not canonicalize queries")
    var doverbose *bool = flag.Bool("v", true, "Print every query received (spammy)")
    var nocleanquery *bool = flag.Bool("n", false, "no clean queries")
    var formatstr *string = flag.String("f", "#s:#q", "Format for output aggregation")
    var zad *string = flag.String("zmq_addr", "tcp://172.30.42.1:7388", "zmq address")
    var sid *string = flag.String("service_id", "default", "service_id")
    var tid *string = flag.String("tenant_id", "default", "tenant_id")
    var tpc *string  = flag.String("topic", "", "topic")
    
    flag.Parse()
    
    verbose = *doverbose
    noclean = *nocleanquery
    port = uint16(*lport)
    dirty = *ldirty
    service_id = *sid
    tenant_id = *tid
    topic = *tpc
    zmqaddr = *zad
    if topic==""{
        topic = "cep.mysql.sniff."+tenant_id
    }
    
    parseFormat(*formatstr)
    
    rand.Seed(time.Now().UnixNano())

    log.SetPrefix("")
    log.SetFlags(0)
    
    tem_puber, _ := zmq.NewSocket(zmq.PUB)
    puber = tem_puber
    puber.Connect(zmqaddr)
    
    log.Printf("Initializing zeromq address %s", zmqaddr)

    log.Printf("Initializing MySQL sniffing on %s:%d", *eth, port)
    iface, err := pcap.Openlive(*eth, 1024, false, 0)
    if iface == nil || err != nil {
        msg := "unknown error"
        if err != nil {
            msg = err.Error()
        }
        log.Fatalf("Failed to open device: %s", msg)
    }

    err = iface.Setfilter(fmt.Sprintf("tcp port %d", port))
    if err != nil {
        log.Fatalf("Failed to set port filter: %s", err.Error())
    }
    
    var pkt *pcap.Packet = nil
    var rv int32 = 0

    for rv = 0; rv >= 0; {
        for pkt, rv = iface.NextEx(); pkt != nil; pkt, rv = iface.NextEx() {
            handlePacket(pkt)
        }
    }
}

// Do something with a packet for a source.
func processPacket(src string, rs *source, request bool, data []byte) {

    stats.packets.rcvd++
    if rs.synced {
        stats.packets.rcvd_sync++
    }

    var ptype int = -1
    var pdata []byte

    if request {
        if rs.resbuffer != nil {
            stats.desyncs++
            rs.resbuffer = nil
            rs.synced = false
        }
        rs.reqbuffer = data
        ptype, pdata = carvePacket(&rs.reqbuffer)
    } else {
        rs.resbuffer = nil
        ptype, pdata = 0, data
    }

    if !rs.synced {
        if !(request && ptype == COM_QUERY) {
            rs.reqbuffer, rs.resbuffer = nil, nil
            return
        }
        rs.synced = true
    }
    
    if ptype == -1 {
        return
    }
    plen := uint64(len(pdata))

    var reqtime uint64
    if !request {
        if rs.reqSent == nil {
            if rs.qdata != nil {
                rs.qdata.bytes += plen
            }
            return
        }
        reqtime = uint64(time.Since(*rs.reqSent).Nanoseconds())

        randn := rand.Intn(TIME_BUCKETS)
        rs.reqTimes[randn] = reqtime
        times[randn] = reqtime
        if rs.qdata != nil {
            rs.qdata.times[randn] = reqtime
            rs.qdata.bytes += plen
        }
        rs.reqSent = nil
        if len(rs.qtext) > 0 {
            sql := strings.ToLower(rs.qtext)                    
            if strings.Index(sql,"select")>=0 || strings.Index(sql,"update")>=0 || strings.Index(sql,"insert")>=0 || strings.Index(sql,"delete")>=0 || strings.Index(sql,"truncate")>=0 {
                temsqls := strings.Split(rs.qtext,":")
                sql = temsqls[2]
                datas := make(map[string]interface{})
                datas["service_id"]=service_id
                datas["tenant_id"]=tenant_id
                datas["sql"]=sql
                datas["time"]=float64(reqtime)/1000
                datas["size"]=rs.qbytes
                datas["operate"]=strings.ToLower(strings.Split(sql," ")[0])
                jsonString, _ := json.Marshal(datas)
                jsonm :=string(jsonString)
                jsonm = "APPS sniff "+jsonm
                if verbose{
                    log.Printf(topic+"="+jsonm)
                }               
                puber.Send(topic, zmq.SNDMORE)
                puber.Send(jsonm, zmq.DONTWAIT)
                rs.qdata = nil
                rs=nil
                delete(chmap,src)
                stats.streams--
                //fmt.Println(len(chmap))
            }
        }
        return
    }
    tnow := time.Now()
    rs.reqSent = &tnow

    querycount++
    var text string
    for _, item := range format {
        switch item.(type) {
        case int:
            switch item.(int) {
            case F_NONE:
                log.Fatalf("F_NONE in format string")
            case F_QUERY:
                if dirty {
                    text += string(pdata)
                } else {
                    text += cleanupQuery(pdata)
                }
            case F_ROUTE:
                parts := strings.SplitN(string(pdata), " ", 5)
                if len(parts) >= 4 && parts[1] == "/*" && parts[3] == "*/" {
                    if strings.Contains(parts[2], ":") {
                        text += strings.SplitN(parts[2], ":", 2)[1]
                    } else {
                        text += parts[2]
                    }
                } else {
                    text += "(unknown) " + cleanupQuery(pdata)
                }
            case F_SOURCE:
                text += rs.src
            case F_SOURCEIP:
                text += rs.srcip
            default:
                log.Fatalf("Unknown F_XXXXXX int in format string")
            }
        case string:
            text += item.(string)
        default:
            log.Fatalf("Unknown type in format string")
        }
    }
    qdata, ok := qbuf[text]
    if !ok {
        qdata = &queryData{}
        qbuf[text] = qdata
    }
    qdata.count++
    qdata.bytes += plen
    rs.qtext, rs.qdata, rs.qbytes = text, qdata, plen
}

func carvePacket(buf *[]byte) (int, []byte) {
    datalen := uint32(len(*buf))
    if datalen < 5 {
        return -1, nil
    }

    size := uint32((*buf)[0]) + uint32((*buf)[1])<<8 + uint32((*buf)[2])<<16
    if size == 0 || datalen < size+4 {
        return -1, nil
    }

    end := size + 4
    ptype := int((*buf)[4])
    data := (*buf)[5 : size+4]
    if end >= datalen {
        *buf = nil
    } else {
        *buf = (*buf)[end:]
    }
    return ptype, data
}

func handlePacket(pkt *pcap.Packet) {
    var pos byte = 14
    srcIP := pkt.Data[pos+12 : pos+16]
    dstIP := pkt.Data[pos+16 : pos+20]

    pos += pkt.Data[pos] & 0x0F * 4

    srcPort := uint16(pkt.Data[pos])<<8 + uint16(pkt.Data[pos+1])
    dstPort := uint16(pkt.Data[pos+2])<<8 + uint16(pkt.Data[pos+3])

    pos += byte(pkt.Data[pos+12]) >> 4 * 4

    if len(pkt.Data[pos:]) <= 0 {
        return
    }

    var src string
    var request bool = false
    if srcPort == port {
        src = fmt.Sprintf("%d.%d.%d.%d:%d", dstIP[0], dstIP[1], dstIP[2],
            dstIP[3], dstPort)
    } else if dstPort == port {
        src = fmt.Sprintf("%d.%d.%d.%d:%d", srcIP[0], srcIP[1], srcIP[2],
            srcIP[3], srcPort)
        request = true
    } else {
        log.Fatalf("got packet src = %d, dst = %d", srcPort, dstPort)
    }

    rs, ok := chmap[src]
    if !ok {
        srcip := src[0:strings.Index(src, ":")]
        rs = &source{src: src, srcip: srcip, synced: false}
        stats.streams++
        chmap[src] = rs
    }

    processPacket(src, rs, request, pkt.Data[pos:])
}

func scanToken(query []byte) (length int, thistype int) {
    if len(query) < 1 {
        log.Fatalf("scanToken called with empty query")
    }

    if verbose && noclean {
        return len(query), TOKEN_OTHER
    }
    b := query[0]
    switch {
    case b == 39 || b == 34: // '"
        started_with := b
        escaped := false
        for i := 1; i < len(query); i++ {
            switch query[i] {
            case started_with:
                if escaped {
                    escaped = false
                    continue
                }
                return i + 1, TOKEN_QUOTE
            case 92:
                escaped = true
            default:
                escaped = false
            }
        }
        return len(query), TOKEN_QUOTE

    case b >= 48 && b <= 57: // 0-9
        for i := 1; i < len(query); i++ {
            switch {
            case query[i] >= 48 && query[i] <= 57: // 0-9
                // do nothing
            default:
                return i, TOKEN_NUMBER
            }
        }
        return len(query), TOKEN_NUMBER

    case b == 32 || (b >= 9 && b <= 13): // whitespace
        for i := 1; i < len(query); i++ {
            switch {
            case query[i] == 32 || (query[i] >= 9 && query[i] <= 13):
                // Eat all whitespace
            default:
                return i, TOKEN_WHITESPACE
            }
        }
        return len(query), TOKEN_WHITESPACE

    case (b >= 65 && b <= 90) || (b >= 97 && b <= 122): // a-zA-Z
        for i := 1; i < len(query); i++ {
            switch {
            case query[i] >= 48 && query[i] <= 57:
                // Numbers, allow.
            case (query[i] >= 65 && query[i] <= 90) || (query[i] >= 97 && query[i] <= 122):
                // Letters, allow.
            case query[i] == 36 || query[i] == 95:
                // $ and _
            default:
                return i, TOKEN_WORD
            }
        }
        return len(query), TOKEN_WORD

    default: // everything else
        return 1, TOKEN_OTHER
    }

    // shouldn't get here
    log.Fatalf("scanToken failure: [%s]", query)
    return
}

func cleanupQuery(query []byte) string {
    // iterate until we hit the end of the query...
    var qspace []string
    for i := 0; i < len(query); {
        length, toktype := scanToken(query[i:])

        switch toktype {
        case TOKEN_WORD, TOKEN_OTHER:
            qspace = append(qspace, string(query[i:i+length]))

        case TOKEN_NUMBER, TOKEN_QUOTE:
            qspace = append(qspace, "?")

        case TOKEN_WHITESPACE:
            qspace = append(qspace, " ")

        default:
            log.Fatalf("scanToken returned invalid token type %d", toktype)
        }

        i += length
    }

    // Remove hostname from the route information if it's present
    tmp := strings.Join(qspace, "")

    parts := strings.SplitN(tmp, " ", 5)
    if len(parts) >= 5 && parts[1] == "/*" && parts[3] == "*/" {
        if strings.Contains(parts[2], ":") {
            tmp = parts[0] + " /* " + strings.SplitN(parts[2], ":", 2)[1] + " */ " + parts[4]
        }
    }

    return strings.Replace(tmp, "?, ", "", -1)
}

// parseFormat takes a string and parses it out into the given format slice
// that we later use to build up a string. This might actually be an overcomplicated
// solution?
func parseFormat(formatstr string) {
    formatstr = strings.TrimSpace(formatstr)
    if formatstr == "" {
        formatstr = "#b:#k"
    }

    is_special := false
    curstr := ""
    do_append := F_NONE
    for _, char := range formatstr {
        if char == '#' {
            if is_special {
                curstr += string(char)
                is_special = false
            } else {
                is_special = true
            }
            continue
        }

        if is_special {
            switch strings.ToLower(string(char)) {
            case "s":
                do_append = F_SOURCE
            case "i":
                do_append = F_SOURCEIP
            case "r":
                do_append = F_ROUTE
            case "q":
                do_append = F_QUERY
            default:
                curstr += "#" + string(char)
            }
            is_special = false
        } else {
            curstr += string(char)
        }

        if do_append != F_NONE {
            if curstr != "" {
                format = append(format, curstr, do_append)
                curstr = ""
            } else {
                format = append(format, do_append)
            }
            do_append = F_NONE
        }
    }
    if curstr != "" {
        format = append(format, curstr)
    }
}

func (self sortableSlice) Len() int {
    return len(self)
}

func (self sortableSlice) Less(i, j int) bool {
    return self[i].value < self[j].value
}

func (self sortableSlice) Swap(i, j int) {
    self[i], self[j] = self[j], self[i]
}

