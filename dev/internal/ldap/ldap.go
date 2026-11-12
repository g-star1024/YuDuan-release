// Package ldap 是御端在受限环境（无法拉取 go-ldap）下自研的最小化 LDAP 客户端。
// 覆盖御端目录同步所需能力：simple bind（真实 AD 账号口令认证）、
// 子树搜索（objectClass/userAccountControl/memberOf 等常用过滤器）、TLS（ldaps）。
// 仅依赖标准库；BER 编解码按 RFC 4511 手写。
package ldap

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// 作用域（RFC 4511 §4.5.1.2）
const (
	ScopeBase         = 0
	ScopeOneLevel     = 1
	ScopeWholeSubtree = 2
)

// 结果码子集（RFC 4511 A.1）
const (
	ResultSuccess            = 0
	ResultOperationsError    = 1
	ResultNoSuchObject       = 32
	ResultInvalidDNSyntax    = 34
	ResultInvalidCredentials = 49
	ResultUnavailable        = 52
)

// Entry 是一条目录条目。
type Entry struct {
	DN         string
	Attributes map[string][]string
}

// Get 取属性首个值。
func (e Entry) Get(attr string) string {
	if vs, ok := e.Attributes[attr]; ok && len(vs) > 0 {
		return vs[0]
	}
	return ""
}

// Conn 是一个 LDAP 连接。
type Conn struct {
	nc    net.Conn
	r     *bufio.Reader
	msgID int
}

// Dial 以明文连接 LDAP 服务（生产建议用 TLS，见 DialTLS）。
func Dial(host string, port int) (*Conn, error) {
	nc, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		return nil, err
	}
	return &Conn{nc: nc, r: bufio.NewReader(nc)}, nil
}

// DialTLS 以 LDAPS（TLS）连接；insecure 跳过证书校验（内网自签场景）。
func DialTLS(host string, port int, insecure bool) (*Conn, error) {
	nc, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp",
		net.JoinHostPort(host, strconv.Itoa(port)),
		&tls.Config{InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12})
	if err != nil {
		return nil, err
	}
	return &Conn{nc: nc, r: bufio.NewReader(nc)}, nil
}

// Close 关闭连接。
func (c *Conn) Close() error { return c.nc.Close() }

// Bind 以 simple 方式绑定（真实 AD 账号口令认证）。
func (c *Conn) Bind(dn, password string) error {
	c.msgID++
	// BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER, name OCTET STRING, authentication [0] OCTET STRING }
	auth := tlv(0x80, []byte(password)) // [0] primitive context tag（simple）
	body := encodeSeq(encodeInt(3), encodeStr(dn), auth)
	if err := c.writeMessage(0x60, body); err != nil {
		return err
	}
	tag, content, err := c.readMessage()
	if err != nil {
		return err
	}
	if tag != 0x61 { // BindResponse
		return fmt.Errorf("ldap: unexpected bind response tag 0x%02x", tag)
	}
	code, _, diag, err := parseLDAPResult(content)
	if err != nil {
		return err
	}
	if code != ResultSuccess {
		return fmt.Errorf("ldap: bind failed code=%d (%s)", code, diag)
	}
	return nil
}

// Unbind 发送 unbind 并关闭。
func (c *Conn) Unbind() error {
	c.msgID++
	_ = c.writeMessage(0x42, nil) // UnbindRequest ::= [APPLICATION 2] NULL
	return c.Close()
}

// SearchRequest 描述一次搜索。
type SearchRequest struct {
	BaseDN     string
	Scope      int
	Filter     string   // LDAP 过滤器语法子集：(&(...)...)/(|...)/(!...)/(attr=value)/(attr=*)/(attr:rule:=value)
	Attributes []string // 期望返回的属性（空=全部用户属性，服务端可能裁剪）
	SizeLimit  int      // 0=服务端默认
}

// Search 执行子树搜索并返回条目。
func (c *Conn) Search(req SearchRequest) ([]Entry, error) {
	if req.Filter == "" {
		req.Filter = "(objectClass=*)"
	}
	filterBytes, err := encodeFilter(req.Filter)
	if err != nil {
		return nil, err
	}
	attrs := make([][]byte, 0, len(req.Attributes))
	for _, a := range req.Attributes {
		attrs = append(attrs, encodeStr(a))
	}
	// SearchRequest ::= [APPLICATION 3] SEQUENCE {
	//   baseObject OCTET STRING, scope ENUMERATED, derefAliases ENUMERATED,
	//   sizeLimit INTEGER, timeLimit INTEGER, typesOnly BOOLEAN,
	//   filter Filter, attributes SEQUENCE OF OCTET STRING }
	body := encodeSeq(
		encodeStr(req.BaseDN),
		encodeEnum(req.Scope),
		encodeEnum(0), // neverDerefAliases
		encodeInt(req.SizeLimit),
		encodeInt(0), // timeLimit
		encodeBool(false),
		filterBytes,
		encodeSeq(attrs...),
	)
	c.msgID++
	if err := c.writeMessage(0x63, body); err != nil {
		return nil, err
	}
	var out []Entry
	for {
		tag, content, err := c.readMessage()
		if err != nil {
			return nil, err
		}
		switch tag {
		case 0x64: // SearchResultEntry
			e, err := parseSearchEntry(content)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		case 0x65: // SearchResultDone
			code, _, diag, err := parseLDAPResult(content)
			if err != nil {
				return nil, err
			}
			if code != ResultSuccess {
				return nil, fmt.Errorf("ldap: search failed code=%d (%s)", code, diag)
			}
			return out, nil
		case 0x73: // SearchResultReference
			continue
		default:
			return nil, fmt.Errorf("ldap: unexpected search response tag 0x%02x", tag)
		}
	}
}

// ---- BER 编解码 ----

func encodeInt(n int) []byte    { return tlv(0x02, intContent(n)) }
func encodeEnum(n int) []byte   { return tlv(0x0A, intContent(n)) }
func encodeStr(s string) []byte { return tlv(0x04, []byte(s)) }
func encodeBool(b bool) []byte {
	if b {
		return tlv(0x01, []byte{0xFF})
	}
	return tlv(0x01, []byte{0x00})
}

func intContent(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	neg := n < 0
	var buf []byte
	for x := n; x != 0; x >>= 8 {
		buf = append([]byte{byte(x)}, buf...)
	}
	// 规范最小长度（保证最高位符号正确）
	if !neg && buf[0]&0x80 != 0 {
		buf = append([]byte{0}, buf...)
	}
	return buf
}

// tlv 组装 tag+length+content（长形式自动切换）。
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLength(len(content))...)
	return append(out, content...)
}

func encodeLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n <= 0xFF:
		return []byte{0x81, byte(n)}
	case n <= 0xFFFF:
		return []byte{0x82, byte(n >> 8), byte(n)}
	default:
		b := make([]byte, 5)
		b[0] = 0x84
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
}

func encodeSeq(items ...[]byte) []byte {
	var c []byte
	for _, it := range items {
		c = append(c, it...)
	}
	return tlv(0x30, c)
}

// parseTLV 读一个 TLV，返回 tag 与 content。
func parseTLV(r io.Reader) (byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return 0, nil, err
	}
	tag := hdr[0]
	if _, err := io.ReadFull(r, hdr[1:2]); err != nil {
		return 0, nil, err
	}
	var n int
	switch {
	case hdr[1]&0x80 == 0:
		n = int(hdr[1])
	case hdr[1] == 0x81:
		var b [1]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = int(b[0])
	case hdr[1] == 0x82:
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint16(b[:]))
	case hdr[1] == 0x84:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n = int(binary.BigEndian.Uint32(b[:]))
	default:
		return 0, nil, fmt.Errorf("ldap: unsupported length form 0x%02x", hdr[1])
	}
	if n < 0 || n > 16<<20 {
		return 0, nil, fmt.Errorf("ldap: bad length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return tag, buf, nil
}

// rawTLV 从 reader 读一个完整 TLV，返回原始字节（tag+len+content）与 content。
func rawTLV(r io.Reader) ([]byte, []byte, error) {
	tag, content, err := parseTLV(r)
	if err != nil {
		return nil, nil, err
	}
	raw := tlvBytes(tag, content)
	return raw, content, nil
}

func tlvBytes(tag byte, content []byte) []byte {
	return tlv(tag, content)
}

// children 顺序解析 content 内的子 TLV，返回每个子 TLV 的原始字节。
func children(content []byte) ([][]byte, error) {
	var items [][]byte
	r := &byteReader{b: content}
	for r.remaining() > 0 {
		raw, _, err := rawTLV(r)
		if err != nil {
			return nil, err
		}
		items = append(items, raw)
	}
	return items, nil
}

type byteReader struct{ b []byte }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
func (r *byteReader) remaining() int { return len(r.b) }

// parseLDAPResult 解析 resultCode / matchedDN / diagnosticMessage。
func parseLDAPResult(content []byte) (int, string, string, error) {
	items, err := children(content)
	if err != nil || len(items) < 3 {
		return 0, "", "", errors.New("ldap: malformed LDAPResult")
	}
	_, codeContent, err := parseTLV(&byteReader{b: items[0]})
	if err != nil || len(codeContent) == 0 {
		return 0, "", "", errors.New("ldap: malformed result code")
	}
	_, matched, err := parseTLV(&byteReader{b: items[1]})
	if err != nil {
		return 0, "", "", err
	}
	_, diag, err := parseTLV(&byteReader{b: items[2]})
	if err != nil {
		return 0, "", "", err
	}
	return int(codeContent[0]), string(matched), string(diag), nil
}

// parseSearchEntry 解析 SearchResultEntry。
func parseSearchEntry(content []byte) (Entry, error) {
	items, err := children(content)
	if err != nil || len(items) < 2 {
		return Entry{}, errors.New("ldap: malformed SearchResultEntry")
	}
	_, dn, err := parseTLV(&byteReader{b: items[0]})
	if err != nil {
		return Entry{}, err
	}
	_, attrSeq, err := parseTLV(&byteReader{b: items[1]})
	if err != nil {
		return Entry{}, err
	}
	partials, err := children(attrSeq)
	if err != nil {
		return Entry{}, err
	}
	e := Entry{DN: string(dn), Attributes: map[string][]string{}}
	for _, p := range partials {
		_, pcontent, err := parseTLV(&byteReader{b: p})
		if err != nil {
			continue
		}
		fields, err := children(pcontent)
		if err != nil || len(fields) < 2 {
			continue
		}
		_, typeBytes, err := parseTLV(&byteReader{b: fields[0]})
		if err != nil {
			continue
		}
		_, valSet, err := parseTLV(&byteReader{b: fields[1]})
		if err != nil {
			continue
		}
		vals, err := children(valSet)
		if err != nil {
			continue
		}
		attr := string(typeBytes)
		for _, v := range vals {
			_, vb, err := parseTLV(&byteReader{b: v})
			if err != nil {
				continue
			}
			e.Attributes[attr] = append(e.Attributes[attr], string(vb))
		}
	}
	return e, nil
}

// ---- 过滤器编码（语法子集） ----

func encodeFilter(f string) ([]byte, error) {
	f = strings.TrimSpace(f)
	if len(f) < 2 || f[0] != '(' || f[len(f)-1] != ')' {
		return nil, fmt.Errorf("ldap: unsupported filter %q", f)
	}
	inner := f[1 : len(f)-1]
	switch {
	case strings.HasPrefix(inner, "&"):
		subs, err := splitFilters(inner[1:])
		if err != nil {
			return nil, err
		}
		var content []byte
		for _, s := range subs {
			b, err := encodeFilter(s)
			if err != nil {
				return nil, err
			}
			content = append(content, b...)
		}
		// and ::= [0] SET OF filter（子过滤器直接并列，无 SEQUENCE 包装）
		return tlv(0xA0, content), nil
	case strings.HasPrefix(inner, "|"):
		subs, err := splitFilters(inner[1:])
		if err != nil {
			return nil, err
		}
		var content []byte
		for _, s := range subs {
			b, err := encodeFilter(s)
			if err != nil {
				return nil, err
			}
			content = append(content, b...)
		}
		// or ::= [1] SET OF filter
		return tlv(0xA1, content), nil
	case strings.HasPrefix(inner, "!"):
		sub, err := encodeFilter(inner[1:])
		if err != nil {
			return nil, err
		}
		return tlv(0xA2, sub), nil // [2] not
	}
	// 可扩展匹配：attr:rule:=value（优先按 ":=" 切分）
	if idx := strings.Index(inner, ":="); idx >= 0 {
		left, val := inner[:idx], inner[idx+2:]
		parts := strings.SplitN(left, ":", 2)
		attrName, rule := parts[0], ""
		if len(parts) == 2 {
			rule = parts[1]
		}
		// RFC 4511：extensibleMatch ::= [9] SEQUENCE {
		//   matchingRule [1] OPTIONAL, type [2] OPTIONAL,
		//   matchValue [3], dnAttributes [4] DEFAULT FALSE }
		// 上下文标签直接承载字节（不再套 OCTET STRING TLV）。
		em := tlv(0x81, []byte(rule))                   // [1] matchingRule
		em = append(em, tlv(0x82, []byte(attrName))...) // [2] type
		em = append(em, tlv(0x83, []byte(val))...)      // [3] matchValue
		em = append(em, tlv(0x84, []byte{0x00})...)     // [4] dnAttributes = FALSE
		return tlv(0xA9, em), nil                       // [9] extensibleMatch
	}
	// 简单形式：attr=value / attr=*
	eq := strings.Index(inner, "=")
	if eq < 0 {
		return nil, fmt.Errorf("ldap: unsupported filter %q", f)
	}
	attr := inner[:eq]
	val := inner[eq+1:]
	if val == "*" && !strings.Contains(attr, ":") {
		return tlv(0x87, encodeStr(attr)), nil // [7] present
	}
	// equalityMatch ::= [3] SEQUENCE{ attributeDesc, assertionValue }（应用标签取代 SEQUENCE）
	return tlv(0xA3, append(encodeStr(attr), encodeStr(val)...)), nil
}

// splitFilters 切分 "(&(...)(...))" 内层的一级子过滤器序列。
func splitFilters(s string) ([]string, error) {
	var out []string
	depth, start := 0, -1
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
			if depth == 1 {
				start = i
			}
		case ')':
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, s[start:i+1])
				start = -1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("ldap: unbalanced filter %q", s)
	}
	return out, nil
}

// ---- 消息帧 ----

// writeMessage 发送 Message ::= SEQUENCE { messageID INTEGER, protocolOp }。
func (c *Conn) writeMessage(opTag byte, opBody []byte) error {
	msg := encodeSeq(encodeInt(c.msgID), tlv(opTag, opBody))
	_ = c.nc.SetWriteDeadline(time.Now().Add(15 * time.Second))
	_, err := c.nc.Write(msg)
	return err
}

// readMessage 读取一条消息，返回 protocolOp 的应用标签与内容。
func (c *Conn) readMessage() (byte, []byte, error) {
	_ = c.nc.SetReadDeadline(time.Now().Add(60 * time.Second))
	tag, content, err := parseTLV(c.r)
	if err != nil {
		return 0, nil, err
	}
	if tag != 0x30 {
		return 0, nil, fmt.Errorf("ldap: expected SEQUENCE, got 0x%02x", tag)
	}
	items, err := children(content)
	if err != nil || len(items) != 2 {
		return 0, nil, errors.New("ldap: malformed message")
	}
	opTag, opBody, err := parseTLV(&byteReader{b: items[1]})
	if err != nil {
		return 0, nil, err
	}
	return opTag, opBody, nil
}
