// 进程内 mock AD/LDAP 服务器：在无域控制器的开发/联调环境中，
// 提供「真实 bind 认证 + 子树搜索 + 过滤器求值」的完整 LDAP 语义，
// 使 LDAPDirectory 与 SyncEngine 的映射逻辑可离线端到端验证。
// 生产部署时不编译引用（仅测试/开发使用）。
package ldap

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MockUser 是 mock 目录中的用户。
type MockUser struct {
	Username    string // sAMAccountName
	DisplayName string
	Email       string
	MemberOf    []string // 组 CN 列表
	Disabled    bool     // userAccountControl 位 2
	Password    string   // 该用户自身口令（用于用户级 bind 测试）
}

// MockServer 是内存 LDAP 服务器（simple bind + 子树搜索）。
type MockServer struct {
	Port    int
	BindDN  string
	BindPwd string
	BaseDN  string
	Users   []MockUser

	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	once  sync.Once
}

// NewMockServer 在随机端口启动 mock LDAP 服务器。
func NewMockServer(bindDN, bindPwd, baseDN string, users []MockUser) (*MockServer, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &MockServer{
		Port: ln.Addr().(*net.TCPAddr).Port, BindDN: bindDN, BindPwd: bindPwd, BaseDN: baseDN, Users: users,
		ln: ln,
	}
	go s.acceptLoop()
	return s, nil
}

// Close 停止服务器。
func (s *MockServer) Close() error {
	s.once.Do(func() {
		_ = s.ln.Close()
		s.mu.Lock()
		for _, c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	return nil
}

func (s *MockServer) acceptLoop() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, nc)
		s.mu.Unlock()
		go s.serve(nc)
	}
}

func (s *MockServer) serve(nc net.Conn) {
	defer nc.Close()
	reader := newConnReader(nc)
	for {
		tag, content, err := parseTLV(reader)
		if err != nil {
			return
		}
		if tag != 0x30 {
			return
		}
		items, err := children(content)
		if err != nil || len(items) != 2 {
			return
		}
		_, msgIDBytes, err := parseTLV(&byteReader{b: items[0]})
		if err != nil {
			return
		}
		msgID := int(msgIDBytes[0])
		opTag, opBody, err := parseTLV(&byteReader{b: items[1]})
		if err != nil {
			return
		}
		switch opTag {
		case 0x60: // BindRequest：opBody 是 SEQUENCE TLV，先剥壳取字段
			_, seqContent, err := parseTLV(&byteReader{b: opBody})
			if err != nil {
				s.writeResult(nc, msgID, 0x61, ResultOperationsError, "malformed bind")
				continue
			}
			fields, err := children(seqContent)
			if err != nil {
				s.writeResult(nc, msgID, 0x61, ResultOperationsError, "malformed bind")
				continue
			}
			s.handleBind(nc, msgID, fields)
		case 0x63: // SearchRequest
			_, seqContent, err := parseTLV(&byteReader{b: opBody})
			if err != nil {
				s.writeResult(nc, msgID, 0x65, ResultOperationsError, "malformed search")
				continue
			}
			fields, err := children(seqContent)
			if err != nil {
				s.writeResult(nc, msgID, 0x65, ResultOperationsError, "malformed search")
				continue
			}
			s.handleSearch(nc, msgID, fields)
		case 0x42: // UnbindRequest
			return
		default:
			s.writeResult(nc, msgID, 0x61, ResultOperationsError, "unsupported operation")
		}
	}
}

// connReader 让 parseTLV 直接读 net.Conn（按需缓冲）。
type connReader struct{ nc net.Conn }

func newConnReader(nc net.Conn) *connReader { return &connReader{nc: nc} }

func (c *connReader) Read(p []byte) (int, error) { return c.nc.Read(p) }

func (s *MockServer) handleBind(nc net.Conn, msgID int, fields [][]byte) {
	if len(fields) < 3 {
		s.writeResult(nc, msgID, 0x61, ResultOperationsError, "malformed bind")
		return
	}
	_, name, err := parseTLV(&byteReader{b: fields[1]})
	if err != nil {
		s.writeResult(nc, msgID, 0x61, ResultOperationsError, "malformed bind name")
		return
	}
	_, pwd, err := parseTLV(&byteReader{b: fields[2]}) // [0] simple 的内容即口令
	if err != nil {
		s.writeResult(nc, msgID, 0x61, ResultOperationsError, "malformed bind auth")
		return
	}
	dn, pw := string(name), string(pwd)
	ok := dn == s.BindDN && pw == s.BindPwd
	if !ok {
		// 也允许以用户自身 DN + 口令 bind（用户级认证）
		for _, u := range s.Users {
			if ("cn="+u.Username+","+s.BaseDN) == dn && u.Password == pw && !u.Disabled {
				ok = true
				break
			}
		}
	}
	if ok {
		s.writeResult(nc, msgID, 0x61, ResultSuccess, "")
	} else {
		s.writeResult(nc, msgID, 0x61, ResultInvalidCredentials, "invalid credentials")
	}
}

func (s *MockServer) handleSearch(nc net.Conn, msgID int, fields [][]byte) {
	if len(fields) < 8 {
		s.writeResult(nc, msgID, 0x65, ResultOperationsError, "malformed search")
		return
	}
	// fields[6] 本身即完整的过滤器 TLV（parseFilter 需要完整 TLV）
	f, err := parseFilter(fields[6])
	if err != nil {
		s.writeResult(nc, msgID, 0x65, ResultOperationsError, "unsupported filter")
		return
	}
	for _, u := range s.Users {
		attrs := map[string][]string{
			"objectClass":        {"top", "person", "organizationalPerson", "user"},
			"sAMAccountName":     {u.Username},
			"displayName":        {u.DisplayName},
			"mail":               {u.Email},
			"memberOf":           u.MemberOf,
			"userAccountControl": {uacOf(u)},
		}
		if !f.match(attrs) {
			continue
		}
		dn := "CN=" + u.DisplayName + ",OU=Users," + s.BaseDN
		// SearchResultEntry ::= [APPLICATION 4] SEQUENCE{ objectName, attributes }：
		// 应用标签直接包裹字段。
		entry := append(encodeStr(dn), encodeSeq(
			encodePartial("objectClass", attrs["objectClass"]),
			encodePartial("sAMAccountName", []string{u.Username}),
			encodePartial("displayName", []string{u.DisplayName}),
			encodePartial("mail", []string{u.Email}),
			encodePartial("memberOf", u.MemberOf),
			encodePartial("userAccountControl", []string{uacOf(u)}),
		)...)
		_ = s.writeMsg(nc, msgID, 0x64, entry)
	}
	s.writeResult(nc, msgID, 0x65, ResultSuccess, "")
}

func uacOf(u MockUser) string {
	if u.Disabled {
		return "514" // 512 + 2（禁用位）
	}
	return "512"
}

func encodePartial(attr string, values []string) []byte {
	var vals [][]byte
	for _, v := range values {
		vals = append(vals, encodeStr(v))
	}
	return encodeSeq(encodeStr(attr), encodeSeq(vals...))
}

func (s *MockServer) writeResult(nc net.Conn, msgID int, appTag byte, code int, diag string) {
	// BindResponse/SearchResultDone ::= [APPLICATION n] SEQUENCE{...}：
	// 应用标签直接包裹字段，不再套一层 SEQUENCE。
	var body []byte
	body = append(body, encodeEnum(code)...)
	body = append(body, encodeStr("")...)
	body = append(body, encodeStr(diag)...)
	_ = s.writeMsg(nc, msgID, appTag, body)
}

func (s *MockServer) writeMsg(nc net.Conn, msgID int, opTag byte, body []byte) error {
	msg := encodeSeq(encodeInt(msgID), tlv(opTag, body))
	_ = nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := nc.Write(msg)
	return err
}

// ---- 过滤器求值 ----

type filter interface {
	match(attrs map[string][]string) bool
}

type eqFilter struct{ attr, val string }

func (f eqFilter) match(a map[string][]string) bool {
	for _, v := range a[f.attr] {
		if strings.EqualFold(v, f.val) {
			return true
		}
	}
	return false
}

type presentFilter struct{ attr string }

func (f presentFilter) match(a map[string][]string) bool {
	vs, ok := a[f.attr]
	return ok && len(vs) > 0
}

type andFilter struct{ subs []filter }

func (f andFilter) match(a map[string][]string) bool {
	for _, s := range f.subs {
		if !s.match(a) {
			return false
		}
	}
	return true
}

type orFilter struct{ subs []filter }

func (f orFilter) match(a map[string][]string) bool {
	for _, s := range f.subs {
		if s.match(a) {
			return true
		}
	}
	return false
}

type notFilter struct{ sub filter }

func (f notFilter) match(a map[string][]string) bool { return !f.sub.match(a) }

// extFilter 可扩展匹配：当前仅支持 AD userAccountControl 位判断（:1.2.840.113556.1.4.803:）。
type extFilter struct {
	attr  string
	rule  string
	value string
}

func (f extFilter) match(a map[string][]string) bool {
	if strings.Contains(f.rule, "1.2.840.113556.1.4.803") { // bitAnd
		bit, err := strconv.Atoi(f.value)
		if err != nil {
			return false
		}
		for _, v := range a[f.attr] {
			uac, err := strconv.Atoi(v)
			if err == nil && uac&bit != 0 {
				return true
			}
		}
		return false
	}
	return eqFilter{attr: f.attr, val: f.value}.match(a)
}

func parseFilter(content []byte) (filter, error) {
	tag, err := peekTag(content)
	if err != nil {
		return nil, err
	}
	_, body, err := parseTLV(&byteReader{b: content})
	if err != nil {
		return nil, err
	}
	switch tag {
	case 0xA3: // equalityMatch
		items, err := children(body)
		if err != nil || len(items) != 2 {
			return nil, fmt.Errorf("bad equalityMatch")
		}
		_, attr, _ := parseTLV(&byteReader{b: items[0]})
		_, val, _ := parseTLV(&byteReader{b: items[1]})
		return eqFilter{attr: string(attr), val: string(val)}, nil
	case 0x87: // present
		_, attr, err := parseTLV(&byteReader{b: body})
		if err != nil {
			return nil, err
		}
		return presentFilter{attr: string(attr)}, nil
	case 0xA0: // and
		items, err := children(body)
		if err != nil {
			return nil, err
		}
		subs, err := parseSubFilters(items)
		if err != nil {
			return nil, err
		}
		return andFilter{subs: subs}, nil
	case 0xA1: // or
		items, err := children(body)
		if err != nil {
			return nil, err
		}
		subs, err := parseSubFilters(items)
		if err != nil {
			return nil, err
		}
		return orFilter{subs: subs}, nil
	case 0xA2: // not
		sub, err := parseFilter(body)
		if err != nil {
			return nil, err
		}
		return notFilter{sub: sub}, nil
	case 0xA9: // extensibleMatch
		items, err := children(body)
		if err != nil {
			return nil, err
		}
		var f extFilter
		for _, it := range items {
			itTag, itBody, err := parseTLV(&byteReader{b: it})
			if err != nil {
				continue
			}
			switch itTag {
			case 0x82: // [2] type（属性名）
				f.attr = string(itBody)
			case 0x81: // [1] matchingRule
				f.rule = string(itBody)
			case 0x83: // [3] matchValue
				f.value = string(itBody)
			}
		}
		return f, nil
	default:
		return nil, fmt.Errorf("unsupported filter tag 0x%02x", tag)
	}
}

func parseSubFilters(items [][]byte) ([]filter, error) {
	var out []filter
	for _, it := range items {
		f, err := parseFilter(it)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func peekTag(content []byte) (byte, error) {
	if len(content) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return content[0], nil
}
