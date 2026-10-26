// Package pg 是御端在受限环境（无法拉取第三方驱动）下自研的最小化 PostgreSQL 客户端。
// 覆盖御端所需的全部能力：trust / 明文口令认证、文本格式行解析、
// 扩展协议参数化查询（$1..$n，杜绝 SQL 注入）、连接池、LISTEN/NOTIFY 监听。
// 生产环境如需更完整能力，可替换为 github.com/lib/pq 或 pgx（见安全里程碑文档）。
package pg

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Conn 表示一个 Postgres 连接。
type Conn struct {
	conn net.Conn
	buf  *bufio.Reader
}

// Connect 建立连接并完成启动/认证握手，直到收到 ReadyForQuery。
// 支持 trust（无口令）与 cleartext（明文口令）两种认证方式。
func Connect(host string, port int, user, database, password string) (*Conn, error) {
	nc, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	c := &Conn{conn: nc, buf: bufio.NewReader(nc)}

	// 构造启动消息（无类型字节）：长度 + 协议版本 + 参数键值对 + 终结 \0
	params := encodeParams("user", user, "database", database)
	body := make([]byte, 0, len(params)+4)
	body = append(body, 0x00, 0x03, 0x00, 0x00) // 协议版本 196608
	body = append(body, params...)
	startup := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(startup[0:4], uint32(len(startup)))
	copy(startup[4:], body)
	if _, err := nc.Write(startup); err != nil {
		return nil, err
	}

	// 读取直到 ReadyForQuery('Z')，期间处理认证请求
	for {
		tag, body, err := c.readMessage()
		if err != nil {
			return nil, err
		}
		switch tag {
		case 'R': // AuthenticationRequest
			authType := int32(binary.BigEndian.Uint32(body[0:4]))
			switch authType {
			case 0: // OK
				continue
			case 3: // CleartextPassword
				if err := c.writeMessage('p', []byte(password+"\x00")); err != nil {
					return nil, err
				}
			default:
				return nil, fmt.Errorf("unsupported auth type %d", authType)
			}
		case 'K', 'S', 'N': // BackendKeyData / ParameterStatus / Notice
			continue
		case 'E': // Error
			return nil, fmt.Errorf("pg error: %s", parseErr(body))
		case 'Z': // ReadyForQuery
			return c, nil
		default:
			continue
		}
	}
}

// Query 执行一条简单查询，返回列名与文本行（二维字符串）。
func (c *Conn) Query(sql string) ([]string, [][]string, error) {
	if err := c.writeMessage('Q', []byte(sql+"\x00")); err != nil {
		return nil, nil, err
	}
	var cols []string
	var rows [][]string
	for {
		tag, body, err := c.readMessage()
		if err != nil {
			return nil, nil, err
		}
		switch tag {
		case 'T': // RowDescription
			cols = parseRowDesc(body)
		case 'D': // DataRow
			rows = append(rows, parseDataRow(body))
		case 'C', 'I': // CommandComplete / EmptyQuery
			continue
		case 'E':
			return nil, nil, fmt.Errorf("pg error: %s", parseErr(body))
		case 'Z':
			return cols, rows, nil
		default:
			continue
		}
	}
}

// Exec 执行不关心结果集的语句（INSERT/UPDATE/CREATE 等）。
func (c *Conn) Exec(sql string) error {
	_, _, err := c.Query(sql)
	return err
}

// Close 关闭连接。
func (c *Conn) Close() error { return c.conn.Close() }

// ---- 扩展协议：参数化查询（$1..$n） ----

// QueryArgs 以扩展协议执行参数化查询。参数以文本格式发送、类型由服务端推断，
// 语义等价于 database/sql 的 $n 占位符，彻底规避 SQL 注入。
// 支持的参数类型：string / []byte / int / int64 / float64 / bool / time.Time / nil。
func (c *Conn) QueryArgs(sql string, args ...any) ([]string, [][]string, error) {
	// 统计占位符数量（仅用于 Parse 的 numParams；多算无害，少算会绑定失败）
	nParams := 0
	for i := 0; i < len(sql); i++ {
		if sql[i] == '$' && i+1 < len(sql) && sql[i+1] >= '0' && sql[i+1] <= '9' {
			nParams++
		}
	}
	// Parse
	parse := append(cstring(""), append(cstring(sql), u16(0)...)...)
	if err := c.writeMessage('P', parse); err != nil {
		return nil, nil, err
	}
	// Bind
	var bind []byte
	bind = append(bind, cstring("")...) // portal
	bind = append(bind, cstring("")...) // statement
	bind = append(bind, u16(0)...)      // 结果格式全部文本
	bind = append(bind, u16(len(args))...)
	for _, a := range args {
		bind = append(bind, encodeParam(a)...)
	}
	bind = append(bind, u16(0)...) // 结果列格式全部文本
	if err := c.writeMessage('B', bind); err != nil {
		return nil, nil, err
	}
	// Execute + Sync
	if err := c.writeMessage('E', append(cstring(""), u32(0)...)); err != nil {
		return nil, nil, err
	}
	if err := c.writeMessage('S', nil); err != nil {
		return nil, nil, err
	}
	var cols []string
	var rows [][]string
	for {
		tag, body, err := c.readMessage()
		if err != nil {
			return nil, nil, err
		}
		switch tag {
		case 'T': // RowDescription
			cols = parseRowDesc(body)
		case 'D': // DataRow
			rows = append(rows, parseDataRow(body))
		case 'C', 'I': // CommandComplete / EmptyQuery
			continue
		case '1', '2', 't', 'n': // ParseComplete / BindComplete / ParameterDescription / NoData
			continue
		case 'E':
			return nil, nil, fmt.Errorf("pg error: %s", parseErr(body))
		case 'Z': // ReadyForQuery
			return cols, rows, nil
		default:
			continue
		}
	}
}

// ExecArgs 以扩展协议执行参数化写语句。
func (c *Conn) ExecArgs(sql string, args ...any) error {
	_, _, err := c.QueryArgs(sql, args...)
	return err
}

func encodeParam(a any) []byte {
	var out []byte
	switch v := a.(type) {
	case nil:
		return u32(0xFFFFFFFF) // NULL
	case string:
		out = []byte(v)
	case []byte:
		out = v
	case int:
		out = []byte(strconv.Itoa(v))
	case int64:
		out = []byte(strconv.FormatInt(v, 10))
	case float64:
		out = []byte(strconv.FormatFloat(v, 'g', -1, 64))
	case bool:
		if v {
			out = []byte("t")
		} else {
			out = []byte("f")
		}
	case time.Time:
		out = []byte(v.UTC().Format("2006-01-02 15:04:05"))
	default:
		out = []byte(fmt.Sprint(v))
	}
	return append(u32(uint32(len(out))), out...)
}

func cstring(s string) []byte {
	b := []byte(s)
	return append(b, 0)
}

func u16(n int) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(n))
	return b
}

func u32(n uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return b
}

// ---- 内部：消息读写 ----

func (c *Conn) writeMessage(tag byte, body []byte) error {
	msg := make([]byte, 1+4+len(body))
	msg[0] = tag
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(body)+4))
	copy(msg[5:], body)
	_, err := c.conn.Write(msg)
	return err
}

func (c *Conn) readMessage() (byte, []byte, error) {
	tag, err := c.buf.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(c.buf, lengthBytes[:]); err != nil {
		return 0, nil, err
	}
	length := int(binary.BigEndian.Uint32(lengthBytes[:])) - 4
	if length < 0 {
		return 0, nil, errors.New("pg: negative message length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(c.buf, body); err != nil {
		return 0, nil, err
	}
	return tag, body, nil
}

// ---- 内部：解析 ----

func encodeParams(kv ...string) []byte {
	var b []byte
	for i := 0; i+1 < len(kv); i += 2 {
		b = append(b, kv[i]...)
		b = append(b, 0)
		b = append(b, kv[i+1]...)
		b = append(b, 0)
	}
	b = append(b, 0)
	return b
}

func parseRowDesc(body []byte) []string {
	count := int(int16(binary.BigEndian.Uint16(body[0:2])))
	off := 2
	cols := make([]string, 0, count)
	for i := 0; i < count; i++ {
		end := off
		for body[end] != 0 {
			end++
		}
		cols = append(cols, string(body[off:end]))
		off = end + 1
		off += 18 // tableOID(4)+col(2)+typeOID(4)+typeSize(2)+typeMod(4)+format(2)
	}
	return cols
}

func parseDataRow(body []byte) []string {
	count := int(int16(binary.BigEndian.Uint16(body[0:2])))
	off := 2
	cells := make([]string, 0, count)
	for i := 0; i < count; i++ {
		l := int(int32(binary.BigEndian.Uint32(body[off : off+4])))
		off += 4
		if l == -1 {
			cells = append(cells, "")
			continue
		}
		cells = append(cells, string(body[off:off+l]))
		off += l
	}
	return cells
}

func parseErr(body []byte) string {
	// 形如：多组 key\0value\0 结尾 \0；提取 M=消息
	fields := strings.Split(string(body), "\x00")
	for i := 0; i+1 < len(fields); i += 2 {
		if fields[i] == "M" {
			return fields[i+1]
		}
	}
	// 兜底：带原始体（十六进制）便于诊断非常规 ErrorResponse
	return fmt.Sprintf("unknown error (raw=%x)", body)
}

// ---- 连接池 ----

// Pool 是最小连接池：有界并发、空闲复用、坏连接自动剔除、满载等待。
type Pool struct {
	dial       func() (*Conn, error)
	maxTotal   int
	idleTarget int

	mu     sync.Mutex
	cond   *sync.Cond
	idle   []*Conn
	total  int
	inUse  int
	closed bool
}

// NewPool 建立连接池并预热 idleTarget 条连接（任一失败即返回错误）。
func NewPool(idleTarget, maxTotal int, dial func() (*Conn, error)) (*Pool, error) {
	if idleTarget < 1 {
		idleTarget = 1
	}
	if maxTotal < idleTarget {
		maxTotal = idleTarget
	}
	p := &Pool{dial: dial, maxTotal: maxTotal, idleTarget: idleTarget}
	p.cond = sync.NewCond(&p.mu)
	for i := 0; i < idleTarget; i++ {
		c, err := dial()
		if err != nil {
			p.Close()
			return nil, err
		}
		p.idle = append(p.idle, c)
		p.total++
	}
	return p, nil
}

// Acquire 取一条连接：优先复用空闲；无空闲且未达上限则新建；满载则等待。
func (p *Pool) Acquire() (*Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if p.closed {
			return nil, errors.New("pg: pool closed")
		}
		if n := len(p.idle); n > 0 {
			c := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.inUse++
			return c, nil
		}
		if p.total < p.maxTotal {
			p.total++
			p.mu.Unlock()
			c, err := p.dial()
			p.mu.Lock()
			if err != nil {
				p.total--
				p.cond.Broadcast()
				return nil, err
			}
			p.inUse++
			return c, nil
		}
		p.cond.Wait()
	}
}

// Release 归还连接；空闲超过水位则直接关闭以控制资源。
func (p *Pool) Release(c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inUse--
	if p.closed {
		_ = c.Close()
		p.total--
		return
	}
	if len(p.idle) < p.idleTarget {
		p.idle = append(p.idle, c)
	} else {
		_ = c.Close()
		p.total--
	}
	p.cond.Broadcast()
}

// Discard 丢弃坏连接（不归还池）。
func (p *Pool) Discard(c *Conn) {
	_ = c.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inUse--
	p.total--
	p.cond.Broadcast()
}

// Close 关闭池内全部连接。
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for _, c := range p.idle {
		_ = c.Close()
	}
	p.idle = nil
	p.total = 0
	p.cond.Broadcast()
}

// Stats 返回池状态快照。
func (p *Pool) Stats() (idle, inUse, total int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.idle), p.inUse, p.total
}

// ---- LISTEN/NOTIFY 监听器 ----

// Listener 在独立连接上 LISTEN 指定频道，后台协程读取 NotificationResponse。
// 该连接专用于监听，不承载普通查询。
type Listener struct {
	conn *Conn
	ch   chan string
	done chan struct{}
	once sync.Once
}

// NewListener 建立监听连接并订阅频道。
func NewListener(host string, port int, user, database, password, channel string) (*Listener, error) {
	c, err := Connect(host, port, user, database, password)
	if err != nil {
		return nil, err
	}
	if err := c.Exec("LISTEN " + channel); err != nil {
		_ = c.Close()
		return nil, err
	}
	l := &Listener{conn: c, ch: make(chan string, 64), done: make(chan struct{})}
	go l.readLoop()
	return l, nil
}

// Notifications 返回通知通道（payload 字符串）。
func (l *Listener) Notifications() <-chan string { return l.ch }

// Close 停止监听并关闭连接。
func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.conn.Close()
}

func (l *Listener) readLoop() {
	for {
		select {
		case <-l.done:
			return
		default:
		}
		tag, body, err := l.conn.readMessage()
		if err != nil {
			return
		}
		if tag != 'A' { // 'A' = NotificationResponse；其余（Z/E/N/K）与本连接无关
			continue
		}
		// 布局：int32 pid + channel\0 + payload\0
		if len(body) < 4 {
			continue
		}
		rest := body[4:]
		idx := indexByte(rest, 0)
		if idx < 0 {
			continue
		}
		payload := rest[idx+1:]
		if end := indexByte(payload, 0); end >= 0 {
			payload = payload[:end]
		}
		select {
		case l.ch <- string(payload):
		case <-l.done:
			return
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

// NewListenerFromDSN 从 DSN（host=.. port=.. user=.. dbname=.. password=..）建立监听器。
func NewListenerFromDSN(dsn, channel string) (*Listener, error) {
	host, port, user, dbname, password := "127.0.0.1", 5432, "", "", ""
	for _, kv := range strings.Fields(dsn) {
		p := strings.SplitN(kv, "=", 2)
		if len(p) != 2 {
			continue
		}
		switch p[0] {
		case "host":
			host = p[1]
		case "port":
			port, _ = strconv.Atoi(p[1])
		case "user":
			user = p[1]
		case "dbname", "database":
			dbname = p[1]
		case "password":
			password = p[1]
		}
	}
	return NewListener(host, port, user, dbname, password, channel)
}
