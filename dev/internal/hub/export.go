// 报表/审计导出（W1-6 资产报表导出、W1-7 日志导出）。
// 纯标准库实现：CSV 直接写；XLSX 用 archive/zip + XML 手写最小工作簿
// （单 sheet、字符串/数字单元格、无样式依赖），不引入第三方依赖。
package hub

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"yuduan/internal/audit"
	"yuduan/internal/store"
)

// ---- W1-6 资产报表导出 ----

// writeDevicesCSV 以 CSV 输出设备台账。
func writeDevicesCSV(w http.ResponseWriter, list []store.Device) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="yuduan-devices.csv"`)
	bw := &bytes.Buffer{}
	cw := csv.NewWriter(bw)
	_ = cw.Write([]string{"ID", "主机名", "OS", "OS版本", "架构", "CPU", "内存GB", "磁盘GB", "序列号", "MAC", "IP", "连接来源", "状态", "部门", "楼层", "批次", "标签", "生命周期", "领用人", "副端版本", "最后心跳"})
	for _, d := range list {
		status := "离线"
		if d.Online {
			status = "在线"
		}
		_ = cw.Write([]string{
			d.ID, d.Hostname, d.OS, d.OSVersion, d.Arch, d.CPU,
			itoa(d.MemoryGB), itoa(d.DiskGB), d.SerialNo, d.MAC, d.IP, d.SourceAddr,
			status, d.Department, d.Floor, d.Batch, strings.Join(d.TagList(), "|"),
			d.Lifecycle, d.Assignee, d.AgentVersion,
			d.LastSeen.Format(time.RFC3339),
		})
	}
	cw.Flush()
	_, _ = w.Write(bw.Bytes())
}

// writeDevicesXLSX 以最小合法 XLSX 输出设备台账（单 sheet，首行表头）。
func writeDevicesXLSX(w http.ResponseWriter, list []store.Device) {
	headers := []string{"ID", "主机名", "OS", "OS版本", "架构", "CPU", "内存GB", "磁盘GB", "序列号", "MAC", "IP", "连接来源", "状态", "部门", "楼层", "批次", "标签", "生命周期", "领用人", "副端版本", "最后心跳"}
	rows := make([][]string, 0, len(list))
	for _, d := range list {
		status := "离线"
		if d.Online {
			status = "在线"
		}
		rows = append(rows, []string{
			d.ID, d.Hostname, d.OS, d.OSVersion, d.Arch, d.CPU,
			itoa(d.MemoryGB), itoa(d.DiskGB), d.SerialNo, d.MAC, d.IP, d.SourceAddr,
			status, d.Department, d.Floor, d.Batch, strings.Join(d.TagList(), "|"),
			d.Lifecycle, d.Assignee, d.AgentVersion, d.LastSeen.Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
	w.Header().Set("Content-Disposition", `attachment; filename="yuduan-devices.xlsx"`)
	data := buildXLSX("设备台账", headers, rows)
	_, _ = w.Write(data)
}

// ---- W1-7 审计日志导出 ----

// writeAuditCSV 以 CSV 输出审计事件。
func writeAuditCSV(w http.ResponseWriter, events []audit.Event) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="yuduan-audit.csv"`)
	bw := &bytes.Buffer{}
	cw := csv.NewWriter(bw)
	// v0.4.31-D：补 prev_hash 列（离线重放需逐条前序哈希重建链）。
	_ = cw.Write([]string{"ID", "时间", "操作人", "动作", "对象", "详情", "结果", "前序哈希", "哈希"})
	for _, e := range events {
		_ = cw.Write([]string{
			strconv.FormatInt(e.ID, 10),
			time.Unix(e.Time, 0).Format(time.RFC3339),
			e.Actor, e.Action, e.Target, e.Detail, e.Result, e.PrevHash, e.Hash,
		})
	}
	cw.Flush()
	_, _ = w.Write(bw.Bytes())
}

// writeAuditJSON 以 JSON 数组输出审计事件（保留 WORM 哈希字段，供离线核验）。
func writeAuditJSON(w http.ResponseWriter, events []audit.Event) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="yuduan-audit.json"`)
	_ = json.NewEncoder(w).Encode(events)
}

// ---- 最小 XLSX 写入器（archive/zip + 手写 XML）----

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// sheetXML 生成单个 worksheet 的 XML。单元格用 t="inlineStr" 字符串或数值。
func sheetXML(headers []string, rows [][]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	writeRow := func(cells []string) {
		b.WriteString(`<row>`)
		for _, c := range cells {
			if n, err := strconv.Atoi(c); err == nil {
				b.WriteString(`<c t="n"><v>` + strconv.Itoa(n) + `</v></c>`)
			} else {
				b.WriteString(`<c t="inlineStr"><is><t>` + xmlEscape(c) + `</t></is></c>`)
			}
		}
		b.WriteString(`</row>`)
	}
	writeRow(headers)
	for _, r := range rows {
		writeRow(r)
	}
	b.WriteString(`</sheetData></worksheet>`)
	return b.String()
}

// buildXLSX 打包一个最小合法 xlsx（zip 容器 + 必要部件）。
func buildXLSX(title string, headers []string, rows [][]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, content string) {
		f, _ := zw.Create(name)
		_, _ = f.Write([]byte(content))
	}
	// 必需部件
	add(`[Content_Types].xml`, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>`)
	add(`_rels/.rels`, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`)
	add(`xl/workbook.xml`, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="`+xmlEscape(title)+`" sheetId="1" r:id="rId1"/></sheets>
</workbook>`)
	add(`xl/_rels/workbook.xml.rels`, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>`)
	add(`xl/styles.xml`, `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="1"><fill><patternFill patternType="none"/></fill></fills>
<borders count="1"><border/></borders>
<cellStyleXfs count="1"><xf/></cellStyleXfs>
<cellXfs count="1"><xf/></cellXfs>
</styleSheet>`)
	add(`xl/worksheets/sheet1.xml`, sheetXML(headers, rows))
	_ = zw.Close()
	return buf.Bytes()
}
