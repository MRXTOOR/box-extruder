package report

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// OOXML fragments match internal/report/templates/enterprise-reference.docx (SAST/SCA/CA).

const (
	corpTblPr2Col = `<w:tblPr><w:tblW w:w="0" w:type="auto"/><w:jc w:val="center"/><w:tblCellMar><w:top w:w="15" w:type="dxa"/><w:left w:w="15" w:type="dxa"/><w:bottom w:w="15" w:type="dxa"/><w:right w:w="15" w:type="dxa"/></w:tblCellMar><w:tblLook w:val="04A0" w:firstRow="1" w:lastRow="0" w:firstColumn="1" w:lastColumn="0" w:noHBand="0" w:noVBand="1"/></w:tblPr>`
	corpTblGrid2Col = `<w:tblGrid><w:gridCol w:w="2909"/><w:gridCol w:w="5078"/></w:tblGrid>`
	corpTblGrid6Col = `<w:tblGrid><w:gridCol w:w="701"/><w:gridCol w:w="1985"/><w:gridCol w:w="4677"/><w:gridCol w:w="1134"/><w:gridCol w:w="1701"/><w:gridCol w:w="1134"/></w:tblGrid>`
	corpTcBorders   = `<w:tcBorders><w:top w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:left w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:bottom w:val="single" w:sz="6" w:space="0" w:color="000000"/><w:right w:val="single" w:sz="6" w:space="0" w:color="000000"/></w:tcBorders>`
	corpTcMar       = `<w:tcMar><w:top w:w="160" w:type="dxa"/><w:left w:w="160" w:type="dxa"/><w:bottom w:w="160" w:type="dxa"/><w:right w:w="160" w:type="dxa"/></w:tcMar>`
	corpRunRPr      = `<w:rFonts w:cs="Arial"/><w:color w:val="000000" w:themeColor="text1"/><w:sz w:val="20"/><w:szCs w:val="20"/>`
)

func corpTitle(buf *bytes.Buffer) {
	buf.WriteString(`<w:p><w:pPr><w:pStyle w:val="T15"/></w:pPr></w:p>`)
	buf.WriteString(`<w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="center"/><w:rPr><w:rFonts w:eastAsiaTheme="majorEastAsia" w:cs="Arial"/><w:bCs/><w:color w:val="000000" w:themeColor="text1"/></w:rPr></w:pPr>`)
	buf.WriteString(`<w:r><w:rPr><w:rFonts w:eastAsiaTheme="majorEastAsia" w:cs="Arial"/><w:bCs/><w:color w:val="000000" w:themeColor="text1"/></w:rPr><w:t>Отчёт</w:t></w:r></w:p>`)
	buf.WriteString(`<w:p><w:pPr><w:jc w:val="center"/><w:rPr><w:rFonts w:eastAsiaTheme="majorEastAsia" w:cs="Arial"/><w:bCs/><w:color w:val="000000" w:themeColor="text1"/></w:rPr></w:pPr>`)
	buf.WriteString(`<w:r><w:rPr><w:rFonts w:eastAsiaTheme="majorEastAsia" w:cs="Arial"/><w:bCs/><w:color w:val="000000" w:themeColor="text1"/></w:rPr><w:t>о проведении тестирования безопасности программного продукта</w:t></w:r></w:p>`)
}

func corpSection(buf *bytes.Buffer, level int, title string) {
	ilvl := level - 1
	if ilvl < 0 {
		ilvl = 0
	}
	buf.WriteString(`<w:p><w:pPr><w:pStyle w:val="af1"/><w:numPr><w:ilvl w:val="`)
	buf.WriteString(strconv.Itoa(ilvl))
	buf.WriteString(`"/><w:numId w:val="22"/></w:numPr><w:jc w:val="both"/><w:rPr><w:rFonts w:eastAsiaTheme="majorEastAsia" w:cs="Arial"/><w:bCs/><w:color w:val="000000" w:themeColor="text1"/></w:rPr></w:pPr>`)
	buf.WriteString(`<w:r><w:rPr><w:rFonts w:eastAsiaTheme="majorEastAsia" w:cs="Arial"/><w:bCs/><w:color w:val="000000" w:themeColor="text1"/></w:rPr><w:t>`)
	buf.WriteString(escapeDocxText(title))
	buf.WriteString(`</w:t></w:r></w:p>`)
}

func corpBody(buf *bytes.Buffer, text string) {
	buf.WriteString(`<w:p><w:pPr><w:pStyle w:val="T15"/><w:jc w:val="both"/><w:rPr>`)
	buf.WriteString(corpRunRPr)
	buf.WriteString(`</w:rPr></w:pPr><w:r><w:rPr>`)
	buf.WriteString(corpRunRPr)
	buf.WriteString(`</w:rPr><w:t xml:space="preserve">`)
	buf.WriteString(escapeDocxText(text))
	buf.WriteString(`</w:t></w:r></w:p>`)
}

func corpInfoTable(buf *bytes.Buffer, rows [][2]string) {
	buf.WriteString(`<w:tbl>`)
	buf.WriteString(corpTblPr2Col)
	buf.WriteString(corpTblGrid2Col)
	corpInfoHeaderRow(buf)
	for _, row := range rows {
		corpInfoDataRow(buf, row[0], row[1])
	}
	buf.WriteString(`</w:tbl>`)
}

func corpInfoHeaderRow(buf *bytes.Buffer) {
	buf.WriteString(`<w:tr><w:trPr><w:jc w:val="center"/></w:trPr>`)
	corpHeaderCell(buf, "Параметр", "")
	corpHeaderCell(buf, "Значение", "")
	buf.WriteString(`</w:tr>`)
}

func corpInfoDataRow(buf *bytes.Buffer, label, value string) {
	buf.WriteString(`<w:tr><w:trPr><w:jc w:val="center"/></w:trPr>`)
	corpDataCell(buf, label, "", "both", false)
	corpDataCell(buf, value, "", "both", true)
	buf.WriteString(`</w:tr>`)
}

func corpFindingsTable(buf *bytes.Buffer, headers []string, rows [][]string, widths []string) {
	buf.WriteString(`<w:tbl>`)
	buf.WriteString(corpTblPr2Col)
	buf.WriteString(corpTblGrid6Col)
	buf.WriteString(`<w:tr><w:trPr><w:jc w:val="center"/></w:trPr>`)
	for i, h := range headers {
		w := ""
		if i < len(widths) {
			w = widths[i]
		}
		corpHeaderCell(buf, h, w)
	}
	buf.WriteString(`</w:tr>`)
	for _, row := range rows {
		buf.WriteString(`<w:tr><w:trPr><w:jc w:val="center"/></w:trPr>`)
		for i := range headers {
			val := ""
			if i < len(row) {
				val = row[i]
			}
			w := ""
			if i < len(widths) {
				w = widths[i]
			}
			align := "both"
			if i == 0 {
				align = "center"
			}
			corpDataCell(buf, val, w, align, false)
		}
		buf.WriteString(`</w:tr>`)
	}
	buf.WriteString(`</w:tbl>`)
}

func corpHeaderCell(buf *bytes.Buffer, text, widthDxa string) {
	buf.WriteString(`<w:tc><w:tcPr>`)
	if widthDxa != "" {
		buf.WriteString(`<w:tcW w:w="`)
		buf.WriteString(widthDxa)
		buf.WriteString(`" w:type="dxa"/>`)
	} else {
		buf.WriteString(`<w:tcW w:w="0" w:type="auto"/>`)
	}
	buf.WriteString(corpTcBorders)
	buf.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/>`)
	buf.WriteString(corpTcMar)
	buf.WriteString(`<w:hideMark/></w:tcPr><w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="center"/><w:rPr>`)
	buf.WriteString(corpRunRPr)
	buf.WriteString(`<w:b/></w:rPr></w:pPr><w:r><w:rPr>`)
	buf.WriteString(corpRunRPr)
	buf.WriteString(`<w:b/></w:rPr><w:t>`)
	buf.WriteString(escapeDocxText(text))
	buf.WriteString(`</w:t></w:r></w:p></w:tc>`)
}

func corpDataCell(buf *bytes.Buffer, text, widthDxa, jc string, italic bool) {
	buf.WriteString(`<w:tc><w:tcPr>`)
	if widthDxa != "" {
		fmt.Fprintf(buf, `<w:tcW w:w="%s" w:type="dxa"/>`, widthDxa)
	} else {
		buf.WriteString(`<w:tcW w:w="0" w:type="auto"/>`)
	}
	buf.WriteString(corpTcBorders)
	buf.WriteString(corpTcMar)
	buf.WriteString(`<w:hideMark/></w:tcPr><w:p><w:pPr><w:spacing w:after="0"/><w:jc w:val="`)
	buf.WriteString(jc)
	buf.WriteString(`"/><w:rPr>`)
	buf.WriteString(corpRunRPr)
	if italic {
		buf.WriteString(`<w:i/>`)
	}
	buf.WriteString(`</w:rPr></w:pPr>`)
	corpWriteRuns(buf, text, italic)
	buf.WriteString(`</w:p></w:tc>`)
}

func corpWriteRuns(buf *bytes.Buffer, text string, italic bool) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if i > 0 {
			buf.WriteString(`<w:r><w:rPr>`)
			buf.WriteString(corpRunRPr)
			if italic {
				buf.WriteString(`<w:i/>`)
			}
			buf.WriteString(`</w:rPr><w:br/></w:r>`)
		}
		buf.WriteString(`<w:r><w:rPr>`)
		buf.WriteString(corpRunRPr)
		if italic {
			buf.WriteString(`<w:i/>`)
		}
		buf.WriteString(`</w:rPr><w:t xml:space="preserve">`)
		buf.WriteString(escapeDocxText(line))
		buf.WriteString(`</w:t></w:r>`)
	}
}

var corpFindingColWidths = []string{"701", "1985", "4677", "1134", "1701", "1134"}
