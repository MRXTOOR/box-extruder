# Шаблон Word-отчёта (корпоративный стиль)

`enterprise-reference.docx` — эталон оформления отчёта «Отчёт о проведении тестирования
безопасности программного продукта» (как для SAST/SCA). Pandoc использует его как
`--reference-doc` при сборке `report.docx`: сохраняются шрифты, заголовки и таблицы.

Содержимое для **DAST** (HTML/PDF/DOCX): `WriteEnterpriseHTMLReport`, `EnsureDocxReport`,
`EnsurePdfReport` — разделы и таблицы как в корпоративном отчёте SAST/SCA.
Markdown (`report.md`) не публикуется.

Заменить шаблон: положите свой `.docx` с тем же именем файла и пересоберите worker.

Если файла нет (ошибка `go:embed templates/enterprise-reference.docx: no matching files`):

```bash
go run internal/report/tools/gen_enterprise_template/main.go
```
