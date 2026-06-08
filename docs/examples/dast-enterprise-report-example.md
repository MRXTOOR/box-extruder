# Пример корпоративного DAST-отчёта

Готовые файлы (сгенерированы из шаблона `internal/report/templates/enterprise-reference.docx`):

| Файл | Описание |
| --- | --- |
| [dast-enterprise-report-example.docx](./dast-enterprise-report-example.docx) | Word-отчёт (как SAST/SCA) |
| [dast-enterprise-report-example.html](./dast-enterprise-report-example.html) | HTML-версия для просмотра в браузере |

Пересобрать пример:

```bash
go run internal/report/tools/gen_example_report/main.go
```

Тестовые данные: сканирование `https://kubikvpn.com`, preset **Fast**, 12 типовых находок (ZAP, Nuclei, Wapiti).
