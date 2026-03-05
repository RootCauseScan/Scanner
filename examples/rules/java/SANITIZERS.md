# Java Default Security Catalog

This parser ships with a default Java catalog used by taint tracking.

## Sources

Typical untrusted entry points treated as `source` by default:

- HTTP request input:
  - `HttpServletRequest.getParameter`
  - `HttpServletRequest.getParameterValues`
  - `HttpServletRequest.getHeader`
  - `HttpServletRequest.getQueryString`
  - `jakarta.servlet.http.HttpServletRequest.getParameter`
  - `javax.servlet.http.HttpServletRequest.getParameter`
- Environment/process input:
  - `System.getenv`
  - `java.lang.System.getenv`
- Untrusted deserialization/parsing:
  - `ObjectMapper.readValue`
  - `com.fasterxml.jackson.databind.ObjectMapper.readValue`
  - `Gson.fromJson`
  - `com.google.gson.Gson.fromJson`

## Sinks

High-impact operations treated as `sink` by default:

- Dynamic SQL:
  - `Statement.execute`
  - `Statement.executeQuery`
  - `Statement.executeUpdate`
  - `java.sql.Statement.execute`
  - `java.sql.Statement.executeQuery`
- Command execution:
  - `Runtime.getRuntime().exec`
  - `Runtime.exec`
  - `java.lang.Runtime.exec`
  - `ProcessBuilder.start`
- Reflection/class loading:
  - `Class.forName`
  - `Method.invoke`
  - `java.lang.reflect.Method.invoke`
- Critical file/path access:
  - `Files.newInputStream`
  - `Files.newOutputStream`
  - `java.nio.file.Files.newInputStream`
  - `FileInputStream`

## Sanitizers

Known sanitization APIs treated as `sanitizer` by default:

- Apache Commons Text:
  - `StringEscapeUtils.escapeHtml`
  - `org.apache.commons.text.StringEscapeUtils.escapeHtml`
  - `StringEscapeUtils.escapeEcmaScript`
  - `StringEscapeUtils.escapeJson`
- OWASP Java Encoder:
  - `Encode.forHtml`
  - `org.owasp.encoder.Encode.forHtml`
  - `Encode.forJavaScript`
  - `Encode.forUriComponent`
- OWASP ESAPI:
  - `ESAPI.encoder().encodeForHTML`
  - `org.owasp.esapi.ESAPI.encoder().encodeForHTML`
- HTML cleanup:
  - `Jsoup.clean`
  - `org.jsoup.Jsoup.clean`

---

You can extend any of these sets at runtime using the shared catalog extension API.
