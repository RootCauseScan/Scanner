use std::collections::HashSet;

use crate::catalog::Catalog;

pub fn load_catalog() -> Catalog {
    Catalog {
        sources: HashSet::from([
            // HTTP/request-derived input
            "HttpServletRequest.getParameter".into(),
            "HttpServletRequest.getParameterValues".into(),
            "HttpServletRequest.getHeader".into(),
            "HttpServletRequest.getQueryString".into(),
            "jakarta.servlet.http.HttpServletRequest.getParameter".into(),
            "jakarta.servlet.http.HttpServletRequest.getHeader".into(),
            "javax.servlet.http.HttpServletRequest.getParameter".into(),
            "javax.servlet.http.HttpServletRequest.getHeader".into(),
            // Environment / process input
            "System.getenv".into(),
            "java.lang.System.getenv".into(),
            // Untrusted deserialization / parser entrypoints
            "ObjectMapper.readValue".into(),
            "com.fasterxml.jackson.databind.ObjectMapper.readValue".into(),
            "Gson.fromJson".into(),
            "com.google.gson.Gson.fromJson".into(),
        ]),
        sinks: HashSet::from([
            // Dynamic SQL execution
            "Statement.execute".into(),
            "Statement.executeQuery".into(),
            "Statement.executeUpdate".into(),
            "java.sql.Statement.execute".into(),
            "java.sql.Statement.executeQuery".into(),
            "java.sql.Statement.executeUpdate".into(),
            // Command execution
            "Runtime.getRuntime().exec".into(),
            "Runtime.exec".into(),
            "java.lang.Runtime.exec".into(),
            "ProcessBuilder.start".into(),
            "java.lang.ProcessBuilder.start".into(),
            // Reflection / class loading
            "Class.forName".into(),
            "Method.invoke".into(),
            "java.lang.reflect.Method.invoke".into(),
            // Critical path/file access
            "Files.newInputStream".into(),
            "Files.newOutputStream".into(),
            "java.nio.file.Files.newInputStream".into(),
            "java.nio.file.Files.newOutputStream".into(),
            "FileInputStream".into(),
            "java.io.FileInputStream".into(),
        ]),
        sanitizers: HashSet::from([
            "StringEscapeUtils.escapeHtml".into(),
            "org.apache.commons.text.StringEscapeUtils.escapeHtml".into(),
            "StringEscapeUtils.escapeEcmaScript".into(),
            "org.apache.commons.text.StringEscapeUtils.escapeEcmaScript".into(),
            "StringEscapeUtils.escapeJson".into(),
            "org.apache.commons.text.StringEscapeUtils.escapeJson".into(),
            "Encode.forHtml".into(),
            "org.owasp.encoder.Encode.forHtml".into(),
            "Encode.forJavaScript".into(),
            "org.owasp.encoder.Encode.forJavaScript".into(),
            "Encode.forUriComponent".into(),
            "org.owasp.encoder.Encode.forUriComponent".into(),
            "ESAPI.encoder().encodeForHTML".into(),
            "org.owasp.esapi.ESAPI.encoder().encodeForHTML".into(),
            "Jsoup.clean".into(),
            "org.jsoup.Jsoup.clean".into(),
        ]),
    }
}
