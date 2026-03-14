# Tests flexibles (examples/tests)

Cada suite bajo `examples/tests/<suite>/` tiene:

- **rules/** – Reglas a cargar (YAML/JSON/Semgrep)
- **good/** – Código que **no** debe producir hallazgos
- **bad/** – Código que **sí** debe producir al menos un hallazgo (en esa suite)

El test `dynamic_examples_should_match_expectations` (en `crates/engine/tests/examples_dynamic.rs`) recorre todas las suites, carga las reglas y comprueba:

1. Todos los archivos en `good/` → 0 findings.
2. Al menos un archivo en `bad/` → ≥1 finding (por suite puede haber warning si no hay ningún match).

## Suites de regresión del scanner

Estas suites aseguran que el **scanner** se comporta bien (no que las reglas estén bien escritas).

| Suite | Qué asegura |
|-------|-------------|
| **scanner-yaml-infer-language** | Reglas sin campo `languages` obtienen idioma por la ruta del fichero (p. ej. `rules/python/rule.yaml` → solo Python). Así una regla de Python **no** se aplica a PHP (evita falsos positivos por reglas “generic”). |
| **scanner-php-taint-sqli** | Con una regla taint bien escrita (fuentes `$_GET`/`$_POST`, sink concatenación SQL, sanitizers), el motor **debe** detectar flujo en PHP. Si el taint PHP está roto, esta suite puede mostrar warning hasta que se corrija; al corregir, el test evita regresiones. |

Añadir aquí nuevas suites cuando se encuentren bugs del scanner (p. ej. no aplicar bien una regla correcta, aplicar una regla al idioma equivocado, etc.).
