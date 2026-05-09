# LangGraph Thesis Project

## Resumen del proyecto

Este proyecto combina:

- un servicio PostgreSQL con `pgvector` para alojar datos CWE y sus embeddings,
- un motor de ingestión que carga datos CWE desde el XML `datasets/cwec_v4.19.1.xml`,
- un contenedor `langgraph-app` que ejecuta la lógica de análisis y validación de hallazgos,
- un contenedor `sandbox` para clonar repositorios GitHub y servirlos a la aplicación,
- un contenedor `pgadmin` para administrar la base de datos.

El objetivo principal es analizar código, construir hipótesis de vulnerabilidad y validar contra CWE usando embeddings semánticos.

---

## Estructura principal

- `docker-compose.yml`: define los servicios `cve-db-tesis-3`, `sandbox-tesis-3`, `pgadmin-tesis-3` y `langgraph-app-tesis-3`.
- `databases/cve-db/init/01_cwe_schema.sql`: esquema inicial de la base de datos con tablas CWE y embeddings.
- `datasets/cwec_v4.19.1.xml`: dataset CWE original usado para cargar la base de datos.
- `langgraph-app/`: aplicación principal y scripts de ingestión/evaluación.
- `langgraph-app/src/ingestion/`: scripts para cargar CWE en la base de datos y generar embeddings.
- `langgraph-app/src/graph/workflow.py`: flujo de análisis de repositorios y evaluación de archivos.
- `langgraph-app/src/evaluation/run_benchmark_subset.py`: script para ejecutar subset de benchmark OWASP.

---

## Requisitos previos

1. Docker y Docker Compose instalados.
2. Python 3.11 disponible en el host si ejecutar los scripts de ingestión desde el host.
3. Conexión a internet para clonar repositorios GitHub y descargar dependencias.

---

## Instalación de dependencias

### 1. Requisitos del workspace raíz

Este repositorio contiene un `requirements.txt` en la raíz. Instálalo si deseas trabajar con los scripts desde el host:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Requisitos de `langgraph-app`

El contenedor `langgraph-app` instala sus propios paquetes desde `langgraph-app/requirements.txt` durante la construcción del contenedor.

Para instalar localmente (si planeas ejecutar código de `langgraph-app` fuera de Docker):

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r langgraph-app/requirements.txt
```

---

## Levantar el proyecto con Docker Compose

Desde la raíz del proyecto ejecuta:

```bash
docker compose up -d --build
```

Esto crea y levanta los servicios:

- `cve-db-tesis-3`: PostgreSQL con `pgvector`.
- `sandbox-tesis-3`: servicio de clonación de repositorios.
- `pgadmin-tesis-3`: interfaz de administración de PostgreSQL.
- `langgraph-app-tesis-3`: aplicación principal con Ollama y el código de LangGraph.

Verifica el estado con:

```bash
docker compose ps
```

---

## Elección e instalación de modelos Open Source

Este proyecto utiliza modelos de lenguaje Open Source alojados en Ollama para dos propósitos principales:

- **Modelo de embeddings**: `mxbai-embed-large` para generar representaciones vectoriales de los CWE y consultas de búsqueda semántica.
- **Modelo de validación**: `qwen2.5:7b` para la lógica de validación de hipótesis de vulnerabilidades contra CWE.

### Instalación manual de modelos

Los modelos no se instalan automáticamente durante la construcción del contenedor. Debes instalarlos manualmente dentro del contenedor `langgraph-app-tesis-3` una vez que esté corriendo:

1. Accede al contenedor:

```bash
docker exec -it langgraph-app-tesis-3 bash
```

2. Instala los modelos requeridos:

```bash
ollama pull qwen2.5:7b
ollama pull mxbai-embed-large
```

3. Verifica que estén instalados:

```bash
ollama list
```

### Cambiar modelos para experimentación

Si deseas probar con otros modelos Open Source disponibles en Ollama:

1. Instala el nuevo modelo dentro del contenedor:

```bash
ollama pull nombre_del_nuevo_modelo
```

2. Actualiza las constantes en el código:

   - Para el modelo de embeddings: modifica `MODEL = "mxbai-embed-large"` en `langgraph-app/src/ingestion/load_cwe_embeddings.py`.
   - Para el modelo de validación: modifica la referencia correspondiente en `langgraph-app/src/agents/cwe_validator.py` (busca la configuración del modelo de lenguaje).

3. Reinicia el contenedor o vuelve a ejecutar los scripts afectados.

> **Nota**: Asegúrate de que el nuevo modelo sea compatible con las interfaces de Ollama utilizadas (embeddings API para embeddings, chat API para validación).

---

## Cargar CWE a la base de datos

### 1. Qué hace `load_cwe_core.py`

`langgraph-app/src/ingestion/load_cwe_core.py`:

- parsea `datasets/cwec_v4.19.1.xml`,
- extrae CWE principales,
- extrae relaciones CWE,
- extrae mitigaciones CWE,
- extrae métodos de detección CWE,
- escribe esos datos en las tablas PostgreSQL:
  - `cwe`
  - `cwe_relationships`
  - `cwe_mitigations`
  - `cwe_detection_methods`

### 2. Ejecutar la carga CWE

Los scripts de ingestión están configurados para conectar a la base de datos en `localhost:5433`, como esta en el mapeo de puertos del contenedor PostgreSQL.

Desde el host, con el entorno Python activo:

```bash
python langgraph-app/src/ingestion/load_cwe_core.py
```

Esto llenará la base de datos con los datos CWE del XML.

> Nota: si deseas ejecutar el script dentro del contenedor `langgraph-app-tesis-3`, primero deberás ajustar `DB_CONFIG` en `load_cwe_core.py` para usar host `cve-db-tesis-3` y puerto `5432`, porque dentro del contenedor `localhost:5433` no apunta al contenedor PostgreSQL.

---

## Generar embeddings CWE

### 1. Qué hace `load_cwe_embeddings.py`

`langgraph-app/src/ingestion/load_cwe_embeddings.py`:

- lee la tabla `cwe`,
- construye un texto combinado por CWE que incluye:
  - nombre,
  - descripción,
  - descripción extendida,
  - mitigaciones,
  - detecciones,
- llama a Ollama para generar embeddings con el modelo `mxbai-embed-large`,
- guarda los embeddings en la tabla `cwe_embeddings`.

### 2. Ejecutar la generación de embeddings

Desde el host:

```bash
python langgraph-app/src/ingestion/load_cwe_embeddings.py
```

### 3. Completar embeddings faltantes

Si hay CWEs sin embedding, usa:

```bash
python langgraph-app/src/ingestion/load_missing_cwe_embeddings_fallback.py
```

Este script busca entradas en `cwe` que no tengan vector en `cwe_embeddings` y trata de calcular embeddings para ellas con un texto más corto.

---

## Otros scripts importantes en `langgraph-app/src/ingestion`

- `preview_cwe_core.py`: carga el XML CWE y muestra un ejemplo de registros, útil para verificar que el XML se parsea correctamente.
- `preview_cwe_embedding_text.py`: muestra cómo se formatea el texto que se usa para generar embeddings.
- `test_cwe_db_connection.py`: verifica que se puede conectar a la base de datos y que hay datos en `cwe`.
- `test_cwe_semantic_search.py`: ejecuta consultas de prueba sobre los embeddings para verificar búsqueda vectorial.



---

## Correr `langgraph-app` sobre un repositorio

El contenedor `langgraph-app-tesis-3` arranca Ollama y luego ejecuta `python -u -m src.main`, pero ese archivo solo mantiene el proceso vivo y no inicia un servidor de análisis automático.

La lógica de análisis está en `src/graph/workflow.py` dentro de la clase `MultiAgentWorkflow`.

### Ejecutar un análisis de repositorio

Dentro del contenedor `langgraph-app-tesis-3` puedes ejecutar el flujo con un comando Python:

```bash
docker exec -it langgraph-app-tesis-3 python -c "import json; from src.graph.workflow import MultiAgentWorkflow; result = MultiAgentWorkflow().run('https://github.com/usuario/repositorio.git'); print(json.dumps(result, indent=2))"
```

Este comando realiza:

- clonación del repositorio usando el servicio `sandbox-tesis-3`,
- análisis del árbol de repositorio y detección de pila,
- selección de archivos candidatos,
- escaneo por patrones inseguros,
- generación de hipótesis,
- validación semántica contra CWE,
- consolidación de hallazgos.

### Ejecutar solo archivos específicos en modo benchmark

Para ejecutar una ruta concreta de benchmark, usa el parámetro `target_files` del workflow.

Ejemplo:

```bash
docker exec -it langgraph-app-tesis-3 python -c "import json; from src.graph.workflow import MultiAgentWorkflow; result = MultiAgentWorkflow().run('https://github.com/usuario/repositorio.git', target_files=['src/main/java/org/owasp/benchmark/testcode/Example.java']); print(json.dumps(result, indent=2))"
```

En ese caso, el flujo usa el `BENCHMARK FAST PATH` y evita la inspección normal completa del repositorio. Solo analiza los archivos listados en `target_files`.

---

## Ejecutar benchmark de OWASP con casos específicos

El script `langgraph-app/src/evaluation/run_benchmark_subset.py` es la forma preparada para correr subsets de benchmark OWASP.

### Uso básico

Dentro del contenedor:

```bash
docker exec -it langgraph-app-tesis-3 python -m src.evaluation.run_benchmark_subset --run-label my_benchmark_run
```

Esto usa por defecto:

- `DEFAULT_BENCHMARK_JSON = /app/src/evaluation/owasp_benchmark_java_v1_2.json`
- `DEFAULT_REPO_URL = https://github.com/OWASP-Benchmark/BenchmarkJava.git`

### Argumentos útiles

- `--run-label`: etiqueta obligatoria para esta ejecución.
- `--benchmark-json`: ruta al JSON de benchmark si deseas otro conjunto de casos.
- `--repo-url`: URL del repositorio GitHub a analizar.
- `--category`: categoría del benchmark, por ejemplo `pathtraver`.
- `--real-vulnerability`: `true`, `false` o `none`.
- `--limit`: número de casos a ejecutar.
- `--force-rerun`: fuerza re-ejecución aun cuando los resultados ya existan.
- `--cwe-id`: filtrar casos por CWE específico.

### Ejemplo concreto

```bash
docker exec -it langgraph-app-tesis-3 python -m src.evaluation.run_benchmark_subset --run-label benchmark_pathtraver --category pathtraver --real-vulnerability true --limit 20
```

Este script:

- carga los casos desde el JSON de benchmark,
- filtra los casos según los parámetros,
- crea tablas de resultados en PostgreSQL si no existen,
- ejecuta el flujo `MultiAgentWorkflow` para cada caso,
- guarda los resultados en `benchmark_case_results`.

---

## Puntos importantes y recomendaciones

- El DB schema inicial se crea automáticamente al iniciar `cve-db-tesis-3`, gracias a los scripts en `databases/cve-db/init/`.
- `langgraph-app` usa Ollama instalado dentro del contenedor y `OLLAMA_URL` en `http://localhost:11434/api/embeddings`.
- Para ejecutar análisis de benchmark desde el contenedor, usa `docker exec` con `python -m src.evaluation.run_benchmark_subset`.
- Los scripts de ingestión en `langgraph-app/src/ingestion` están escritos para conectarse al DB en `localhost:5433`. Si deseas ejecutarlos dentro del contenedor, cambia la configuración a `host='cve-db-tesis-3'` y `port=5432`.

---

## Resumen rápido de pasos

1. Instalar dependencias: `pip install -r requirements.txt` o `pip install -r langgraph-app/requirements.txt`.
2. Levantar containers: `docker compose up -d --build`.
3. Cargar CWE a la DB: `python langgraph-app/src/ingestion/load_cwe_core.py`.
4. Generar embeddings: `python langgraph-app/src/ingestion/load_cwe_embeddings.py`.
5. Validar y completar embeddings faltantes: `python langgraph-app/src/ingestion/load_missing_cwe_embeddings_fallback.py`.
6. Ejecutar un repo con el workflow: `docker exec -it langgraph-app-tesis-3 python -c "...MultiAgentWorkflow().run(...)..."`.
7. Ejecutar benchmark de archivos específicos: `docker exec -it langgraph-app-tesis-3 python -m src.evaluation.run_benchmark_subset --run-label ...`.

---

## Contacto interno

- `langgraph-app/src/graph/workflow.py`: flujo de análisis.
- `langgraph-app/src/ingestion/load_cwe_core.py`: carga core CWE en la DB.
- `langgraph-app/src/ingestion/load_cwe_embeddings.py`: genera embeddings.
- `langgraph-app/src/evaluation/run_benchmark_subset.py`: ejecución de benchmark.
- `docker-compose.yml`: define la topología de servicios.
