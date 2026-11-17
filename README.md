# IOC-Triage

Herramienta de línea de comandos para el **triaje rápido de indicadores de compromiso (IOC)**: direcciones IP, dominios y hashes (MD5, SHA1 y SHA256).

En segundos, la herramienta:

1. **Enriquece** el indicador mediante [AbuseIPDB](https://www.abuseipdb.com/) y [VirusTotal](https://www.virustotal.com/).
2. Calcula un **veredicto base mediante reglas transparentes**, sin depender de inteligencia artificial.
3. Utiliza un **LLM (Google Gemini)** para generar un resumen de analista SOC y proponer siguientes pasos, utilizando exclusivamente los datos recogidos.
4. Guarda los resultados en formato JSON para facilitar su consulta y análisis posterior.

El proyecto utiliza únicamente la biblioteca estándar de Python, sin dependencias externas.

---

## ¿Por qué separar las reglas del LLM?

Un modelo de lenguaje puede equivocarse, interpretar incorrectamente los datos o inventar contexto.

Por eso, IOC-Triage mantiene dos veredictos independientes:

- **Reglas:** clasificación determinista basada en los datos obtenidos de las fuentes de inteligencia.
- **LLM:** análisis contextual, resumen de evidencias y recomendaciones para el analista.

El LLM no decide por sí solo. Su función es interpretar y explicar la información disponible.

Además, `evaluate.py` permite comparar ambos métodos utilizando una lista de IOCs etiquetados previamente.

## Características

- Identificación automática de IPs, dominios y hashes.
- Enriquecimiento mediante AbuseIPDB y VirusTotal.
- Clasificación mediante reglas transparentes.
- Integración con Google Gemini.
- Validación de la respuesta JSON del LLM.
- Funcionamiento sin IA mediante `--no-llm`.
- Modo offline con datos simulados mediante `--offline`.
- Exportación de resultados individuales en JSON.
- Evaluación automática de resultados.
- Tests unitarios sin necesidad de consultar APIs reales.

## Requisitos

- Python 3.10 o superior.
- Claves API de AbuseIPDB y VirusTotal.
- Clave API de Google Gemini (opcional, si se quiere utilizar el LLM).

No es necesario instalar dependencias externas.

## Instalación y configuración

Clonar el repositorio:

```bash
git clone https://github.com/IvanVH909/ioc-triage.git
cd ioc-triage
```

Crear el archivo de configuración:

```bash
cp .env.example .env
```

En Windows PowerShell también puedes utilizar:

```powershell
Copy-Item .env.example .env
```

Configurar las claves API en `.env`:

```env
ABUSEIPDB_API_KEY=TU_API_KEY
VT_API_KEY=TU_API_KEY
GEMINI_API_KEY=TU_API_KEY

IOC_LLM_MODEL=gemini-3.5-flash
```

El modelo se puede modificar mediante `IOC_LLM_MODEL`, utilizando un identificador compatible con la API de Gemini.

**Importante:** No publiques tus claves API ni el archivo `.env` en GitHub o en ningún otro lugar público. El repositorio incluye `.env.example` como plantilla de configuración. Utiliza ese archivo para crear tu configuración local y comprueba que `.env` está incluido en `.gitignore`.

## Uso

### Triaje de una IP

```bash
python triaje.py 8.8.8.8
```

### Triaje de un hash SHA256

```bash
python triaje.py 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

### Triaje de un dominio

```bash
python triaje.py malware.example
```

### Varios indicadores a la vez

```bash
python triaje.py 8.8.8.8 1.1.1.1 google.com
```

### Sin inteligencia artificial

```bash
python triaje.py 8.8.8.8 --no-llm
```

Esta opción realiza el enriquecimiento y calcula el veredicto mediante las reglas, sin consultar Gemini.

Cada ejecución guarda un archivo JSON en `results/`, con las evidencias, los veredictos y la fecha de consulta.

## Demo offline

El proyecto incorpora una carpeta `fixtures/` con respuestas simuladas que reproducen la estructura de las APIs reales.

Se utilizan direcciones IP reservadas para documentación, como `203.0.113.x`, `198.51.100.x` y `192.0.2.x`.

Ejecutar:

```bash
python triaje.py 203.0.113.7 198.51.100.23 192.0.2.10 --offline --no-llm
```

Ejemplo de salida:

```text
=== 203.0.113.7 (ip) ===
AbuseIPDB : score 100/100 · 412 reportes · XX · Example Hosting Ltd
VirusTotal: 14 malicious / 2 suspicious / 55 harmless
Veredicto base (reglas): MALICIOUS
```

> Esta salida utiliza datos inventados para la demostración. No representa la reputación real de esas direcciones IP.

## Reglas del veredicto base

La clasificación se realiza mediante umbrales configurables en `baseline_verdict()` dentro de `triaje.py`.

| Veredicto | Condición |
|---|---|
| `malicious` | VirusTotal ≥ 5 detecciones maliciosas o AbuseIPDB ≥ 75 |
| `suspicious` | VirusTotal ≥ 2 detecciones maliciosas, ≥ 3 sospechosas o AbuseIPDB ≥ 25 |
| `benign` | Hay datos disponibles y no se cumplen las condiciones anteriores |
| `unknown` | No se ha podido obtener información de ninguna fuente |

**Consideraciones:**

- Una única detección maliciosa en VirusTotal no es suficiente para clasificar automáticamente un indicador como sospechoso.
- Un resultado `benign` significa que no se han encontrado evidencias suficientes de actividad maliciosa en las fuentes consultadas. No garantiza que el indicador sea seguro.
- Los umbrales son decisiones de diseño y pueden ajustarse según los resultados de las evaluaciones.

## Integración con Google Gemini

El proyecto utiliza la API de Google Gemini para generar un resumen de analista SOC de nivel 1.

El modelo recibe:

- IOC analizado.
- Tipo de indicador.
- Veredicto calculado mediante reglas.
- Datos de AbuseIPDB.
- Datos de VirusTotal.
- Errores producidos durante el enriquecimiento.

### Restricciones del prompt

El modelo debe:

- Utilizar exclusivamente la información proporcionada.
- No inventar campañas, familias de malware ni atribuciones.
- Indicar explícitamente cuándo faltan datos.
- Reducir la confianza cuando las evidencias sean insuficientes.
- Proporcionar un veredicto, nivel de confianza, resumen y siguientes pasos.

La respuesta debe tener un formato JSON con los siguientes campos:

```json
{
  "verdict": "malicious",
  "confidence": "high",
  "summary": "Resumen del análisis...",
  "next_steps": [
    "Revisar las evidencias",
    "Investigar actividad relacionada",
    "Escalar al equipo SOC"
  ]
}
```

El código valida la respuesta recibida y limita los veredictos permitidos a:

- `malicious`
- `suspicious`
- `benign`
- `unknown`

Si el LLM devuelve un veredicto no reconocido, se convierte en `unknown`.

Si Gemini falla, el triaje basado en reglas sigue funcionando.

## Evaluación

El proyecto incluye `eval/iocs.csv`, un conjunto de indicadores etiquetados manualmente para comprobar el comportamiento de los clasificadores.

La evaluación compara:

- Veredicto esperado.
- Veredicto obtenido mediante reglas.
- Veredicto obtenido mediante el LLM.
- Aciertos.
- Falsos positivos (FP).
- Falsos negativos (FN).

Ejecutar la evaluación completa:

```bash
python evaluate.py eval/iocs.csv
```

Evaluar únicamente las reglas:

```bash
python evaluate.py eval/iocs.csv --no-llm
```

Los resultados se guardan en `eval/resultados.md`.

### Resultados obtenidos

Primera evaluación realizada con un conjunto de 10 indicadores: 4 benignos y 6 maliciosos.

| Método | Aciertos | Precisión de clasificación | FP | FN |
|---|---:|---:|---:|---:|
| Reglas | 10/10 | 100 % | 0 | 0 |
| LLM | 8/8 respuestas válidas | 100 % | 0 | 0 |

**Disponibilidad del LLM:** 8 de los 10 indicadores obtuvieron una respuesta válida. Se produjeron dos errores durante las consultas.

Los resultados del LLM se calculan únicamente sobre las respuestas válidas, por lo que el 100 % no representa una cobertura completa del conjunto de evaluación.

> Estos resultados corresponden a un conjunto de pruebas reducido. No demuestran todavía que el sistema tenga una precisión del 100 % en escenarios reales de producción.

## Tests unitarios

El proyecto incorpora tests para comprobar:

- Identificación de IPs, dominios y hashes.
- Validación de indicadores incorrectos.
- Funcionamiento de las reglas de clasificación.
- Normalización de respuestas de las APIs.
- Procesamiento de respuestas JSON del LLM.
- Comportamiento ante errores de Gemini.
- Funcionamiento offline.
- Evaluación de falsos positivos y falsos negativos.

Ejecutar todos los tests:

```bash
python -m unittest discover -s tests -v
```

**Estado actual: 19 tests superados.**

Los tests utilizan mocks para simular las respuestas de las APIs, por lo que no necesitan claves API ni conexión a Internet.

## Estructura del proyecto

```text
ioc-triage/
│
├── triaje.py              # Motor principal de triaje
├── evaluate.py            # Evaluación de clasificadores
├── .env.example           # Plantilla de configuración
├── .gitignore             # Exclusión de claves y resultados
│
├── fixtures/              # Datos simulados para modo offline
│
├── eval/
│   ├── iocs.csv            # Dataset de evaluación
│   └── resultados.md       # Resultados de evaluación
│
├── tests/
│   └── test_triaje.py      # Tests unitarios
│
└── results/                # Resultados individuales en JSON
```

## Limitaciones

- Los planes gratuitos de VirusTotal y AbuseIPDB tienen límites de consultas.
- Solo se utilizan dos fuentes de inteligencia de amenazas.
- La reputación de una IP o dominio puede cambiar con el tiempo.
- Una IP legítima puede aparecer en fuentes de reputación negativa debido a VPN, hosting compartido o CGNAT.
- Un indicador sin detecciones no necesariamente es seguro.
- La disponibilidad del LLM depende de la API, sus límites y el modelo configurado.
- No debe utilizarse como sustituto de un analista de seguridad ni como único mecanismo de respuesta ante incidentes.

**Privacidad:** No envíes indicadores internos, direcciones de clientes o información confidencial a servicios de terceros sin contar con la autorización correspondiente. Las consultas a AbuseIPDB, VirusTotal y Google Gemini pueden implicar el envío de información a dichos proveedores.

## Posibles mejoras futuras

Las siguientes funcionalidades se plantean como ampliaciones del proyecto y no forman parte de la implementación actual.

### 1. Ampliación del dataset y mejora de la evaluación

- Ampliar el conjunto de evaluación de 10 a 100-200 IOCs.
- Incorporar indicadores maliciosos recientes procedentes de feeds públicos, como [abuse.ch](https://abuse.ch/).
- Añadir más indicadores benignos y casos difíciles de clasificar.
- Separar los datos utilizados para ajustar las reglas de los utilizados para evaluar su rendimiento.
- Repetir las pruebas periódicamente para comprobar la evolución del rendimiento.

### 2. Métricas SOC y matriz de confusión

Ampliar `evaluate.py` para calcular:

- Precisión (*Precision*).
- Exhaustividad (*Recall*).
- F1-score.
- Matriz de confusión.
- Tasa de falsos positivos.
- Tasa de falsos negativos.

Esto permitirá evaluar mejor el rendimiento del clasificador y detectar si las modificaciones de los umbrales mejoran realmente la detección.

### 3. Mejorar la disponibilidad del LLM

- Investigar y corregir los errores de conexión y disponibilidad de Gemini.
- Añadir reintentos controlados ante errores temporales.
- Registrar los errores por tipo y código HTTP.
- Medir la tasa de respuestas válidas.
- Comparar distintos modelos y su rendimiento en el mismo conjunto de evaluación.

### 4. Integración con ssh-bruteforce-detector

Integrar el proyecto con [ssh-bruteforce-detector](https://github.com/IvanVH909/ssh-bruteforce-detector).

El objetivo es enriquecer automáticamente las direcciones IP detectadas durante ataques de fuerza bruta SSH y obtener información sobre su reputación antes de tomar decisiones de respuesta.

### 5. Caché local

Implementar una caché local para almacenar los resultados de consultas anteriores.

Ventajas:

- Evitar consultas repetidas a las APIs.
- Reducir el consumo de cuotas.
- Mejorar los tiempos de respuesta.
- Mantener un historial de reputación de los indicadores.

La caché debería tener una caducidad configurable para evitar utilizar información obsoleta.

### 6. Exportación e interoperabilidad

Añadir exportación de resultados a:

- STIX para intercambio de inteligencia de amenazas.
- CSV para análisis en hojas de cálculo.
- JSON enriquecido para integraciones con otras herramientas SOC.

### 7. Historial y seguimiento de IOC

Crear un sistema que permita:

- Consultar análisis anteriores.
- Comparar cambios de reputación.
- Detectar cambios de veredicto.
- Mantener un historial temporal de los indicadores.

---

## Autor

**Iván Vázquez Hernández**

GitHub: [@IvanVH909](https://github.com/IvanVH909)

Proyectos relacionados:

- [ioc-triage](https://github.com/IvanVH909/ioc-triage)
- [ssh-bruteforce-detector](https://github.com/IvanVH909/ssh-bruteforce-detector)

---

*Proyecto personal de ciberseguridad orientado al análisis de indicadores de compromiso y al aprendizaje de técnicas de Threat Intelligence y automatización SOC.*