# Automatización de Correos — Backend

Ingesta de adjuntos de correo (Gmail / Outlook) y extracción de datos tributarios SUNAT,
con aislamiento estricto entre clientes, workers asíncronos y progreso en vivo.

API en **FastAPI** sobre **PostgreSQL** con Row Level Security, cola **ARQ/Redis**,
almacenamiento **compatible con S3** y arquitectura hexagonal **verificada en CI**.

---

## Estado

Implementadas las **fases 0 a 5** y los tests de integración de la **fase 7** del
[plan de arquitectura](ARQUITECTURA.md#17-plan-de-implementación-por-fases):

| Fase | Contenido | Estado |
|------|-----------|--------|
| 0 | Cimientos, Docker, configuración validada, observabilidad, CI | ✅ |
| 1 | Identidad, roles, RLS, auditoría | ✅ |
| 2 | OAuth con PKCE, cifrado envolvente, refresco y revocación | ✅ |
| 3 | Cola, worker de ingesta, validación de adjuntos, storage, SSE | ✅ |
| 4 | Extracción en cuatro motores, perfil SUNAT, confianza por campo | ✅ |
| 5 | Cola de revisión humana, reportes Excel/CSV asíncronos | ✅ |
| 6 | Frontend (interfaz de operación) | pendiente |
| 7 | Tests de integración contra PostgreSQL, Redis y S3 reales | ✅ |
| 7 | Cuotas por tenant separadas del limitador de avalanchas | ✅ |
| 7 | Pruebas de carga (escenarios autenticados pendientes de staging) | 🔄 |
| 8 | Operación: runbooks, dashboards, despliegue | pendiente |

**Verificación actual:** 381 tests en verde (345 sin infraestructura + 36 de
integración), 6/6 contratos de arquitectura, `mypy --strict` sin hallazgos, `ruff`,
`bandit` y `pip-audit` limpios. Cobertura: dominio 92–100 %, capa de aplicación
73–100 %.

Los tests de integración corren contra PostgreSQL, Redis y un S3 real, y son los
únicos que pueden afirmar que el aislamiento multi-tenant funciona. Encontraron cuatro
defectos que ninguna comprobación estática podía detectar:

- Las migraciones no arrancaban: la URL síncrona que usaba Alembic resuelve al driver
  `psycopg`, que no es dependencia del proyecto. Ahora Alembic usa el mismo `asyncpg`
  que la aplicación.
- Las políticas RLS lanzaban `invalid input syntax for type uuid: ""` en cualquier
  conexión reciclada del pool. `SET LOCAL` no deja la variable indefinida al terminar
  la transacción: la deja vacía. Corregido en la migración `0003`.
- Ningún adjunto se podía guardar con el `docker compose` del repositorio: el almacén
  exige cifrado en reposo y el servicio de desarrollo lo rechazaba.
- La imagen `minio/minio` había desaparecido de Docker Hub, así que un clon reciente no
  podía ni levantar el entorno. El almacén de desarrollo y de CI pasa a ser LocalStack,
  que es pública, está mantenida e implementa tanto SSE-S3 como el presignado v4.

Y las [pruebas de carga](pruebas-de-carga/) destaparon dos más:

- **Denegación de servicio sin credenciales.** La cuota horaria de escaneos la aplicaba
  el middleware de rate limit, que corre antes de autenticar y por tanto solo puede
  contar por dirección IP: veintiuna peticiones anónimas dejaban sin escaneos durante
  una hora a todos los que compartieran salida a internet. Las cuotas se aplican ahora
  por tenant y después de autenticar.
- **La recarga en caliente no recargaba nada.** La imagen instala el paquete, así que
  `import mailauto` resolvía a `site-packages` y el código montado en `/app/src` no se
  importaba nunca: se editaba un fichero, uvicorn anunciaba la recarga y seguía sirviendo
  lo que había en la imagen.

---

## Puesta en marcha

Requiere Docker. No hace falta instalar Python, PostgreSQL ni Tesseract en la máquina.

```bash
cp .env.example .env
```

Genera la clave maestra y pégala en `MASTER_KEY_B64`:

```bash
python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
```

Completa las credenciales OAuth de Google y/o Microsoft y levanta todo:

```bash
docker compose up
```

Esto arranca API, worker de ingesta, worker de cron, PostgreSQL, Redis, el almacén de
objetos y Jaeger,
y aplica las migraciones antes de que la API acepte tráfico.

| Servicio | URL |
|----------|-----|
| API | http://localhost:8000 |
| Documentación interactiva | http://localhost:8000/docs |
| Almacén de objetos (S3) | http://localhost:4566 |
| Trazas (Jaeger) | http://localhost:16686 |

---

## Desarrollo sin Docker

```bash
python -m venv .venv && .venv/Scripts/activate   # Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

Necesitas PostgreSQL y Redis accesibles, y aplicar las migraciones:

```bash
alembic upgrade head
```

```bash
uvicorn mailauto.bootstrap.app:crear_app --factory --reload
```

```bash
arq mailauto.workers.settings.WorkerDeIngesta
```

---

## Verificación

Lo mismo que ejecuta el CI, en orden:

```bash
ruff format --check src tests migrations && ruff check src tests migrations
```

```bash
lint-imports --config importlinter.ini
```

```bash
mypy --config-file pyproject.toml
```

```bash
pytest -q -m "not integration"
```

```bash
bandit -q -c pyproject.toml -r src && pip-audit --skip-editable
```

Los tests de integración necesitan los servicios en marcha y van aparte:

```bash
docker compose up -d postgres redis almacen && docker compose run --rm migraciones
```

```bash
pytest -q -m integration
```

Se saltan solos, con un aviso que explica qué levantar, si no encuentran nada
escuchando. En CI eso sería un trabajo en verde sin haber comprobado nada, así que allí
un salto se trata como fallo.

Las pruebas de carga van en [`pruebas-de-carga/`](pruebas-de-carga/) con su propia
documentación. El escenario de humo no necesita token y corre contra la pila local:

```bash
docker run --rm --network automatizacion-correos_default -v "$PWD/pruebas-de-carga:/carga:ro" -e BASE_URL=http://api:8000 -e ESCENARIO=humo grafana/k6:latest run /carga/carga.js
```

Las URLs de conexión se leen de `TEST_DATABASE_URL`, `TEST_DATABASE_URL_OWNER`,
`TEST_REDIS_URL` y `TEST_STORAGE_ENDPOINT_URL`, y por defecto apuntan a los puertos del
`docker-compose.yml`. **Son dos URLs de la misma base a propósito:** una con el rol
propietario, que solo siembra datos, y otra con el rol de aplicación, que es el que debe
estar sometido a RLS. Usar la misma para ambas cosas dejaría los tests pasando sin
verificar nada.

`lint-imports` es el que conviene no saltarse: verifica que las capas no se han cruzado.
Un import "temporal" de infraestructura dentro del dominio falla el pipeline, y es así
como la arquitectura se mantiene con el tiempo en vez de degradarse.

---

## Arquitectura

Documento completo en [ARQUITECTURA.md](ARQUITECTURA.md). Resumen:

```
  api  ──▶  application  ──▶  domain  ◀──  infrastructure
                                 ▲               │
                                 └───────────────┘
                             implementa los puertos
```

- **domain** — entidades, objetos de valor y puertos. No importa SQLAlchemy, FastAPI, httpx
  ni las librerías de parseo: los contratos de CI lo verifican.
- **application** — casos de uso sobre puertos abstractos. Testeables sin red ni base de datos.
- **infrastructure** — adaptadores concretos (PostgreSQL, Redis, S3, Gmail, Graph).
- **api** — routers delgados que delegan.
- **bootstrap** — *composition root*, único punto que conoce todas las capas.

Seis contextos acotados independientes: `identity`, `mailbox`, `ingestion`, `extraction`,
`reporting`, `audit`. No se importan entre sí; la comunicación pasa por el composition root
(ver `bootstrap/adaptadores.py`).

```
src/mailauto/
├── bootstrap/     configuración, contenedor de dependencias, fábrica de la app
├── shared/        cripto, seguridad, observabilidad, paginación, sesiones de BD
├── modules/       identity · mailbox · ingestion · extraction · reporting · audit
├── api/           routers v1, middlewares, DTOs
└── workers/       definiciones de los workers ARQ
```

---

## Seguridad

Cobertura detallada en [ARQUITECTURA.md §9](ARQUITECTURA.md#9-seguridad). Lo esencial:

**Aislamiento entre clientes, en dos capas independientes.** Todo repositorio exige un
`TenantContext` en su firma, y además PostgreSQL aplica Row Level Security con
`FORCE ROW LEVEL SECURITY`. Un `WHERE` olvidado devuelve cero filas en lugar de datos
ajenos.

> ⚠️ **La aplicación debe conectarse con un rol que no sea propietario de las tablas ni
> superusuario.** PostgreSQL exime a ambos de las políticas RLS: el aislamiento quedaría
> desactivado sin ningún error ni aviso. En desarrollo lo garantiza
> [`scripts/init-db.sql`](scripts/init-db.sql); en producción debe reproducirlo la
> infraestructura.

**Extracción: coste controlado por diseño.** El pipeline prueba cuatro motores en orden de
coste y para en cuanto los campos imprescindibles son fiables: texto nativo del PDF (~10 ms,
gratis) → tablas → OCR local con preprocesamiento OpenCV (~800 ms, gratis) → visión IA
(~2 s, de pago). La mayoría de documentos no pasa del primero. La IA lleva tope de llamadas
por escaneo y, si no hay credencial, el pipeline degrada a los tres gratuitos en lugar de
fallar.

El documento es **entrada no confiable**: puede llevar texto escrito para que el modelo lo
obedezca. Tres barreras — la imagen va en un bloque de usuario delimitado y nunca concatenada
al prompt de sistema, el modelo no tiene herramientas, y la salida pasa después por los
objetos de valor del dominio, que descartan un RUC sin dígito verificador válido venga de
donde venga.

**Dato tributario válido por construcción.** `Ruc("20131312954")` lanza: el dígito verificador
módulo 11 se comprueba en el constructor. El OCR confunde 0/O, 1/l y 5/S, y sin esa
comprobación esos errores entrarían en el reporte con apariencia de dato bueno. Lo mismo con
periodos, importes (`Decimal`, nunca `float`) y fechas imposibles.

**Credenciales OAuth.** Cifrado sobre envolvente: una DEK por cliente, envuelta por una
clave maestra en KMS. AES-256-GCM con AAD = `tenant|propósito|sujeto`, de modo que un
ciphertext copiado a otra fila no descifra. `key_version` permite rotar sin downtime.

**Adjuntos.** Son la superficie de ataque principal: ficheros de terceros que acabarán en
parsers nativos. Se validan por contenido real (nunca por extensión), con allowlist cerrada
de tipos, topes de tamaño aplicados durante la transferencia, y rechazo de PDFs con
JavaScript, `/Launch`, ficheros embebidos o patrón de bomba de descompresión. Se almacenan
con clave UUID: el nombre del adjunto nunca influye en la ruta.

**Configuración.** Se valida al arrancar. Con `ENVIRONMENT=production`, la aplicación
**no levanta** si `CORS_ORIGINS` contiene `*`, si `/docs` está habilitado, si
`KMS_PROVIDER=local` o si se intenta persistir texto OCR crudo. Un contenedor que no
arranca es visible; una brecha silenciosa no.

**Logs.** Un procesador de redacción obligatorio enmascara tokens, cabeceras de
autorización y campos personales a cualquier profundidad, antes de serializar.

---

## API

Prefijo `/api/v1`. Errores en formato RFC 9457 (Problem Details). Listados paginados por
cursor, nunca sin límite.

| Método | Ruta | Permiso |
|--------|------|---------|
| GET | `/health/live` · `/health/ready` | público |
| GET | `/api/v1/me` | autenticado |
| GET | `/api/v1/mailboxes` | `mailbox:read` |
| POST | `/api/v1/mailboxes/authorize` | `mailbox:write` |
| POST | `/api/v1/mailboxes/callback` | `mailbox:write` |
| DELETE | `/api/v1/mailboxes/{id}` | `mailbox:write` |
| POST | `/api/v1/scans` | `scan:run` |
| GET | `/api/v1/scans` · `/api/v1/scans/{id}` | `scan:read` |
| GET | `/api/v1/scans/{id}/stream` (SSE) | `scan:read` |
| GET | `/api/v1/scans/{id}/errors` | `scan:read` |
| POST | `/api/v1/scans/{id}/cancel` | `scan:run` |
| GET | `/api/v1/records` · `/api/v1/records/{id}` | `record:read` |
| PATCH | `/api/v1/records/{id}` (corregir y aprobar) | `record:review` |
| POST | `/api/v1/records/{id}/approve` · `/reject` | `record:review` |
| GET | `/api/v1/review` · `/api/v1/review/count` | `record:review` |
| POST | `/api/v1/reports/exports` | `report:read` |
| GET | `/api/v1/reports/exports/{id}` | `report:read` |
| GET | `/api/v1/audit` | `admin:read` |

Cabeceras: `Authorization: Bearer`, `X-Tenant-Id` (si el usuario pertenece a varios
espacios de trabajo), `Idempotency-Key` en `POST /scans`, `X-Request-ID`.

---

## Antes de salir a producción

**La verificación de Google no es un trámite menor.** El alcance `gmail.readonly` es un
*restricted scope*: publicar exige verificación por parte de Google y, al superar el umbral
de usuarios, una evaluación de seguridad CASA realizada por un asesor autorizado. Tiene
coste y plazo reales, y bloquea el lanzamiento si se deja para el final. Conviene iniciar
el trámite en paralelo al desarrollo.

Además: provisionar el rol de base de datos sin privilegios de propietario, mover la clave
maestra a un KMS, configurar `CORS_ORIGINS` con el dominio real y desactivar `/docs`.

---

## Documentación

- [ARQUITECTURA.md](ARQUITECTURA.md) — diseño completo, decisiones y plan por fases
- `/docs` — OpenAPI interactivo (solo fuera de producción)
