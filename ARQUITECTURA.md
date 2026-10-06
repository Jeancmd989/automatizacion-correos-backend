# Arquitectura — Plataforma de Automatización de Correos

> Extracción automática de datos tributarios desde adjuntos de correo (Gmail / Outlook),
> con validación, revisión humana y reportería. Rediseño completo sobre la base funcional
> de `automatizacion-email-backend` / `automatizacion-email-frontend`.

**Autor:** Jean Paul Quispe Salvador
**Versión del documento:** 1.0 · 2026-10-05
**Estado:** propuesta de arquitectura — pendiente de aprobación antes de implementar

---

## Índice

1. [Análisis del sistema de referencia](#1-análisis-del-sistema-de-referencia)
2. [Objetivos y requisitos no funcionales](#2-objetivos-y-requisitos-no-funcionales)
3. [Decisiones de arquitectura (ADR resumidos)](#3-decisiones-de-arquitectura-adr-resumidos)
4. [Vista de contexto (C4 nivel 1)](#4-vista-de-contexto-c4-nivel-1)
5. [Vista de contenedores (C4 nivel 2)](#5-vista-de-contenedores-c4-nivel-2)
6. [Backend — estructura de capas](#6-backend--estructura-de-capas)
7. [Modelo de datos](#7-modelo-de-datos)
8. [Pipeline de ingesta y extracción](#8-pipeline-de-ingesta-y-extracción)
9. [Seguridad](#9-seguridad)
10. [Rendimiento y escalabilidad](#10-rendimiento-y-escalabilidad)
11. [Observabilidad](#11-observabilidad)
12. [Frontend — estructura](#12-frontend--estructura)
13. [Contrato de API](#13-contrato-de-api)
14. [Estrategia de testing](#14-estrategia-de-testing)
15. [CI/CD y despliegue](#15-cicd-y-despliegue)
16. [Cumplimiento y privacidad](#16-cumplimiento-y-privacidad)
17. [Plan de implementación por fases](#17-plan-de-implementación-por-fases)
18. [Riesgos y mitigaciones](#18-riesgos-y-mitigaciones)

---

## 1. Análisis del sistema de referencia

### 1.1 Qué hace (dominio funcional a conservar)

El sistema de referencia resuelve un flujo concreto y válido:

1. El operador vincula su buzón (Gmail u Outlook) vía OAuth 2.0.
2. Lanza un escaneo acotado por fecha y/o cantidad.
3. El backend descarga adjuntos permitidos (PDF, JPG, PNG, WebP).
4. Un pipeline multi-estrategia extrae datos tributarios SUNAT:
   RUC, razón social, RUC/nombre de inquilino, periodo, fecha de pago,
   número de operación e importe (constancias de arrendamiento / pagos).
5. Los registros se persisten en PostgreSQL con deduplicación por hash.
6. Se genera un reporte consolidado en Excel y vistas de auditoría y errores.

**Este dominio se conserva íntegro.** El rediseño es de arquitectura, no de alcance funcional.

### 1.2 Debilidades detectadas (lo que justifica el rediseño)

| # | Hallazgo | Severidad | Evidencia en el repo de referencia | Corrección propuesta |
|---|----------|-----------|-----------------------------------|----------------------|
| H1 | **Sin aislamiento de datos entre usuarios.** `registros_tributarios` no tiene columna de propietario y `obtener_todos_los_registros()` no filtra. Cualquier usuario autenticado descarga el Excel con los datos tributarios de todos. | **Crítica** — OWASP A01 Broken Access Control | `src/domain/ports.py` → `obtener_todos_los_registros()`; `migrations/001_initial.sql`, tabla sin `user_sub` | `tenant_id` + `owner_id` en toda entidad + **Row Level Security** en PostgreSQL |
| H2 | **Estado del proceso en un singleton en memoria** (`_EstadoGlobal`). Solo admite un escaneo simultáneo en todo el sistema, se pierde al reiniciar, no escala horizontalmente y expone el progreso de un usuario a los demás. | **Alta** | `src/services/scan_service.py:152-187` | Estado persistido en BD + cola de jobs distribuida (Redis/ARQ) + canal SSE por job |
| H3 | **Jobs como `asyncio.create_task` dentro del proceso web.** Sin reintentos, sin timeouts, sin DLQ; un redeploy mata el trabajo en curso; la carga de OCR compite con el event loop de la API. | **Alta** | `scan_service.py:205` | Workers separados, reintentos con backoff, idempotencia, apagado controlado |
| H4 | **`/admin/limpiar` hace TRUNCATE global.** Borrado irreversible de los datos de todos los usuarios desde un solo endpoint. | **Alta** | `ports.py` → `limpiar_base_datos()` | Borrado acotado al tenant, soft-delete + purga diferida, confirmación explícita y registro en audit log |
| H5 | **Clave de cifrado única, estática, sin rotación ni AAD.** Un `ENCRYPTION_KEY` global cifra todos los tokens OAuth; no hay versión de clave ni vínculo criptográfico con la fila. | Media-Alta — A02 | `core/security.py`, `.env.example` | Cifrado sobre envolvente (KEK en KMS + DEK por tenant), `key_version`, AAD = `tenant\|provider\|user` |
| H6 | **Migraciones SQL numeradas aplicadas al arrancar.** Sin control transaccional de versión, sin rollback, sin detección de deriva. | Media | `infrastructure/db/pool.py` + `migrations/*.sql` | Alembic con migraciones versionadas y revisables |
| H7 | **`debug_ocr` persiste texto OCR crudo** del documento tributario. Es PII y dato fiscal en claro, sin TTL, expuesto por `/reportes/debug-ocr`. | Media — A02 / privacidad | `models.py` campo `debug_ocr`; `002_add_debug_ocr.sql` | Desactivado por defecto, opt-in por tenant, cifrado y con purga automática |
| H8 | **Polling del frontend al endpoint de estado.** Tráfico constante, latencia de actualización y costo innecesario. | Media | `app/hooks/useAutomatizador.ts` | SSE sobre Redis pub/sub |
| H9 | **God-hook de 350 líneas** que concentra estado del servidor, polling, OAuth y notificaciones. Sin caché, sin invalidación, sin reintentos. | Media | `useAutomatizador.ts` (350 LOC) | TanStack Query + hooks por feature, estructura *feature-sliced* |
| H10 | **Contrato de API duplicado a mano** en `app/lib/types.ts`. Deriva silenciosa entre backend y frontend. | Media | `types.ts` frente a los modelos Pydantic | Cliente TypeScript generado desde OpenAPI en CI |
| H11 | **Sin almacenamiento de objetos.** Los adjuntos viven en el disco del contenedor; se pierde trazabilidad y no se pueden reprocesar. | Media | `AdjuntoDescargado.ruta: Path` | Almacenamiento compatible con S3, con cifrado en reposo, claves opacas y URLs prefirmadas de corta vida |
| H12 | **El worker de OCR corre en el mismo contenedor que la API**, parseando archivos no confiables de terceros con salida a Internet sin restricción. | Media-Alta — A04 / A08 | `Dockerfile` único | Worker aislado: contenedor propio, usuario no-root, rootfs de solo lectura, egress restringido, límites de CPU/RAM, seccomp |
| H13 | Hash de deduplicación en **MD5**. | Baja | `models.py` → `content_hash` | SHA-256 |
| H14 | Archivos de depuración versionados (`debug_out.txt`, `debug_pdf.py`, `test_fixes.py` en la raíz). | Baja — código muerto | raíz del repo | Excluidos; scripts de diagnóstico en `tools/`, fuera del paquete |

> H1, H2 y H3 son las que impiden que el sistema actual pase a producción multiusuario.
> El rediseño se organiza alrededor de resolverlas.

---

## 2. Objetivos y requisitos no funcionales

| Atributo | Objetivo medible |
|----------|------------------|
| **Seguridad** | Cero fugas entre tenants, verificable por test; OWASP Top 10 cubierto; secretos nunca en código ni en logs |
| **Disponibilidad** | API sin estado → N réplicas; reinicio de workers sin pérdida de trabajos |
| **Rendimiento** | p95 < 300 ms en endpoints de lectura; ≥ 20 adjuntos/min por worker de extracción |
| **Escalabilidad** | Escalado horizontal independiente de API y workers; sin estado compartido en memoria |
| **Mantenibilidad** | Dependencias entre capas verificadas automáticamente en CI; cobertura ≥ 80 % en dominio y aplicación |
| **Trazabilidad** | Todo registro extraído rastreable hasta el correo, el adjunto y el job que lo originó |
| **Costo** | La IA de visión es el último recurso del pipeline, con presupuesto por tenant y corte automático |

---

## 3. Decisiones de arquitectura (ADR resumidos)

| ADR | Decisión | Alternativas evaluadas | Razón |
|-----|----------|------------------------|-------|
| 001 | **Monolito modular** por contexto acotado, no microservicios | Microservicios | El dominio es pequeño y cohesionado; los microservicios añadirían latencia, complejidad operativa y transacciones distribuidas sin beneficio. Los módulos quedan listos para extraerse si alguna vez hace falta |
| 002 | **Arquitectura hexagonal** (puertos y adaptadores), 4 capas | Capas clásicas, CRUD directo | El dominio tiene reglas reales (validación de RUC, normalización, confianza) y varios adaptadores intercambiables (Gmail/Graph, PDF/OCR/IA). Es el caso de uso canónico |
| 003 | Dependencias entre capas **verificadas por `import-linter` en CI** | Solo documentarlas | Una arquitectura que no se verifica se degrada. El contrato debe ser ejecutable |
| 004 | **FastAPI + Python 3.12** | Node/NestJS, Go | El ecosistema de OCR/PDF/visión (PyMuPDF, Tesseract, OpenCV, pdfplumber) es Python. Cambiar de stack rehace el núcleo de valor sin ganancia |
| 005 | **ARQ + Redis** para jobs asíncronos | Celery, RQ, `asyncio.Task` | ARQ es nativo asyncio (sin puente sync/async como Celery) y aporta reintentos, timeouts, cron y jobs diferidos en una sola dependencia. Celery queda como alternativa si se necesita su ecosistema de monitoreo |
| 006 | **SQLAlchemy 2.0 async + Alembic** | asyncpg crudo, Prisma, Tortoise | Elimina el SQL concatenado por construcción, da migraciones versionadas y mantiene control fino del SQL generado |
| 007 | **Row Level Security de PostgreSQL** como segunda barrera de aislamiento | Solo filtro en el repositorio | Defensa en profundidad: un `WHERE` olvidado deja de ser una fuga de datos |
| 008 | **SSE** para progreso en vivo | Polling, WebSocket | Unidireccional servidor→cliente, sobre HTTP normal, sin sesiones pegajosas; el fan-out se resuelve con Redis pub/sub |
| 009 | **BFF en route handlers de Next.js**; el access token nunca llega al navegador | Token en `localStorage` | Elimina la clase completa de robo de token por XSS |
| 010 | **Cliente TypeScript generado desde OpenAPI** | Tipos escritos a mano | Hace imposible la deriva de contrato: el CI falla si el frontend usa un campo que la API ya no expone |
| 011 | **Almacenamiento de objetos compatible con S3** para adjuntos (AWS S3 en producción, LocalStack en desarrollo y CI) | Disco del contenedor, BYTEA en BD | Permite reprocesar, auditar y aplicar retención; evita hinchar la base de datos |
| 012 | **Worker de extracción aislado** con egress restringido | Un solo contenedor | El worker ejecuta parsers nativos sobre archivos no confiables: es la superficie de ataque principal |
| 013 | **Auth0 detrás de un `IdentityProviderPort`** | Keycloak autoalojado, JWT propio | Se conserva lo que ya funciona, sin acoplar el dominio al proveedor |
| 014 | **Dos repositorios separados** (backend y frontend), como en el sistema de referencia | Monorepo | Despliegue y ciclo de vida independientes, y continuidad con la organización actual del equipo. El coste —no poder cambiar la API y su cliente en el mismo commit— se compensa con el ADR 015 |
| 015 | **`openapi.json` versionado como contrato compartido** entre ambos repositorios | Paquete npm publicado; sincronización manual | Sin monorepo, el cliente TypeScript no puede regenerarse en el mismo commit que cambia la API. El CI del backend verifica que el esquema versionado está al día (`scripts/exportar_openapi.py`) y el del frontend regenera su cliente a partir de él y falla si hay diferencias. Mismo efecto que el monorepo —deriva de contrato imposible— con un paso más de pipeline y sin publicar un paquete |
| 016 | Las políticas RLS leen el tenant con **`nullif(current_setting('app.current_tenant', true), '')::uuid`** | `current_setting(..., true)` a secas | El segundo argumento devuelve `NULL` solo mientras la variable nunca se ha fijado en la conexión. Tras el primer `SET LOCAL`, al terminar la transacción queda como **cadena vacía**, y `''::uuid` lanza excepción. Con conexiones recicladas en un pool eso convierte "no se ve ninguna fila" en un error 500. El `nullif` restaura el fallo cerrado. Detectado por los tests de integración; corregido en la migración `0003` |
| 017 | **Alembic usa el mismo driver asíncrono que la aplicación** (`asyncpg` + `connection.run_sync`) | Reescribir la URL a `postgresql://` y usar un driver síncrono | SQLAlchemy 2.1 resuelve `postgresql://` a `psycopg` 3, que no es dependencia del proyecto: las migraciones no arrancaban. Un segundo driver además haría que un problema de conexión o de TLS se comportara distinto en las migraciones que en la aplicación |
| 018 | **El entorno de desarrollo se ajusta al código, no al revés**: el almacén exige `ServerSideEncryption` en cada `PutObject` sin excepciones, y soportarlo es un requisito del servicio de desarrollo y de CI | Hacer configurable el cifrado del almacén | Una opción para desactivar el cifrado acaba puesta en producción. Fue además el criterio que descartó Garage al sustituir MinIO: sin SSE, el emulador no sirve |
| 019 | **Los privilegios `UPDATE` y `DELETE` sobre `audit_log` se retiran al rol de aplicación** | Confiar solo en la ausencia de política RLS para esas operaciones | Sin política, PostgreSQL no da error: filtra todas las filas y la sentencia termina con éxito y cero filas afectadas, así que un intento de manipular la bitácora no deja rastro. Retirar el privilegio lo convierte en un error explícito, visible en el log del servidor e independiente de que RLS siga activo |
| 020 | **Dos controles de volumen separados:** un cortafuegos por minuto en el middleware (por IP, antes de autenticar) y **cuotas de negocio por tenant como dependencia de FastAPI** (después de autenticar) | Un único limitador en el middleware con límites por prefijo | Una cuota pertenece al tenant. Contarla en el middleware obliga a contarla por IP, porque el sujeto autenticado lo resuelve una dependencia que corre después de todo el middleware. Con una ventana de una hora eso era una denegación de servicio sin credenciales: veintiuna peticiones anónimas a `/scans` dejaban sin escaneos durante una hora a todos los que compartieran salida a internet. Lo detectó una prueba de carga |

---

## 4. Vista de contexto (C4 nivel 1)

```
                    ┌──────────────────────────────┐
                    │        Operador / Admin      │
                    │   (contador, administrador)  │
                    └───────────────┬──────────────┘
                                    │ HTTPS
                                    ▼
        ┌───────────────────────────────────────────────────┐
        │   Plataforma de Automatización de Correos         │
        │   (web + API + workers)                           │
        └──┬──────────┬──────────┬──────────┬───────────────┘
           │          │          │          │
           ▼          ▼          ▼          ▼
     ┌──────────┐ ┌────────┐ ┌────────┐ ┌─────────────┐
     │  Auth0   │ │ Gmail  │ │   MS   │ │ Proveedor   │
     │  (OIDC)  │ │  API   │ │ Graph  │ │ Visión IA   │
     └──────────┘ └────────┘ └────────┘ └─────────────┘
       identidad    buzón      buzón      OCR de
                                          último recurso
```

---

## 5. Vista de contenedores (C4 nivel 2)

```
┌─────────────────────────────────────────────────────────────────────┐
│                            Navegador                                │
│   Next.js (SSR/CSR) ──▶ BFF route handlers (sesión httpOnly)        │
└────────────────────────────────┬────────────────────────────────────┘
                                 │ HTTPS + cookie de sesión
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  API  (FastAPI, sin estado, N réplicas)                             │
│  ├─ Middlewares: request-id, CORS, rate limit, headers, logging     │
│  ├─ /api/v1/*  → casos de uso                                       │
│  └─ /api/v1/scans/{id}/stream  → SSE  ◀── Redis pub/sub             │
└───┬───────────────┬──────────────────┬──────────────────┬───────────┘
    │ encola        │ lee / escribe    │ publica estado   │
    ▼               ▼                  ▼                  ▼
┌────────┐   ┌────────────┐     ┌────────────┐    ┌──────────────┐
│ Redis  │   │ PostgreSQL │     │  Object    │    │  Secrets /   │
│ cola + │   │   + RLS    │     │  Storage   │    │     KMS      │
│ pubsub │   │            │     │ (S3)       │    │              │
│ + rate │   └────────────┘     └────────────┘    └──────────────┘
└───┬────┘          ▲                  ▲
    │ consume       │                  │
    ▼               │                  │
┌─────────────────────────────────────────────────────────────────────┐
│  Worker de ingesta (ARQ)        │  Worker de extracción (ARQ)       │
│  · lista correos                │  · parsers PDF / OCR / visión     │
│  · descarga adjuntos en stream  │  · AISLADO: no-root, rootfs RO,   │
│  · valida y sube a storage      │    egress restringido, seccomp,   │
│  · respeta 429 / Retry-After    │    límites CPU/RAM, tmpfs efímero │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │  Worker de cron (ARQ)   │
                    │  · refresco de tokens   │
                    │  · purga por retención  │
                    │  · rotación de claves   │
                    │  · reintento de fallidos│
                    └─────────────────────────┘
```

**Por qué tres roles de worker y no uno:** *bulkhead*. Un pico de OCR no debe retrasar la
descarga de correos ni el refresco de tokens, y el contenedor que parsea archivos no
confiables necesita un perfil de seguridad mucho más restrictivo que el que habla con Gmail.

---

## 6. Backend — estructura de capas

### 6.1 Reglas de dependencia (verificadas en CI)

```
  api  ──▶  application  ──▶  domain  ◀──  infrastructure
                                  ▲               │
                                  └───────────────┘
                              implementa los puertos

  domain         : no importa NADA del proyecto fuera de domain
  application    : importa domain. NO importa infrastructure ni api
  infrastructure : importa domain (para implementar puertos). NO importa api
  api            : importa application y domain. NO importa infrastructure
  bootstrap/     : composition root — único lugar que conoce todas las capas
```

Estas reglas se declaran en `importlinter.ini` y el pipeline falla si se violan.

### 6.2 Árbol de directorios

```
apps/api/
├── src/mailauto/
│   ├── bootstrap/                 # Composition root — ÚNICO lugar que cablea todo
│   │   ├── container.py           #   factories de dependencias (DI explícita)
│   │   ├── settings.py            #   Pydantic Settings, validado al arrancar
│   │   └── app.py                 #   create_app(): monta routers y middlewares
│   │
│   ├── shared/                    # Kernel compartido, sin lógica de negocio
│   │   ├── domain/                #   Entity, ValueObject, DomainEvent, Result
│   │   ├── errors.py              #   jerarquía de errores de dominio
│   │   ├── crypto/                #   AES-256-GCM, cifrado envolvente, hashing
│   │   ├── security/              #   verificación JWT, scopes, TenantContext
│   │   ├── observability/         #   logging estructurado, tracing, métricas
│   │   ├── pagination.py          #   paginación por cursor
│   │   └── types.py               #   UUIDv7, Money, tipos base
│   │
│   ├── modules/                   # Contextos acotados
│   │   ├── identity/              #   usuarios, tenants, roles, permisos
│   │   ├── mailbox/               #   conexiones OAuth y proveedores de correo
│   │   ├── ingestion/             #   jobs de escaneo, correos, adjuntos
│   │   ├── extraction/            #   perfiles, estrategias, registros, revisión
│   │   ├── reporting/             #   Excel/CSV, estadísticas
│   │   └── audit/                 #   bitácora de acciones privilegiadas
│   │
│   └── api/
│       ├── v1/routers/            # auth, mailboxes, scans, records, reports, admin
│       ├── middleware/            # request_id, rate_limit, security_headers, errors
│       ├── deps.py                # dependencias FastAPI (auth, tenant, paginación)
│       └── schemas/               # DTOs de entrada/salida (≠ entidades de dominio)
│
├── migrations/                    # Alembic
├── tests/{unit,integration,e2e,security}/
├── tools/                         # scripts de diagnóstico, fuera del paquete
├── importlinter.ini · pyproject.toml · Dockerfile · Dockerfile.worker
```

### 6.3 Anatomía de un módulo

Cada módulo repite la misma estructura, de modo que quien entiende uno entiende todos
(principio de mínima sorpresa):

```
modules/extraction/
├── domain/
│   ├── entities.py        # ExtractedRecord, ExtractionProfile, FieldConfidence
│   ├── value_objects.py   # Ruc, TaxPeriod, Amount, ContentHash  ← validan al construirse
│   ├── events.py          # RecordExtracted, ExtractionFailed, ReviewRequired
│   ├── policies.py        # reglas puras: ¿completo, parcial o vacío?
│   └── ports.py           # ExtractionStrategyPort, RecordRepositoryPort
├── application/
│   ├── commands/          # ExtractAttachment, ApproveRecord, RejectRecord
│   ├── queries/           # ListRecords, GetRecordDetail, GetReviewQueue
│   └── services/          # ExtractionOrchestrator (encadena estrategias)
└── infrastructure/
    ├── strategies/        # NativePdfText, PdfTables, TesseractOcr, VisionLlm
    ├── preprocessing/     # OpenCV: CLAHE, denoise, deskew, binarize
    ├── persistence/       # modelos SQLAlchemy + repositorio
    └── profiles/          # sunat_arrendamiento.py (perfil declarativo)
```

**Objetos de valor que validan al construirse.** `Ruc("20123456789")` ejecuta el dígito
verificador módulo 11 en su constructor. Un `Ruc` inválido no puede existir en el sistema:
la validación deja de ser algo que hay que acordarse de llamar.

---

## 7. Modelo de datos

### 7.1 Esquema (PostgreSQL 16)

```sql
-- ── Identidad y aislamiento ──────────────────────────────────────────
tenants(id uuid pk, name, slug unique, status, settings jsonb,
        created_at, updated_at)

users(id uuid pk, external_id unique,       -- 'sub' del IdP
      email citext, display_name, status, last_login_at)

memberships(id uuid pk, tenant_id fk, user_id fk,
            role,                            -- owner | admin | operator | viewer
            unique(tenant_id, user_id))

-- ── Buzones ──────────────────────────────────────────────────────────
mailbox_connections(
  id uuid pk, tenant_id fk, user_id fk,
  provider,                                  -- google | microsoft
  account_email citext,
  access_token_ct bytea,                     -- AES-256-GCM
  refresh_token_ct bytea,
  dek_id uuid fk, key_version int,           -- rotación de claves
  granted_scopes text[],
  expires_at timestamptz,
  status,                                    -- active | expired | revoked | error
  last_verified_at,
  unique(tenant_id, user_id, provider))

-- ── Ingesta ──────────────────────────────────────────────────────────
scan_jobs(
  id uuid pk, tenant_id fk, requested_by fk, connection_id fk,
  status,                                    -- queued | running | succeeded |
                                             -- failed | partial | cancelled
  params jsonb,                              -- rango de fechas, límite, carpeta
  idempotency_key text,
  progress_percent int, phase text,
  counters jsonb,                            -- revisados, con adjunto, extraídos, errores
  queued_at, started_at, finished_at,
  attempt int, error_code text, error_message text,
  unique(tenant_id, idempotency_key))

email_messages(
  id uuid pk, tenant_id fk, job_id fk,
  provider, provider_message_id text,
  sender citext, subject text, received_at timestamptz,
  unique(tenant_id, provider, provider_message_id))    -- idempotencia

attachments(
  id uuid pk, tenant_id fk, message_id fk,
  original_filename text,                    -- solo para mostrar, nunca para rutas
  storage_key text,                          -- UUID opaco en el bucket
  mime_type text, size_bytes bigint,
  sha256 char(64),
  av_status,                                 -- pending | clean | infected | skipped
  unique(tenant_id, message_id, sha256))     -- deduplicación

-- ── Extracción ───────────────────────────────────────────────────────
extracted_records(
  id uuid pk, tenant_id fk, attachment_id fk, job_id fk,
  profile text,                              -- 'sunat_arrendamiento'
  -- columnas tipadas, para consultar e indexar
  taxpayer_ruc varchar(11), taxpayer_name text,
  tenant_ruc varchar(11), tenant_name text,
  tax_period char(6),                        -- YYYYMM normalizado
  payment_date date, operation_number text,
  amount numeric(14,2), currency char(3),
  -- metadatos de calidad
  fields jsonb,                              -- campos crudos del perfil
  confidence jsonb,                          -- confianza por campo (0..1)
  completeness,                              -- complete | partial | empty
  review_status,                             -- not_required | pending | approved | rejected
  reviewed_by fk, reviewed_at,
  strategy_used text, extraction_ms int,
  created_at)

processing_errors(
  id uuid pk, tenant_id fk, job_id fk, attachment_id fk null,
  stage,                                     -- fetch | download | validate | extract | persist
  error_code text, message text, context jsonb,
  retryable bool, occurred_at)

-- ── Gobierno ─────────────────────────────────────────────────────────
audit_log(                                   -- append-only: sin UPDATE ni DELETE
  id bigserial pk, tenant_id, actor_id, actor_ip inet,
  action text, resource_type text, resource_id uuid,
  metadata jsonb, occurred_at)

encryption_keys(id uuid pk, tenant_id fk, wrapped_dek bytea,
                version int, status, created_at, rotated_at)
```

### 7.2 Aislamiento multi-tenant

Dos barreras independientes:

**Barrera 1 — aplicación.** Ningún repositorio expone un método sin `TenantContext`.
La firma lo hace imposible de olvidar:

```python
async def list_records(self, ctx: TenantContext, filters: RecordFilters,
                       page: CursorPage) -> Page[ExtractedRecord]: ...
```

**Barrera 2 — base de datos.** RLS activo en toda tabla con `tenant_id`. Cada transacción
abre con `SET LOCAL app.current_tenant = :tenant_id`, inyectado por el middleware:

```sql
ALTER TABLE extracted_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE extracted_records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON extracted_records
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

El rol de aplicación **no** es superusuario ni dueño de las tablas, para que RLS no pueda
omitirse. Un `WHERE` olvidado devuelve cero filas en lugar de filtrar datos ajenos.
Esto cierra **H1**.

### 7.3 Índices (derivados de las consultas reales, no especulativos)

```sql
-- listado principal del operador
idx_records_tenant_created   ON extracted_records (tenant_id, created_at DESC)
-- cola de revisión humana (índice parcial: solo lo pendiente)
idx_records_review_pending   ON extracted_records (tenant_id, created_at)
                             WHERE review_status = 'pending'
-- búsqueda por contribuyente y periodo (reporte mensual)
idx_records_ruc_period       ON extracted_records (tenant_id, taxpayer_ruc, tax_period)
-- panel de jobs
idx_jobs_tenant_status       ON scan_jobs (tenant_id, status, queued_at DESC)
-- deduplicación e idempotencia
idx_attachments_sha          ON attachments (tenant_id, sha256)
idx_messages_provider_id     ON email_messages (tenant_id, provider, provider_message_id)
```

Sin N+1: toda lectura de registros con su adjunto y su correo usa `selectinload` explícito
o un único join. Toda lista pagina por cursor — nunca `OFFSET` sobre tablas grandes,
nunca una respuesta sin límite.

---

## 8. Pipeline de ingesta y extracción

### 8.1 Flujo completo

```
POST /api/v1/scans  (Idempotency-Key)
   │  valida parámetros, verifica cuota del tenant, crea scan_job(queued)
   │  encola en Redis → responde 202 + Location: /api/v1/scans/{id}
   ▼
[Worker de ingesta]
   1. Resuelve y descifra el token; lo refresca si está por vencer
   2. Lista mensajes por rango de fecha (paginado, respetando 429 / Retry-After)
   3. Descarta los provider_message_id ya procesados  ──▶ idempotencia
   4. Por cada adjunto candidato:
        · corta por tamaño máximo DURANTE el streaming (nunca carga entero en RAM)
        · corta por número máximo de adjuntos por correo
        · verifica magic bytes + MIME real (libmagic), no la extensión
        · calcula SHA-256 en streaming  ──▶ deduplicación
        · antivirus opcional (ClamAV)
        · sube a object storage con clave UUID opaca (jamás el nombre original)
   5. Publica progreso en Redis  ──▶ SSE al navegador
   6. Encola un job de extracción por adjunto  ──▶ paralelismo real
   ▼
[Worker de extracción — contenedor aislado]
   Cadena de estrategias, de la más barata a la más cara; se detiene al alcanzar
   el umbral de confianza:

     1. Texto nativo PDF (PyMuPDF)      ~10 ms   costo 0
     2. Tablas PDF (pdfplumber)         ~80 ms   costo 0
     3. OCR local (OpenCV + Tesseract) ~800 ms   costo 0
     4. Visión IA (modelo multimodal)    ~2 s    costo $   ← último recurso

   Cada estrategia devuelve campos con una confianza por campo. El agregador toma el
   mejor valor de cada campo entre estrategias y aplica los validadores de dominio:
     · RUC: 11 dígitos + dígito verificador módulo 11
     · Periodo: normalizado a YYYYMM
     · Importe: parseo con locale, moneda explícita
     · Fecha: parseo estricto, rechazo de fechas imposibles

   Clasificación:  completo → persistido
                   parcial  → persistido + cola de revisión humana
                   vacío    → error registrado con el motivo
   ▼
[Resultado]  registros consultables, exportables a Excel/CSV y auditables
             hasta el correo y el adjunto de origen.
```

### 8.2 Revisión humana (mejora sobre el sistema de referencia)

El sistema actual marca un registro como "Parcial" y ahí termina. Aquí, un registro parcial
entra en una **cola de revisión**: el operador ve el adjunto original junto al formulario
precargado, corrige los campos dudosos y aprueba. Queda registrado quién corrigió qué y cuándo.

Esto convierte una limitación técnica (el OCR nunca es perfecto) en un flujo de trabajo
cerrado, y además genera el conjunto de datos etiquetados con el que medir la precisión
real de cada estrategia.

### 8.3 Resiliencia

| Mecanismo | Aplicación |
|-----------|-----------|
| Reintentos con backoff exponencial + jitter | Errores transitorios de red, 429, 5xx del proveedor |
| Límite de intentos → DLQ | Tras N intentos el job pasa a `failed` con la causa registrada, y es reintentable desde la UI |
| Timeout por etapa | Ninguna llamada externa ni parser sin plazo máximo |
| Circuit breaker por proveedor | Si Gmail o la API de visión se degradan, se corta y se encola en vez de martillar |
| Idempotencia | `(tenant, provider, message_id)` + `Idempotency-Key`: reintentar nunca duplica |
| Apagado controlado | El worker termina el job en curso antes de morir (`terminationGracePeriod`) |
| Presupuesto de IA por tenant | Contador mensual; al agotarse, el pipeline degrada a OCR local en vez de fallar |

---

## 9. Seguridad

### 9.1 Cobertura OWASP Top 10

| | Riesgo | Control |
|---|-------|---------|
| **A01** | Broken Access Control | `tenant_id` obligatorio en toda entidad; RLS en PostgreSQL como segunda barrera; autorización por scope y rol **antes** de cada caso de uso; tests automáticos que intentan acceso cruzado entre tenants y deben recibir un rechazo |
| **A02** | Cryptographic Failures | TLS 1.3 en tránsito; AES-256-GCM en reposo para tokens; cifrado envolvente (KEK en KMS, DEK por tenant) con versión de clave y rotación; AAD = `tenant\|provider\|user`, para que un ciphertext no sirva en otra fila; SHA-256 para hashes; sin PII en logs |
| **A03** | Injection | ORM parametrizado, cero SQL concatenado; validación de entrada con Pydantic en el borde y objetos de valor en el dominio; sanitización de nombres de archivo; sin `shell=True` en ninguna invocación de proceso |
| **A04** | Insecure Design | Modelado de amenazas documentado; límites de cuota y de tasa por diseño; separación de workers por perfil de riesgo; menor privilegio en BD, storage y contenedores |
| **A05** | Security Misconfiguration | Configuración validada al arrancar (la app no levanta con `CORS=*` o sin `ENCRYPTION_KEY` en producción); CSP con nonce, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy; trazas de excepción nunca al cliente; `/docs` cerrado en producción |
| **A06** | Vulnerable Components | Renovate con PRs automáticos; `pip-audit` + `npm audit` + Trivy sobre la imagen en CI; SBOM con Syft; versiones fijadas con hash |
| **A07** | Auth Failures | OIDC RS256 con JWKS cacheado y validación estricta de `iss` / `aud` / `exp` / `nbf` / `alg`; rechazo explícito de `alg: none` y de algoritmos simétricos; OAuth con PKCE S256 y `state` de un solo uso con TTL; rotación de refresh tokens; revocación efectiva al desvincular |
| **A08** | Integrity Failures | Imágenes firmadas con cosign; dependencias con hash; audit log append-only; validación de magic bytes antes de parsear cualquier adjunto |
| **A09** | Logging & Monitoring Failures | Logs JSON estructurados con `trace_id` / `tenant_id`, con filtro de redacción de secretos y PII; audit log de toda acción privilegiada; alertas sobre tasa de error, jobs fallidos y uso anómalo |
| **A10** | SSRF | Sin URLs controladas por el usuario en llamadas salientes; `redirect_uri` contra allowlist estricta; el worker de extracción no puede alcanzar la red interna ni el endpoint de metadatos de la nube (egress por allowlist) |

### 9.2 Tratamiento de adjuntos — la superficie crítica

Los adjuntos son **entrada no confiable de terceros procesada por parsers nativos**
(PyMuPDF, Tesseract, OpenCV). Es el vector de ataque más serio del sistema:

| Amenaza | Control |
|---------|---------|
| Bomba de descompresión / PDF bomb | Tope de páginas, tope de ratio de descompresión, timeout de render, límite de RAM del contenedor |
| XXE / entidades externas | Resolución de entidades externas deshabilitada; sin fetch de recursos remotos al renderizar |
| Path traversal | El nombre original jamás toca el sistema de archivos; la clave de almacenamiento es un UUID |
| Ejecutable disfrazado | Triple coincidencia extensión + MIME declarado + magic bytes reales; allowlist cerrada de tipos |
| CVE en el parser | Contenedor dedicado: no-root, rootfs de solo lectura, `tmpfs` efímero, `cap_drop: ALL`, perfil seccomp, sin egress salvo Redis/BD/proveedor IA |
| Malware | Escaneo ClamAV opcional antes de parsear |
| Inyección de prompt vía documento | El contenido del documento se trata como dato, nunca como instrucción: prompt con delimitadores, salida forzada a JSON Schema, sin acceso a herramientas desde el modelo, validación de dominio posterior obligatoria |

### 9.3 Gestión de secretos

- Nada de secretos en el código ni en el repositorio. `gitleaks` en pre-commit y en CI.
- Producción: KMS / Vault / secrets del proveedor. Desarrollo: `.env` fuera de git, con `.env.example` documentado.
- La configuración se valida al arrancar: si falta un secreto requerido en producción, **la aplicación no levanta**. Fallar rápido y visible, no degradar en silencio.
- Rotación de la clave maestra sin downtime gracias a `key_version` y a un recifrado diferido por job de cron.

---

## 10. Rendimiento y escalabilidad

| Palanca | Implementación |
|---------|----------------|
| Escalado horizontal | API sin estado (nada en memoria del proceso); los workers escalan por profundidad de cola |
| Paralelismo de extracción | Un job por adjunto; el grado de concurrencia es configuración, no código |
| Descarga en streaming | El adjunto nunca se carga completo en memoria, ni en la API ni en el worker |
| Caché | JWKS (TTL 1 h), metadatos de perfil, estadísticas agregadas en Redis con invalidación por evento |
| Paginación por cursor | Todas las listas; ninguna respuesta sin límite |
| Índices dirigidos | Derivados de las consultas reales (§7.3), incluidos índices parciales |
| Sin N+1 | Carga explícita de relaciones; test de integración que cuenta consultas por endpoint |
| Reporte Excel en streaming | Escritura por lotes con `openpyxl` en modo write-only; para volúmenes grandes, generación asíncrona y descarga por URL prefirmada |
| Frontend | Server Components por defecto, code splitting por ruta, `next/image`, TanStack Query con `staleTime` afinado, debounce en filtros |
| Particionado (futuro) | `extracted_records` por mes cuando el volumen lo justifique — no antes (YAGNI) |

---

## 11. Observabilidad

- **Trazas** — OpenTelemetry extremo a extremo: petición HTTP → job en cola → worker → llamada al proveedor. Una traza completa por escaneo.
- **Métricas** — Prometheus: duración por etapa del pipeline, tasa de éxito por estrategia de extracción, profundidad y antigüedad de la cola, costo de IA por tenant, tasa de 429 por proveedor.
- **Logs** — `structlog` en JSON con `trace_id`, `tenant_id` y `job_id`, y un procesador de redacción que elimina tokens, cabeceras de autorización y campos marcados como PII antes de serializar.
- **Errores** — Sentry con *scrubbing* de datos sensibles activado.
- **Salud** — `/health/live` (el proceso responde) y `/health/ready` (BD, Redis y storage alcanzables). Cada probe usa el endpoint correcto.
- **Auditoría** — tabla append-only para vinculación y desvinculación de buzones, lanzamiento de escaneos, exportación de reportes, aprobación de registros y cualquier acción de administrador.

---

## 12. Frontend — estructura

**Stack:** Next.js 16 (App Router) · React 19 · TypeScript strict · Tailwind CSS 4 ·
TanStack Query · Zod · React Hook Form · Vitest + Testing Library · Playwright · MSW.

```
apps/web/src/
├── app/                        # Rutas (App Router) — solo composición
│   ├── (auth)/login/
│   ├── (dashboard)/
│   │   ├── escaneos/ · registros/ · revision/ · reportes/ · buzones/
│   │   └── admin/
│   └── api/                    # BFF: intercambio de sesión, proxy, callback OAuth
│
├── features/                   # Feature-sliced: cada carpeta es autocontenida
│   ├── auth/ · mailboxes/ · scans/ · records/ · review/ · reports/ · admin/
│   │   ├── components/         #   UI de la feature
│   │   ├── hooks/              #   lógica (useScanProgress, useStartScan…)
│   │   ├── api/                #   llamadas, sobre el cliente generado
│   │   └── schemas.ts          #   validación Zod de formularios
│
├── shared/
│   ├── ui/                     # design system: Button, Table, Dialog, Toast…
│   ├── lib/                    # sse-client, formatters, helpers
│   └── config/                 # constantes, rutas, flags
│
└── generated/api/              # ⚠ GENERADO desde OpenAPI — no editar a mano
```

### Decisiones clave del frontend

**BFF: el access token nunca llega al navegador.** El login OIDC se completa en route
handlers del servidor; el navegador solo recibe una cookie de sesión `httpOnly`, `Secure`,
`SameSite=Lax`. Las llamadas a la API pasan por el BFF, que adjunta el token del lado
servidor. Un XSS deja de poder robar credenciales de API. (El sistema de referencia usa
`@auth0/auth0-react`, que mantiene el token accesible desde JavaScript.)

**TanStack Query en lugar del god-hook.** Caché, deduplicación de peticiones, reintentos,
invalidación por mutación y estados de carga/error resueltos por la librería. El hook de
350 líneas desaparece y cada feature expone dos a cuatro hooks pequeños y testeables.

**SSE para progreso en vivo.** `useScanProgress(jobId)` abre un `EventSource` contra
`/api/v1/scans/{id}/stream` y recibe eventos; se acaba el polling cada N segundos.
Con reconexión automática y `Last-Event-ID` para no perder eventos.

**Cliente generado.** `openapi-typescript` + `orval` producen tipos y hooks a partir del
`openapi.json` que el backend versiona (ADR 015). Si el backend renombra un campo, el build
del frontend falla en CI en lugar de romperse en producción. Elimina **H10**.

**Accesibilidad y UX.** WCAG 2.2 AA: navegación por teclado, roles ARIA, contraste
verificado, `prefers-reduced-motion`. Estados vacíos, de carga (skeletons) y de error
diseñados explícitamente, no como una excepción.

---

## 13. Contrato de API

**Versionado:** `/api/v1`. **Formato de error:** RFC 9457 Problem Details, con el tipo
expresado como URN (`urn:mailauto:error:<codigo>`): RFC 9457 admite cualquier URI, y una
URL `https` que no resuelve prometería una documentación que no existe.
**Envoltura de éxito:** consistente en todos los endpoints.

```jsonc
// Éxito
{ "status": "ok",
  "data": { },
  "meta": { "cursor": "...", "has_more": true } }

// Error (RFC 9457)
{ "type": "urn:mailauto:error:validacion-fallida",
  "title": "Datos de entrada inválidos",
  "status": 422,
  "detail": "El rango de fechas excede el máximo permitido",
  "instance": "/api/v1/scans",
  "trace_id": "0af7651916cd43dd...",
  "errors": [ { "field": "date_from", "code": "range_too_wide" } ] }
```

| Método | Ruta | Descripción | Autorización |
|--------|------|-------------|--------------|
| GET | `/health/live` · `/health/ready` | Sondas de salud | público |
| GET | `/api/v1/me` | Perfil, tenant y permisos efectivos | autenticado |
| GET | `/api/v1/mailboxes` | Buzones vinculados | `mailbox:read` |
| POST | `/api/v1/mailboxes/{provider}/authorize` | Inicia OAuth (PKCE + state) | `mailbox:write` |
| POST | `/api/v1/mailboxes/{provider}/callback` | Completa OAuth | `mailbox:write` |
| DELETE | `/api/v1/mailboxes/{id}` | Desvincula y **revoca** en el proveedor | `mailbox:write` |
| POST | `/api/v1/scans` | Lanza escaneo → `202` + `Location` | `scan:run` |
| GET | `/api/v1/scans` | Historial paginado | `scan:read` |
| GET | `/api/v1/scans/{id}` | Detalle y contadores | `scan:read` |
| GET | `/api/v1/scans/{id}/stream` | **SSE** de progreso en vivo | `scan:read` |
| POST | `/api/v1/scans/{id}/cancel` | Cancela un escaneo en curso | `scan:run` |
| GET | `/api/v1/records` | Registros con filtros y cursor | `record:read` |
| GET | `/api/v1/records/{id}` | Detalle y confianza por campo | `record:read` |
| GET | `/api/v1/records/{id}/attachment` | URL prefirmada, TTL corto | `record:read` |
| GET | `/api/v1/review` | Cola de revisión humana | `record:review` |
| PATCH | `/api/v1/records/{id}` | Corrige campos y aprueba | `record:review` |
| POST | `/api/v1/reports/exports` | Solicita export (Excel/CSV) → `202` | `report:read` |
| GET | `/api/v1/reports/exports/{id}` | Estado y URL de descarga | `report:read` |
| GET | `/api/v1/reports/statistics` | Agregados del tenant | `report:read` |
| GET | `/api/v1/errors` | Errores de procesamiento | `scan:read` |
| GET | `/api/v1/audit` | Bitácora de auditoría | `admin:read` |
| POST | `/api/v1/admin/retention/purge` | Purga **del tenant**, con confirmación | `admin:write` |

Cabeceras soportadas: `Idempotency-Key` en los POST que crean trabajo, `X-Request-ID`,
`If-None-Match` / `ETag` en lecturas cacheables.

**Lo que la API no devuelve nunca:** tokens OAuth (ni cifrados), rutas internas, nombres
de tablas, trazas de excepción, ni registros de otro tenant — esto último verificado por test.

---

## 14. Estrategia de testing

| Nivel | Herramientas | Alcance | Meta |
|-------|-------------|---------|------|
| Unitario | pytest, Hypothesis | Dominio puro: validador de RUC, normalización de periodo, políticas de completitud, agregador de confianza. Sin BD ni red | ≥ 90 % en `domain/` |
| Aplicación | pytest-asyncio, dobles de prueba | Casos de uso contra puertos simulados | ≥ 85 % en `application/` |
| Integración ✅ | pytest contra los servicios de `docker compose` (PostgreSQL, Redis, LocalStack) | Migraciones aplicadas, **RLS verificado sobre la base real**, privilegios del rol de aplicación, consumo atómico del `state` OAuth, ciclo completo del almacén de adjuntos | 36 tests |
| Contrato | Schemathesis sobre el OpenAPI | Fuzzing de todos los endpoints contra su esquema | sin 500 inesperados |
| Seguridad | Suite dedicada | Acceso cruzado entre tenants, escalada de rol, JWT manipulado (`alg: none`, firma inválida, `aud` erróneo), path traversal en el nombre del adjunto, PDF bomb, archivo con magic bytes falsos | todos deben recibir un rechazo |
| E2E ✅ | Playwright | Acceso al panel, escaneo con progreso en vivo por SSE, paginación por cursor, cola de revisión, exportación asíncrona y accesibilidad | 43 tests |
| Carga 🔄 | k6 | Escenario de humo ✅ (salud, autenticación exigida, limitador bajo ráfaga). Escenarios autenticados escritos y pendientes de ejecutar en staging: lectura sostenida y 50 escaneos concurrentes | p95 < 300 ms en lecturas |
| Estático | ruff, mypy strict, bandit, semgrep, import-linter, eslint, tsc | Todo el código | sin hallazgos nuevos |

Fixtures con datos sintéticos. **Ningún documento tributario real en el repositorio.**

### Por qué los tests de integración no son opcionales

Row Level Security falla en silencio. PostgreSQL exime de las políticas al propietario de
la tabla y a los superusuarios, así que una aplicación conectada con el rol equivocado ve
el esquema completo con RLS "habilitado" en cada panel y sin filtrar una sola fila: no hay
error, no hay aviso, y los datos fiscales de un cliente quedan visibles para otro.

Ninguna comprobación estática puede detectarlo —la política está escrita, la columna
existe, la migración la aplica— porque lo que falta es el rol. De ahí la división:

- `tests/security/test_cobertura_de_rls.py` compara la metadata del código con el
  contrato `TABLAS_CON_RLS` de cada migración. Cubre **el olvido**, que es el fallo
  frecuente, y corre en cada push sin infraestructura.
- `tests/integration/test_aislamiento_rls.py` lee `pg_policies` y `pg_roles` de la base
  real y ejerce accesos cruzados con el rol de aplicación. Cubre **la configuración**,
  que es el fallo raro y el grave.

Se prescindió de `testcontainers`: el repositorio ya trae los tres servicios en
`docker-compose.yml` y en CI los runners ofrecen `services:` nativos. Una librería que
arranque contenedores desde el proceso de pytest añadiría una dependencia de desarrollo,
exigiría Docker accesible desde el propio test y duplicaría el lugar donde se declaran las
versiones de PostgreSQL y Redis. Los tests leen las URLs del entorno y se saltan solos si
no hay nada escuchando; en CI un salto se trata como fallo, porque un trabajo en verde que
no comprobó nada es peor que un trabajo rojo.

---

## 15. CI/CD y despliegue

### Pipeline (GitHub Actions)

```
PR abierto
 ├─ lint          ruff · mypy --strict · eslint · tsc --noEmit
 ├─ arquitectura  import-linter (contratos de capas)   ← falla si se viola una capa
 ├─ test          unit + integración (testcontainers) + contrato
 ├─ seguridad     bandit · semgrep · pip-audit · npm audit · gitleaks
 ├─ contrato      genera el cliente TS y verifica que no haya diff sin commitear
 └─ build         imágenes api/worker/web · Trivy · SBOM (Syft) · firma (cosign)

merge a main → deploy a staging → smoke tests → aprobación manual → producción
```

Reglas de rama: `main` protegida, PR obligatorio, checks en verde, commits convencionales
(`type(scope): descripción`), Renovate para dependencias.

### Entornos

**Desarrollo** — `docker compose up` levanta api, worker-ingesta, worker-extracción,
worker-cron, postgres, redis, minio y jaeger. Un solo comando, sin instalar Tesseract a mano.

**Producción** — contenedores en el proveedor elegido (Fly.io / Render / AWS ECS).
API y workers escalan por separado. Migraciones compatibles hacia atrás (expand/contract)
para desplegar sin downtime.

```
Dockerfile          → imagen de API    (slim, sin Tesseract ni OpenCV)
Dockerfile.worker   → imagen de worker (con Tesseract, OpenCV, poppler)
```

Separarlas reduce la imagen de API en cientos de MB y, sobre todo, quita del contenedor
expuesto a Internet todas las bibliotecas nativas de parseo.

---

## 16. Cumplimiento y privacidad

- **Minimización.** El texto OCR crudo no se persiste por defecto. Si un tenant lo activa para diagnóstico, se almacena cifrado y con purga automática por TTL. Corrige **H7**.
- **Retención.** Política configurable por tenant; un job de cron purga adjuntos, correos y registros vencidos, y la purga queda en el audit log.
- **Derecho de supresión.** Endpoint de borrado por tenant que elimina datos y objetos del storage, dejando constancia del acto sin conservar el contenido.
- **Alcances mínimos de OAuth.** `gmail.readonly` y `Mail.Read`. Ningún permiso de escritura o de envío.
- **Verificación de Google.** ⚠ `gmail.readonly` es un *restricted scope*: publicar la app en producción exige verificación por parte de Google y, al superar el umbral de usuarios, una evaluación de seguridad CASA por un asesor autorizado. **Hay que planificar tiempo y costo desde el inicio** — no es un trámite menor y bloquea el lanzamiento si se deja para el final.
- **Residencia de datos.** Región de base de datos y bucket configurables, documentada en el README.

---

## 17. Plan de implementación por fases

| Fase | Contenido | Resultado verificable |
|------|-----------|----------------------|
| **0 — Cimientos** ✅ | Monorepo, Docker Compose, configuración validada, logging y tracing, health checks, CI con lint + arquitectura + tests | `docker compose up` levanta todo; CI en verde |
| **1 — Identidad y aislamiento** ✅ | Tenants, usuarios, roles, verificación OIDC, `TenantContext`, RLS, audit log | Los tests de acceso cruzado entre tenants reciben un rechazo (cierra **H1**) |
| **2 — Buzones** ✅ | OAuth con PKCE para Google y Microsoft, cifrado envolvente, refresco y revocación de tokens | Vincular, verificar y desvincular un buzón real |
| **3 — Ingesta** ✅ | Cola ARQ, worker de ingesta, listado y descarga en streaming, validación de adjuntos, object storage, SSE de progreso | Escaneo real con progreso en vivo y reanudación tras reinicio (cierra **H2** y **H3**) |
| **4 — Extracción** ✅ | Cadena de estrategias, preprocesamiento OpenCV, perfil SUNAT, objetos de valor con validación, confianza por campo | Precisión medida sobre un set sintético etiquetado |
| **5 — Revisión y reportes** ✅ | Cola de revisión humana, corrección y aprobación, export Excel/CSV asíncrono, estadísticas | Flujo completo extremo a extremo |
| **6 — Frontend** | Design system, features, cliente generado, BFF, SSE, a11y, tests | Playwright en verde sobre los flujos críticos |
| **7 — Endurecimiento** 🔄 | Tests de integración contra PostgreSQL, Redis y un S3 real ✅ · E2E con Playwright ✅ · cuotas por tenant separadas del cortafuegos de avalanchas ✅ · escenario de humo de carga ✅ · pendiente: ejecutar los escenarios de carga autenticados en staging | Informe de seguridad y de carga |
| **8 — Operación** | Runbooks, dashboards, alertas, manual técnico y de usuario, despliegue a producción | Sistema operando y documentado |

---

## 18. Riesgos y mitigaciones

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| La verificación CASA de Google demora o encarece el lanzamiento | Alto | Iniciar el trámite en la Fase 2, no al final; mantener Outlook como camino alternativo mientras tanto |
| La precisión del OCR no alcanza lo esperado en documentos de baja calidad | Alto | Cadena de estrategias con IA de visión como respaldo, más cola de revisión humana: el sistema es útil incluso con precisión imperfecta |
| El costo de la IA de visión se dispara | Medio | Último escalón del pipeline, presupuesto por tenant, corte automático con degradación a OCR local, métrica de costo por registro |
| Límites de tasa de Gmail / Graph en escaneos grandes | Medio | Backoff respetando `Retry-After`, paginación, cuotas por tenant, reanudación por cursor |
| Cambios en los formatos de documento SUNAT | Medio | Perfiles de extracción declarativos y versionados: adaptarse es editar un perfil, no el motor |
| Complejidad del rediseño frente al sistema actual | Medio | Entrega por fases: cada fase deja algo funcionando y verificable, no un *big bang* |

---

## Apéndice — Stack completo

**Backend:** Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2.0 async · Alembic ·
asyncpg · ARQ · Redis · PostgreSQL 16 · aioboto3 (S3) · PyMuPDF · pdfplumber · Tesseract ·
OpenCV · Pillow · openpyxl · structlog · OpenTelemetry · cryptography · Authlib ·
pytest · Testcontainers · ruff · mypy · import-linter · bandit

**Frontend:** Next.js 16 · React 19 · TypeScript · Tailwind CSS 4 · TanStack Query ·
Zod · React Hook Form · openapi-typescript + orval · Vitest · Testing Library ·
Playwright · MSW · ESLint

**Infraestructura:** Docker · Docker Compose · GitHub Actions · Trivy · Syft · cosign ·
gitleaks · Renovate · Sentry · Prometheus · Jaeger
