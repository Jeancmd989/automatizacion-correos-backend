"""
Aislamiento multi-tenant verificado contra PostgreSQL real.

Proposito
    Comprobar que Row Level Security no solo esta declarado, sino que
    filtra. Es el unico test del proyecto que puede afirmarlo.

Por que hace falta una base de datos
    RLS falla en silencio. PostgreSQL exime de las politicas al
    propietario de la tabla y a los superusuarios, asi que una
    aplicacion conectada con el rol equivocado ve el esquema entero con
    RLS "habilitado" en cada panel y sin filtrar una sola fila. No hay
    error, no hay aviso, y los datos fiscales de un cliente quedan
    visibles para otro. Ningun test sin base de datos puede detectarlo:
    la politica esta escrita, la columna existe, la migracion la aplica.
    Lo que falta es el rol.

Dependencias
    PostgreSQL con las migraciones aplicadas y los dos roles creados por
    `scripts/init-db.sql`.

Decision de diseño
    Las aserciones se hacen a traves de `FabricaDeSesiones`, no con SQL
    suelto. Lo que debe quedar protegido es el camino que recorre la
    aplicacion, incluida la forma en que esa clase fija
    `app.current_tenant`; un test que abriera su propia conexion
    verificaria la base de datos y no el producto.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from mailauto.shared.db.session import FabricaDeSesiones, leer_tenant_actual
from tests.contratos_de_esquema import (
    TABLAS_DE_INFRAESTRUCTURA,
    TABLAS_GLOBALES,
    tablas_protegidas_por_las_migraciones,
)
from tests.integration.conftest import DosTenants, sembrar_escaneo

pytestmark = [pytest.mark.integration, pytest.mark.security]

_CONTAR_ESCANEOS = text("SELECT count(*) FROM scan_jobs")


# ─────────────────────────────────────────────────────────────────────
# Configuracion: el rol con el que se conecta la aplicacion
# ─────────────────────────────────────────────────────────────────────


async def test_el_rol_de_aplicacion_no_puede_saltarse_rls(
    motor_de_aplicacion: AsyncEngine,
) -> None:
    """
    Un rol con SUPERUSER o con BYPASSRLS ignora todas las politicas.

    Es la forma mas directa de anular el aislamiento entero sin tocar
    ni una linea del esquema, y ocurre sin querer: basta desplegar con
    las credenciales que se usaron para crear la base de datos.
    """
    async with motor_de_aplicacion.connect() as conexion:
        fila = (
            await conexion.execute(
                text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")
            )
        ).one()

    superusuario, puede_saltarse = fila
    assert not superusuario, "El rol de la aplicacion es superusuario: RLS no se aplica"
    assert not puede_saltarse, "El rol de la aplicacion tiene BYPASSRLS: RLS no se aplica"


async def test_el_rol_de_aplicacion_no_es_propietario_de_ninguna_tabla(
    motor_de_aplicacion: AsyncEngine,
) -> None:
    """
    El propietario esta exento de sus propias politicas salvo con FORCE.

    El esquema usa FORCE, asi que esto es una segunda barrera: si
    alguien retirara el FORCE de una migracion futura, el aislamiento
    seguiria en pie mientras la aplicacion no sea propietaria.
    """
    async with motor_de_aplicacion.connect() as conexion:
        propias = (
            (
                await conexion.execute(
                    text(
                        "SELECT c.relname FROM pg_class c "
                        "JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = 'public' AND c.relkind = 'r' "
                        "AND pg_get_userbyid(c.relowner) = current_user"
                    )
                )
            )
            .scalars()
            .all()
        )

    assert not propias, f"El rol de la aplicacion es propietario de: {sorted(propias)}"


async def test_toda_tabla_declarada_tiene_rls_habilitado_y_forzado(
    motor_propietario: AsyncEngine,
) -> None:
    """
    El complemento de `tests/security/test_cobertura_de_rls.py`: aquel
    comprueba que la migracion lo declare, este que la base de datos lo
    tenga puesto. Una migracion aplicada a medias pasa el primero y
    falla aqui.
    """
    declaradas = tablas_protegidas_por_las_migraciones()
    assert declaradas, "El contrato de migraciones esta vacio"

    async with motor_propietario.connect() as conexion:
        filas = (
            await conexion.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = 'public' AND c.relkind = 'r'"
                )
            )
        ).all()

    estado = {nombre: (habilitado, forzado) for nombre, habilitado, forzado in filas}

    faltantes = declaradas - set(estado)
    assert not faltantes, f"Tablas declaradas que no existen en la base: {sorted(faltantes)}"

    sin_rls = sorted(t for t in declaradas if not estado[t][0])
    sin_force = sorted(t for t in declaradas if not estado[t][1])
    assert not sin_rls, f"Tablas sin RLS habilitado: {sin_rls}"
    assert not sin_force, f"Tablas con RLS pero sin FORCE: {sin_force}"


async def test_no_hay_tablas_de_negocio_fuera_del_contrato(
    motor_propietario: AsyncEngine,
) -> None:
    """
    Al reves que el anterior: una tabla con `tenant_id` creada a mano en
    la base de datos, sin pasar por una migracion, no estaria en el
    contrato y nadie la miraria.
    """
    async with motor_propietario.connect() as conexion:
        con_tenant = set(
            (
                await conexion.execute(
                    text(
                        "SELECT table_name FROM information_schema.columns "
                        "WHERE table_schema = 'public' AND column_name = 'tenant_id'"
                    )
                )
            )
            .scalars()
            .all()
        )

    huerfanas = sorted(
        con_tenant
        - tablas_protegidas_por_las_migraciones()
        - TABLAS_GLOBALES
        - TABLAS_DE_INFRAESTRUCTURA
    )
    assert not huerfanas, f"Tablas con tenant_id que ninguna migracion protege: {huerfanas}"


async def test_las_politicas_leen_la_variable_de_sesion_de_forma_tolerante(
    motor_propietario: AsyncEngine,
) -> None:
    """
    Verifica la expresion que PostgreSQL tiene realmente guardada.

    Dos cosas, y la segunda es la que costo un fallo en produccion:

    · Que compare contra `app.current_tenant`. Una politica que no la
      lea no filtra por el tenant de la transaccion.

    · Que envuelva la lectura en `nullif(..., '')`. El segundo argumento
      de `current_setting` devuelve NULL solo mientras la variable nunca
      se ha fijado en la conexion; despues de la primera transaccion
      queda como cadena vacia, y `''::uuid` lanza excepcion. Sin el
      `nullif`, una consulta sin tenant sobre una conexion reciclada
      revienta en vez de devolver vacio.
    """
    async with motor_propietario.connect() as conexion:
        filas = (
            await conexion.execute(
                text(
                    "SELECT tablename, policyname, qual, with_check "
                    "FROM pg_policies WHERE schemaname = 'public'"
                )
            )
        ).all()

    assert filas, "No hay ninguna politica en la base de datos"

    for tabla, politica, usando, comprobacion in filas:
        expresiones = [e for e in (usando, comprobacion) if e]
        assert expresiones, f"La politica {politica} de {tabla} no tiene expresion"
        for expresion in expresiones:
            assert "app.current_tenant" in expresion, (
                f"{tabla}.{politica} no compara contra app.current_tenant: {expresion}"
            )
            assert "NULLIF" in expresion.upper(), (
                f"{tabla}.{politica} castea la variable sin NULLIF y fallara en una "
                f"conexion reciclada: {expresion}"
            )


async def test_una_conexion_reciclada_sin_tenant_no_lanza_excepcion(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    """
    El fallo exacto que destapo este fichero, aislado en un test.

    `SET LOCAL` deja la variable como cadena vacia al terminar la
    transaccion, no indefinida. Si la politica casteara eso a uuid, esta
    segunda consulta devolveria un 500 con un mensaje que habla de un
    UUID vacio que nadie escribio.
    """
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        await sesion.execute(_CONTAR_ESCANEOS)

    async with fabrica.sesion_de_sistema_sin_aislamiento() as sesion:
        assert (await sesion.execute(_CONTAR_ESCANEOS)).scalar_one() == 0


# ─────────────────────────────────────────────────────────────────────
# Lectura
# ─────────────────────────────────────────────────────────────────────


async def test_un_tenant_no_ve_los_escaneos_de_otro(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    """El caso que da sentido a todo el esquema."""
    propio = await sembrar_escaneo(motor_propietario, tenants.a, tenants.usuario_a)
    ajeno = await sembrar_escaneo(motor_propietario, tenants.b, tenants.usuario_b)

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        visibles = set((await sesion.execute(text("SELECT id FROM scan_jobs"))).scalars().all())

    assert propio in visibles
    assert ajeno not in visibles, "Un tenant ve los escaneos de otro: RLS no esta filtrando"


async def test_consultar_por_el_id_ajeno_no_devuelve_nada(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    """
    Conocer el identificador no debe bastar. Es el ataque realista:
    un UUID filtrado en un log, en una URL o en un informe.
    """
    ajeno = await sembrar_escaneo(motor_propietario, tenants.b, tenants.usuario_b)

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        resultado = await sesion.execute(
            text("SELECT id FROM scan_jobs WHERE id = :id"), {"id": ajeno}
        )
        assert resultado.scalar_one_or_none() is None


async def test_sin_contexto_de_tenant_no_se_ve_ninguna_fila(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    """
    La sesion de sistema existe para las tablas globales. Si por
    descuido se usara con una tabla de negocio, debe devolver cero
    filas y no el conjunto completo: fallar cerrado.
    """
    await sembrar_escaneo(motor_propietario, tenants.a, tenants.usuario_a)

    async with fabrica.sesion_de_sistema_sin_aislamiento() as sesion:
        assert await leer_tenant_actual(sesion) is None
        assert (await sesion.execute(_CONTAR_ESCANEOS)).scalar_one() == 0


async def test_el_tenant_no_sobrevive_al_final_de_la_transaccion(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    """
    El riesgo de `SET` frente a `SET LOCAL`, comprobado sobre el pool.

    Con `SET`, la variable viaja con la conexion al devolverla al pool y
    la siguiente peticion —de otro cliente— hereda el tenant anterior.
    El pool de este test tiene dos conexiones, asi que la segunda sesion
    reutiliza con seguridad una conexion ya usada.
    """
    await sembrar_escaneo(motor_propietario, tenants.a, tenants.usuario_a)

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        assert await leer_tenant_actual(sesion) == str(tenants.a)
        assert (await sesion.execute(_CONTAR_ESCANEOS)).scalar_one() == 1

    # Misma conexion reciclada, sin declarar tenant: no debe arrastrar
    # el de la transaccion anterior ni reventar al castear la variable.
    for _ in range(3):
        async with fabrica.sesion_de_sistema_sin_aislamiento() as sesion:
            assert (await sesion.execute(_CONTAR_ESCANEOS)).scalar_one() == 0

    async with fabrica.sesion_de_tenant_por_id(tenants.b) as sesion:
        assert (await sesion.execute(_CONTAR_ESCANEOS)).scalar_one() == 0


# ─────────────────────────────────────────────────────────────────────
# Escritura
# ─────────────────────────────────────────────────────────────────────


async def test_insertar_una_fila_con_tenant_ajeno_es_rechazado(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    """
    Es lo que aporta WITH CHECK. Sin el, el aislamiento protegeria la
    lectura y dejaria sembrar filas en el espacio de otro cliente.
    """
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        with pytest.raises(DBAPIError) as fallo:
            await sesion.execute(
                text(
                    "INSERT INTO scan_jobs (id, tenant_id, conexion_id, encolado_en) "
                    "VALUES (:id, :tenant, :conexion, now())"
                ),
                {"id": uuid4(), "tenant": tenants.b, "conexion": uuid4()},
            )

    assert "row-level security" in str(fallo.value).lower()


async def test_actualizar_una_fila_ajena_no_afecta_a_nada(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    """
    Un UPDATE contra una fila invisible no es un error: simplemente no
    encuentra nada. Lo que no debe pasar es que la modifique.
    """
    ajeno = await sembrar_escaneo(motor_propietario, tenants.b, tenants.usuario_b)

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        resultado = await sesion.execute(
            text("UPDATE scan_jobs SET estado = 'cancelled' WHERE id = :id"),
            {"id": ajeno},
        )
        assert resultado.rowcount == 0

    async with motor_propietario.connect() as conexion:
        estado = (
            await conexion.execute(
                text("SELECT estado FROM scan_jobs WHERE id = :id"), {"id": ajeno}
            )
        ).scalar_one()
    assert estado == "queued", "Un tenant modifico un escaneo de otro"


async def test_borrar_una_fila_ajena_no_afecta_a_nada(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    ajeno = await sembrar_escaneo(motor_propietario, tenants.b, tenants.usuario_b)

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        resultado = await sesion.execute(
            text("DELETE FROM scan_jobs WHERE id = :id"), {"id": ajeno}
        )
        assert resultado.rowcount == 0

    async with motor_propietario.connect() as conexion:
        sigue = (
            await conexion.execute(
                text("SELECT count(*) FROM scan_jobs WHERE id = :id"), {"id": ajeno}
            )
        ).scalar_one()
    assert sigue == 1, "Un tenant borro un escaneo de otro"


async def test_no_se_puede_mover_una_fila_propia_a_otro_tenant(
    fabrica: FabricaDeSesiones,
    motor_propietario: AsyncEngine,
    tenants: DosTenants,
) -> None:
    """
    Reescribir `tenant_id` seria una fuga hacia fuera: regalar una fila
    propia al espacio de otro cliente. WITH CHECK tambien lo cubre.
    """
    propio = await sembrar_escaneo(motor_propietario, tenants.a, tenants.usuario_a)

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        with pytest.raises(DBAPIError) as fallo:
            await sesion.execute(
                text("UPDATE scan_jobs SET tenant_id = :otro WHERE id = :id"),
                {"otro": tenants.b, "id": propio},
            )

    assert "row-level security" in str(fallo.value).lower()


# ─────────────────────────────────────────────────────────────────────
# Privilegios: lo que el rol de aplicacion no debe poder hacer
# ─────────────────────────────────────────────────────────────────────


async def test_la_aplicacion_no_puede_desactivar_rls(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    """
    Si la aplicacion pudiera alterar la tabla, una inyeccion SQL con
    exito no se limitaria a leer: desactivaria el aislamiento y
    despues leeria con total normalidad.
    """
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        with pytest.raises((ProgrammingError, DBAPIError)):
            await sesion.execute(text("ALTER TABLE scan_jobs DISABLE ROW LEVEL SECURITY"))


async def test_la_aplicacion_no_puede_crear_politicas(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    """Una politica permisiva añadida en caliente anula la restrictiva."""
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        with pytest.raises((ProgrammingError, DBAPIError)):
            await sesion.execute(text("CREATE POLICY colada ON scan_jobs FOR SELECT USING (true)"))


async def test_la_aplicacion_no_puede_crear_tablas(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    """
    Sin CREATE sobre el esquema, una inyeccion no puede dejar una tabla
    propia donde acumular lo que vaya extrayendo.
    """
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        with pytest.raises((ProgrammingError, DBAPIError)):
            await sesion.execute(text("CREATE TABLE colada (id int)"))


# ─────────────────────────────────────────────────────────────────────
# Bitacora de auditoria
# ─────────────────────────────────────────────────────────────────────


async def test_la_bitacora_admite_insercion_y_lectura(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        await sesion.execute(
            text(
                "INSERT INTO audit_log (tenant_id, actor_id, accion, tipo_de_recurso) "
                "VALUES (:tenant, :actor, 'scan.started', 'scan_job')"
            ),
            {"tenant": tenants.a, "actor": tenants.usuario_a},
        )

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        total = (await sesion.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()
    assert total == 1


async def test_la_bitacora_no_se_puede_reescribir_ni_borrar(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    """
    Una auditoria que el propio sistema comprometido puede editar no
    sirve como evidencia.

    Hay dos barreras y se comprueban las dos. Las politicas cubren solo
    SELECT e INSERT, asi que un UPDATE no encuentra ninguna fila: es
    seguro, pero termina con exito y cero filas afectadas, de modo que un
    intento de manipulacion no deja rastro. Por eso el rol de aplicacion
    tampoco tiene los privilegios UPDATE y DELETE sobre la tabla: el
    intento se convierte en un error explicito de permisos, visible en el
    log de PostgreSQL e independiente de que RLS siga activo.
    """
    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        await sesion.execute(
            text(
                "INSERT INTO audit_log (tenant_id, actor_id, accion, tipo_de_recurso) "
                "VALUES (:tenant, :actor, 'scan.started', 'scan_job')"
            ),
            {"tenant": tenants.a, "actor": tenants.usuario_a},
        )

    for sentencia in ("UPDATE audit_log SET accion = 'nada'", "DELETE FROM audit_log"):
        async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
            with pytest.raises(DBAPIError) as fallo:
                await sesion.execute(text(sentencia))
            assert "permission denied" in str(fallo.value).lower(), (
                f"`{sentencia}` no fue rechazada por privilegios: {fallo.value}"
            )

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        total = (await sesion.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()
    assert total == 1, "La entrada de auditoria desaparecio"


async def test_la_bitacora_de_un_tenant_es_invisible_para_otro(
    fabrica: FabricaDeSesiones,
    tenants: DosTenants,
) -> None:
    async with fabrica.sesion_de_tenant_por_id(tenants.b) as sesion:
        await sesion.execute(
            text(
                "INSERT INTO audit_log (tenant_id, actor_id, accion, tipo_de_recurso) "
                "VALUES (:tenant, :actor, 'mailbox.linked', 'mailbox_connection')"
            ),
            {"tenant": tenants.b, "actor": tenants.usuario_b},
        )

    async with fabrica.sesion_de_tenant_por_id(tenants.a) as sesion:
        total = (await sesion.execute(text("SELECT count(*) FROM audit_log"))).scalar_one()
    assert total == 0
