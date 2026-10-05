-- ────────────────────────────────────────────────────────────────────
-- Inicializacion de la base de datos de desarrollo.
--
-- Crea el rol con el que se conecta la aplicacion. Es deliberadamente
-- distinto del propietario de las tablas, y esa separacion es la que
-- hace que Row Level Security funcione de verdad:
--
--   · PostgreSQL EXIME al propietario de una tabla de sus politicas RLS.
--   · Tambien exime a los superusuarios.
--
-- Si la aplicacion se conectara como `mailauto_owner`, las politicas
-- estarian creadas y activas, el panel diria que RLS esta habilitado, y
-- aun asi no filtrarian absolutamente nada. Es un fallo silencioso: no
-- hay error, no hay aviso, solo datos de un tenant visibles para otro.
--
-- En produccion esta separacion la debe reproducir la infraestructura.
-- ────────────────────────────────────────────────────────────────────

-- Rol de aplicacion: sin privilegios de creacion, sin BYPASSRLS.
CREATE ROLE mailauto_app WITH LOGIN PASSWORD 'desarrollo' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;

GRANT CONNECT ON DATABASE mailauto TO mailauto_app;
GRANT USAGE ON SCHEMA public TO mailauto_app;

-- Permisos de datos, nunca de esquema: la aplicacion no puede alterar
-- tablas ni, por tanto, desactivar una politica RLS en caliente.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mailauto_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO mailauto_app;

-- Las migraciones corren como `mailauto_owner` y crean las tablas
-- despues de este script, por eso se usan DEFAULT PRIVILEGES: aplican a
-- lo que se cree a partir de ahora.
