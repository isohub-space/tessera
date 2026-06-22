-- Testcontainers init (runs as the container superuser before the app starts).
-- Establishes the three-role model so neither Flyway nor the runtime datasource
-- connects as a superuser — a superuser bypasses RLS unconditionally, defeating
-- FORCE ROW LEVEL SECURITY.
--
--   * iam_migrator — Flyway connects as this NON-superuser role, so the tables it
--     creates are OWNED by iam_migrator and remain RLS-bound (FORCE).
--   * iam_app      — the runtime datasource role; owns nothing, holds only the DML
--     granted to it by V1 (run as iam_migrator).
CREATE ROLE iam_migrator LOGIN PASSWORD 'iam_migrator' NOSUPERUSER;
CREATE ROLE iam_app LOGIN PASSWORD 'iam_app' NOSUPERUSER;

GRANT CREATE, USAGE ON SCHEMA public TO iam_migrator;
