-- Audit attribution must survive: deleting a user with trail history is
-- refused instead of silently nulling `actor` (which breaks the chain —
-- chain_hash covers the actor byte-for-byte). Operators deactivate;
-- Gone users are removed only via demo reset (TRUNCATE ... CASCADE).
ALTER TABLE audit_log DROP CONSTRAINT audit_log_actor_fkey;
ALTER TABLE audit_log
    ADD CONSTRAINT audit_log_actor_fkey FOREIGN KEY (actor) REFERENCES users (id);
