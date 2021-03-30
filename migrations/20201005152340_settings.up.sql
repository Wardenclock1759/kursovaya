CREATE TABLE "settings" (
    project_id bigserial not null primary key,
    id varchar not null,
    ident varchar not null,
    name varchar not null,
    settings varchar not null,
    created_at time not null,
    is_active boolean
);