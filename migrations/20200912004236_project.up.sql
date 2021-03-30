CREATE TABLE "project" (
    api_key varchar NOT NULL,
    project_id bigserial NOT NULL,
    created_at time NOT NULL,
    updated_at time,
    is_active boolean,
    primary key (api_key, project_id, is_active)
);