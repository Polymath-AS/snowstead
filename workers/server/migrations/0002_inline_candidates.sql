-- Inline candidates come from verified request bytes, not a stored source.
ALTER TABLE nar_installations ALTER COLUMN source_key DROP NOT NULL;
