-- Once a publisher fences an org, unversioned policy writes cannot bypass it.
ALTER TABLE orgs ADD COLUMN limits_version bigint CHECK (limits_version > 0);
