-- The one-second expiry sweep finds retained batches by deadline rather than
-- reading every batch, member, and session.
CREATE INDEX upload_finalization_expiry ON upload_finalization_batches(expires_at);
-- A job resume used to requeue settled batches. Park them again so idle
-- consumers stop rereading them; an open admission is never parked.
UPDATE upload_finalization_batches b SET work_at='infinity'
WHERE b.admitted AND b.work_id IS NULL AND b.work_at<>'infinity'
    AND NOT EXISTS(SELECT 1 FROM upload_finalizations f WHERE f.batch_id=b.id AND f.result IS NULL);
-- The orphan sweep asks, per stored object, whether any blob still points at
-- its key. Only r2_key was indexed, so each question read every blob.
CREATE INDEX blob_objects_public_key ON blob_objects(public_key) WHERE public_key IS NOT NULL;
CREATE INDEX blob_objects_private_key ON blob_objects(private_key) WHERE private_key IS NOT NULL;
