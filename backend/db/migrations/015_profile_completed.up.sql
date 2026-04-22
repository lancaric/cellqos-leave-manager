ALTER TABLE users
  ADD COLUMN IF NOT EXISTS profile_completed BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users
SET profile_completed = TRUE
WHERE profile_completed = FALSE;