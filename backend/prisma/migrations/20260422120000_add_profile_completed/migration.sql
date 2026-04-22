-- AlterTable
ALTER TABLE "users" ADD COLUMN     "profile_completed" BOOLEAN NOT NULL DEFAULT false;

UPDATE "users"
SET "profile_completed" = true;