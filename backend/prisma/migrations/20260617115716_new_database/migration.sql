/*
  Warnings:

  - You are about to drop the column `magic_link_expires_at` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `magic_link_token_hash` on the `users` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "users" DROP COLUMN "magic_link_expires_at",
DROP COLUMN "magic_link_token_hash";

-- CreateTable
CREATE TABLE "manager_teams" (
    "manager_user_id" TEXT NOT NULL,
    "team_id" BIGINT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "manager_teams_pkey" PRIMARY KEY ("manager_user_id","team_id")
);

-- AddForeignKey
ALTER TABLE "manager_teams" ADD CONSTRAINT "manager_teams_manager_user_id_fkey" FOREIGN KEY ("manager_user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "manager_teams" ADD CONSTRAINT "manager_teams_team_id_fkey" FOREIGN KEY ("team_id") REFERENCES "teams"("id") ON DELETE CASCADE ON UPDATE CASCADE;
