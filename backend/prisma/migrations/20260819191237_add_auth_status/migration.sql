-- CreateEnum
CREATE TYPE "AuthStatus" AS ENUM ('PASS', 'PARTIAL', 'FAIL', 'NONE');

-- AlterTable
ALTER TABLE "mailbox_messages" ADD COLUMN     "auth_details" TEXT,
ADD COLUMN     "auth_status" "AuthStatus" NOT NULL DEFAULT 'NONE';
