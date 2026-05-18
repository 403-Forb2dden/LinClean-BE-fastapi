import { EXTERNAL_TEST_URL, redirectResponse } from "@/lib/redirects";

export async function GET() {
  return await redirectResponse(EXTERNAL_TEST_URL);
}

export const HEAD = GET;
