import { redirectResponse } from "@/lib/redirects";

export async function GET() {
  return await redirectResponse("javascript:alert(1)");
}

export const HEAD = GET;
