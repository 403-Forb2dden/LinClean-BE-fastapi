import type { NextRequest } from "next/server";

export const EXTERNAL_TEST_URL = "https://example.com/";
export const MAX_HOP_TERMINAL_STEP = 12;
export const REDIRECT_DELAY_MS = 500;

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function redirectResponse(
  location: string,
  status = 302,
): Promise<Response> {
  await wait(REDIRECT_DELAY_MS);

  return new Response(null, {
    status,
    headers: {
      "Cache-Control": "no-store",
      Location: location,
      "X-LinClean-Fixture": "redirect-chain",
    },
  });
}

export function absoluteFixtureUrl(request: NextRequest, path: string): string {
  return new URL(path, request.nextUrl.origin).toString();
}
