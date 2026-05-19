import type { NextRequest } from "next/server";
import { absoluteFixtureUrl, redirectResponse } from "@/lib/redirects";

export async function GET(request: NextRequest) {
  return await redirectResponse(absoluteFixtureUrl(request, "/hop/1"));
}

export const HEAD = GET;
